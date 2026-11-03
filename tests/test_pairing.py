import asyncio, base64, json, os
import pytest
from germguardian import pairing as PR, client as C, protocol as P

K0 = bytes(range(100, 116))
UNIT_KEY = bytes(range(7, 23))
MASTER = "00000000-24f6-4000-a000-0fedf19130a2"
PROTO = 0xEEF3C48D


class FakeServer:
    """Plays the server's part as read from the app code."""
    def __init__(self, preissued=False):
        self.k0 = P.Cipher16(K0)
        self.schal = None
        self.calls = []
        self.preissued = preissued

    def post_json(self, path, o):
        self.calls.append((path, o["request"]))
        if path == "/imper" and o["request"] == "getChallenge":
            assert o["masterUUID"] == MASTER.replace("-", "")
            self.schal = os.urandom(16)
            return 200, json.dumps({
                "serverResponse": self.k0.block(bytes.fromhex(o["deviceChallenge"])).hex(),
                "serverChallenge": self.schal.hex()}).encode()
        if path == "/imper":
            ok = bytes.fromhex(o["deviceResponse"]) == self.k0.block(self.schal)
            return 200, json.dumps({"result": "OK" if ok else "NG"}).encode()
        assert o["masterUUID"] == MASTER.replace("-", "").upper()
        if o["request"] == "getRegistryModeData":
            return 200, b"REGISTRYMODE" * 3
        if o["request"] == "generateLocalKey":
            assert o["keyId"] == 1
            return 200, self.k0.block(UNIT_KEY) + b"ISSUED" + bytes(10)
        blob = base64.b64decode(o["data"])
        if blob[:16] == self.k0.block(UNIT_KEY):
            return 200, json.dumps({"keyId": 1, "key": UNIT_KEY.hex()}).encode()
        return 200, json.dumps({"keyId": 0}).encode()


class FakeUnit:
    def __init__(self, has_key=False):
        self.k0 = P.Cipher16(K0)
        self.unlocked = self.registry = False
        self.slot = self.k0.block(UNIT_KEY) + b"STORED" + bytes(10) if has_key else bytes(32)
        self.rd = 0
        self.writes = []

    async def read_gatt_char(self, u):
        if u == C.U_F004:
            assert self.unlocked
            self.chal = os.urandom(16); return bytearray(self.chal)
        if u == C.U_F005:
            return bytearray(self.k0.block(self.hc))
        if u == PR.U_F011:
            assert self.registry, "f011 only readable in registry mode"
            n = len(self.slot) // 16
            i = self.rd % n; self.rd += 1
            return bytearray(bytes([i + 1 | (0x80 if i == n - 1 else 0)]) + self.slot[i*16:i*16+16])
        raise AssertionError(u)

    async def write_gatt_char(self, u, d, response=False):
        d = bytes(d); self.writes.append(u)
        if u == C.U_F000: self.unlocked = d == PROTO.to_bytes(4, "little")
        elif u == C.U_F005: assert d == self.k0.block(self.chal)
        elif u == C.U_F004: self.hc = d
        elif u == PR.U_F010:
            if d[0] & 0x80: self.registry = True
        elif u == PR.U_F011:
            assert self.registry
            if d[0] & 0x0F == 1: self.new = b""
            self.new += d[1:]
            if d[0] & 0x80: self.slot = self.new; self.rd = 0
        elif u == C.U_F012: assert d == b"\x00\x01"


def run(unit, server):
    return asyncio.run(PR.pair(unit, MASTER, server, PROTO))


def test_pair_issues_new_key_on_empty_slot():
    u, s = FakeUnit(), FakeServer()
    assert run(u, s) == UNIT_KEY
    assert ("/setup", "generateLocalKey") in s.calls


def test_pair_returns_existing_key_without_generating():
    u, s = FakeUnit(has_key=True), FakeServer()
    assert run(u, s) == UNIT_KEY
    assert ("/setup", "generateLocalKey") not in s.calls


def test_carousel_roundtrip_header_bits():
    u = FakeUnit(); u.registry = True
    asyncio.run(PR.carousel_write(u, PR.U_F011, bytes(range(40))))
    assert u.slot == bytes(range(40))     # 3 blocks, last one short
    assert u.writes.count(PR.U_F011) == 3
