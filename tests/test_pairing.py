import asyncio, base64, json, os
import pytest
from germguardian import pairing as PR, client as C, protocol as P

K0 = bytes(range(100, 116))
UNIT_KEY = bytes(range(7, 23))
MASTER = "00000000-24f6-4000-a000-0fedf19130a2"
GATEWAY = "00000000-24f6-4000-a000-0a1312c1f600"
PROTO = 0xEEF3C48D
GW_PROTO = 0x3821A625
KNOWN = {   # what the real server told the app: id -> (types, function number, protocol number)
    MASTER.replace("-", ""): (["93240"], 65551, PROTO),
    GATEWAY.replace("-", ""): (["82567"], 65548, GW_PROTO),
}


class FakeServer:
    """Plays the server's part as read from the app code."""
    def __init__(self, preissued=False):
        self.k0 = P.Cipher16(K0)
        self.schal = None
        self.calls = []
        self.preissued = preissued

    def post_json(self, path, o):
        self.calls.append((path, o["request"]))
        assert o["clientInformation"] == PR.CLIENT_INFO     # every real request carries it
        if o["request"] == "validateDevices":
            assert path == "/setup"
            res = []
            for d in o["devices"]:
                types, fn, proto = KNOWN.get(d["masterUUID"], ([], None, None))
                res.append({
                    "masterUUID": d["masterUUID"], "result": "OK" if types else "NotAuthenticated",
                    "types": types, "functionNumber": fn, "protocolNumber": proto, "deviceName": " ",
                })
            return 200, json.dumps({"results": res}).encode()
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


# ---- wire format, checked against a capture of the real app (bodies and Content-Length) ----
CAPTURED_GET_CHALLENGE = (
    b'{"deviceChallenge":"00112233445566778899aabbccddeeff",'
    b'"masterUUID":"0000000024f64000a0000fedf19130a2",'
    b'"clientInformation":{"model":"i:iPhone18,1","osVersion":"27.2","sdkVersion":"i:1.6.4."},'
    b'"request":"getChallenge","version":"20141224"}'
)
CAPTURED_VERIFY = (
    b'{"clientInformation":{"model":"i:iPhone18,1","osVersion":"27.2","sdkVersion":"i:1.6.4."},'
    b'"masterUUID":"0000000024f64000a0000fedf19130a2",'
    b'"deviceResponse":"0f0e0d0c0b0a09080706050403020100",'
    b'"serverChallenge":"101112131415161718191a1b1c1d1e1f",'
    b'"request":"verifyResponse","version":"20141224"}'
)
CAPTURED_VALIDATE = (
    b'{"validateOption":{"types":["93240","82567"]},'
    b'"clientInformation":{"model":"i:iPhone18,1","osVersion":"27.2","sdkVersion":"i:1.6.4."},'
    b'"devices":[{"masterUUID":"0000000024f64000a0000fedf19130a2"}],'
    b'"central":"i:iPhone18,1","request":"validateDevices","version":"20150818"}'
)


def test_wire_format_matches_real_app():
    enc = PR.Http.encode
    got = enc(PR.body_get_challenge(MASTER, bytes.fromhex("00112233445566778899aabbccddeeff")))
    assert got == CAPTURED_GET_CHALLENGE and len(got) == 236      # Content-Length in the capture
    got = enc(PR.body_verify(MASTER, bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
                             bytes.fromhex("0f0e0d0c0b0a09080706050403020100")))
    assert got == CAPTURED_VERIFY and len(got) == 290
    got = enc(PR.body_validate(MASTER))
    assert got == CAPTURED_VALIDATE and len(got) == 270


def test_headers_identify_this_client():
    h = PR.Http.headers()
    assert h["User-Agent"].startswith("ha-germguardian")
    assert h["Content-Type"] == "application/json" and h["Accept"] == "*/*"
    assert "oem4guardiantech" not in str(h)          # we do not pose as the vendor's app


def test_validate_returns_the_servers_protocol_number():
    info = asyncio.run(PR.validate(FakeServer(), MASTER))
    assert info.protocol == PROTO and info.types == ["93240"]


def test_validate_rejects_unknown_unit():
    with pytest.raises(PR.PairError, match="does not recognise"):
        asyncio.run(PR.validate(FakeServer(), "00000000-24f6-4000-a000-000000000001"))


class Forbidden:
    last_headers = {"Server": "awselb/2.0", "Content-Type": "text/html", "Set-Cookie": "secret"}

    def post_json(self, path, o):
        return 403, b"<html><body><h1>403 Forbidden</h1></body></html>"


def test_403_error_is_readable_and_names_the_front_server():
    with pytest.raises(PR.PairError) as e:
        asyncio.run(PR.validate(Forbidden(), MASTER))
    msg = str(e.value)
    assert "403" in msg and "awselb" in msg and "403 Forbidden" in msg
    assert "<html>" not in msg and "secret" not in msg


CAPTURED_VALIDATE_TWO_LEN = 320   # Content-Length of the app's two-unit validateDevices


def test_validate_body_with_two_units_matches_real_app():
    got = PR.Http.encode(PR.body_validate([MASTER, GATEWAY]))
    assert len(got) == CAPTURED_VALIDATE_TWO_LEN
    assert got.count(b'{"masterUUID"') == 2


def test_server_tells_purifier_from_gateway():
    unknown = "00000000-24f6-4000-a000-000000000001"
    found = asyncio.run(PR.validate_many(FakeServer(), [MASTER, GATEWAY, unknown]))
    assert found[PR.plain_id(MASTER)].is_purifier
    assert found[PR.plain_id(MASTER)].protocol == PROTO
    assert not found[PR.plain_id(GATEWAY)].is_purifier
    assert found[PR.plain_id(GATEWAY)].protocol == GW_PROTO
    assert PR.plain_id(unknown) not in found            # never heard of it


def test_pairing_refuses_a_gateway():
    info = asyncio.run(PR.validate(FakeServer(), GATEWAY))
    with pytest.raises(PR.PairError, match="not a purifier"):
        PR.ensure_purifier(info)
    PR.ensure_purifier(asyncio.run(PR.validate(FakeServer(), MASTER)))   # purifier passes
