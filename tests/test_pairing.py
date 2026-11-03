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


# ---- Linux/BlueZ sends a real Write Request; a characteristic that only takes Write Commands refuses it ----
class _Char:
    def __init__(self, props):
        self.properties = props


class _Services:
    def __init__(self, props_by_uuid):
        self._p = props_by_uuid

    def get_characteristic(self, uuid):
        return _Char(self._p.get(uuid, ["read", "write"]))


class WriteCommandOnlyUnit(FakeUnit):
    """Registry characteristics accept only Write Command, like a strict stack would enforce."""
    REG = None

    def __init__(self, know_props=True, **kw):
        super().__init__(**kw)
        self.modes = []
        self.REG = (PR.U_F010, PR.U_F011, C.U_F012)
        if know_props:
            self.services = _Services({u: ["write-without-response"] for u in self.REG})

    async def write_gatt_char(self, u, d, response=False):
        if u in self.REG:
            self.modes.append((u, response))
            if response:
                raise RuntimeError("Write Not Permitted")      # ATT 0x03 from the unit
        return await super().write_gatt_char(u, d, response)


def test_pairing_writes_the_way_the_characteristic_allows():
    unit, server = WriteCommandOnlyUnit(has_key=True), FakeServer()
    assert run(unit, server) == UNIT_KEY
    assert all(resp is False for _, resp in unit.modes)       # never even tried a Write Request


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(PR, "REGISTRY_RETRY_DELAY", 0, raising=False)
    monkeypatch.setattr(PR, "PAIR_ROUND_PAUSE", 0, raising=False)


def test_a_refused_write_request_is_never_retried_as_a_write_command():
    """A Write Command cannot be refused (nothing answers it), so 'retrying' one would only hide
    the unit's real answer - registry mode is closed - and fail later, somewhere confusing."""
    unit, server = WriteCommandOnlyUnit(know_props=False, has_key=True), FakeServer()
    with pytest.raises(PR.RegistryError, match="refused registry mode.*Write Not Permitted"):
        run(unit, server)
    f010 = [resp for u, resp in unit.modes if u == PR.U_F010]
    assert f010 and all(resp is True for resp in f010)          # only ever Write Requests
    assert len(f010) == PR.REGISTRY_TRIES                       # it asked a few times, then stopped


class RefusesFirst(FakeUnit):
    """Registry mode is closed for the first `refusals` writes to f010, then LINK 'takes'."""
    def __init__(self, refusals, **kw):
        super().__init__(**kw)
        self.left = refusals

    async def write_gatt_char(self, u, d, response=False):
        if u == PR.U_F010 and self.left > 0:
            self.left -= 1
            raise RuntimeError("Write Not Permitted")
        return await super().write_gatt_char(u, d, response)


def test_registry_mode_is_asked_for_repeatedly_while_link_gets_going():
    unit, server = RefusesFirst(PR.REGISTRY_TRIES - 1, has_key=True), FakeServer()
    assert run(unit, server) == UNIT_KEY
    asked = [c for c in server.calls if c == ("/setup", "getRegistryModeData")]
    assert len(asked) == PR.REGISTRY_TRIES                      # a fresh blob for every try


def test_a_unit_that_never_opens_registry_mode_is_reported_not_hidden():
    with pytest.raises(PR.RegistryError, match="refused registry mode.*Write Not Permitted"):
        run(RefusesFirst(10 ** 6, has_key=True), FakeServer())


def test_a_server_problem_is_not_blamed_on_link():
    class Broken(FakeServer):
        def post_json(self, path, o):
            if o["request"] == "getRegistryModeData":
                return 500, b"oops"
            return super().post_json(path, o)
    with pytest.raises(PR.PairError) as err:
        run(FakeUnit(has_key=True), Broken())
    assert not isinstance(err.value, PR.RegistryError)           # retrying the unit will not help
    assert "LINK" not in str(err.value)


class NoSlotYet(FakeUnit):
    async def read_gatt_char(self, u):
        if u == PR.U_F011:
            raise RuntimeError("Read Not Permitted")
        return await super().read_gatt_char(u)


def test_reading_the_slot_before_registry_mode_is_a_clean_error_not_a_crash():
    with pytest.raises(PR.RegistryError, match="key slot.*LINK.*Read Not Permitted"):
        run(NoSlotYet(has_key=True), FakeServer())


# ---- pair_over_ble: connect, pair, and start again on a fresh connection if the unit says 'not yet' ----
@pytest.fixture
def ble(monkeypatch):
    import sys
    import types
    st = types.SimpleNamespace(connects=0, disconnects=0, http_closed=0, outcomes=[], progress=[],
                               connect_error=None)

    class Client:
        async def disconnect(self):
            st.disconnects += 1

    async def establish_connection(cls, dev, name, max_attempts=3, **kw):
        st.connects += 1
        if st.connect_error:
            raise st.connect_error
        return Client()

    mod = types.ModuleType("bleak_retry_connector")
    mod.BleakClientWithServiceCache, mod.establish_connection = object, establish_connection
    monkeypatch.setitem(sys.modules, "bleak_retry_connector", mod)

    class FakeHttp:
        def warm(self):
            pass

        def close(self):
            st.http_closed += 1

    async def fake_validate(http, mu):
        return PR.Validated(PROTO, ["93240"], 65551)

    async def fake_pair(client, mu, http, proto, key_id=1, progress=None):
        outcome = st.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(PR, "Http", FakeHttp)
    monkeypatch.setattr(PR, "validate", fake_validate)
    monkeypatch.setattr(PR, "pair", fake_pair)
    return st


def run_ble(st):
    dev = types_ns(address="00:1C:4D:4B:F0:80")
    return asyncio.run(PR.pair_over_ble(dev, MASTER, PROTO, progress=st.progress.append))


def types_ns(**kw):
    from types import SimpleNamespace
    return SimpleNamespace(**kw)


def test_pairing_starts_again_on_a_fresh_connection_when_registry_mode_is_closed(ble):
    ble.outcomes = [PR.RegistryError("not yet"), UNIT_KEY]
    res = run_ble(ble)
    assert res.key == UNIT_KEY and res.protocol == PROTO
    assert ble.connects == 2 and ble.disconnects == 2 and ble.http_closed == 1
    assert any("attempt 2" in m for m in ble.progress)           # the HA log shows it


def test_pairing_gives_up_after_the_last_round(ble):
    ble.outcomes = [PR.RegistryError("not yet")] * 20
    with pytest.raises(PR.RegistryError):
        run_ble(ble)
    assert ble.connects == PR.PAIR_ROUNDS == ble.disconnects and ble.http_closed == 1


def test_other_pairing_errors_are_not_retried(ble):
    ble.outcomes = [PR.PairError("server returned key id 2, wanted 1")]
    with pytest.raises(PR.PairError, match="key id"):
        run_ble(ble)
    assert ble.connects == 1 and ble.disconnects == 1


def test_a_surprise_exception_becomes_a_pairing_error_and_cleans_up(ble):
    ble.outcomes = [RuntimeError("boom")]
    with pytest.raises(PR.PairError, match="boom"):
        run_ble(ble)
    assert ble.disconnects == 1 and ble.http_closed == 1


def test_a_failed_connection_is_a_pairing_error(ble):
    ble.connect_error = OSError("adapter busy")
    with pytest.raises(PR.PairError, match="cannot connect.*adapter busy"):
        run_ble(ble)
    assert ble.http_closed == 1


def test_characteristic_table_summary_for_the_log():
    unit = WriteCommandOnlyUnit()
    s = PR.gatt_summary(unit, [PR.U_F010, C.U_F004])
    assert "f010:write-without-response" in s and "f004:read/write" in s
    assert "unavailable" in PR.gatt_summary(FakeUnit(), [PR.U_F010])     # no table: say so, don't crash


def test_gateway_message_names_the_gateway():
    info = asyncio.run(PR.validate(FakeServer(), GATEWAY))
    with pytest.raises(PR.PairError, match="is a gateway"):
        PR.ensure_purifier(info)
