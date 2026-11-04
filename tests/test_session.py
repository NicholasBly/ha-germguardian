import asyncio, pytest
from fake_device import FakePurifier
from germguardian import client as C

KEY = bytes(range(16, 32))
PROTO = 0xEEF3C48D


async def _session(dev, key=KEY):
    s = C.Session(dev, key, PROTO)
    await s.start()
    return s


def test_auth_status_and_set():
    async def go():
        dev = FakePurifier(KEY)
        s = await _session(dev)
        await s.authenticate()
        st = await s.get_status()
        assert (st.power, st.air_quality, st.filter_hours) == (False, 123, 1385)
        await s.set(power=True, auto=False, wind=5, uv=True)
        st = await s.get_status()
        assert (st.power, st.wind, st.uv) == (True, 5, True)
        await s.set(power=False)
        assert (await s.get_status()).power is False
        # the unlock must be the little-endian protocol number
        assert dev.writes[0] == (C.U_F000, bytes.fromhex("8dc4f3ee"))
        # we never touch fffd
        assert not any("fffd" in u for u, _ in dev.writes)
    asyncio.run(go())


def test_wrong_key_is_auth_error():
    async def go():
        dev = FakePurifier(KEY)
        s = await _session(dev, key=bytes(16))
        with pytest.raises(C.AuthError):
            await s.authenticate()
    asyncio.run(go())


def test_wrong_protocol_number_cannot_read():
    async def go():
        dev = FakePurifier(KEY, proto=0x12345678)
        s = await _session(dev)
        with pytest.raises(C.CommError):
            await s.authenticate()
    asyncio.run(go())


def test_unit_that_refuses_the_unlock_is_reported_as_wrong_unit():
    class Refuses(FakePurifier):
        async def read_gatt_char(self, uuid):
            raise OSError("Read Not Permitted")     # what a gateway does to the purifier handshake
    async def go():
        s = await _session(Refuses(KEY))
        with pytest.raises(C.UnlockError):
            await s.authenticate()
    asyncio.run(go())
    assert issubclass(C.UnlockError, C.CommError)


# ---- a dropped Bluetooth link must be reported as a dropped link, not as a bad key or a raw crash ----
class Flaky(FakePurifier):
    """`gone`: the link is already down when we first write (Bleak: 'Service Discovery has not been
    performed yet'). `mid`: it drops while we answer the challenge."""
    def __init__(self, key, mode):
        super().__init__(key)
        self.is_connected, self.mode = True, mode

    async def write_gatt_char(self, uuid, data, response=False):
        if self.mode == "gone" and uuid == C.U_F000:
            self.is_connected = False
            raise RuntimeError("Service Discovery has not been performed yet")
        if self.mode == "mid" and uuid == C.U_F005:
            self.is_connected = False
            raise RuntimeError("Not connected")
        return await super().write_gatt_char(uuid, data, response)


def test_link_already_down_at_the_first_write_is_a_link_error_not_a_raw_crash():
    async def go():
        s = await _session(Flaky(KEY, "gone"))
        with pytest.raises(C.LinkLostError, match="Service Discovery"):
            await s.authenticate()
    asyncio.run(go())


def test_link_dropping_during_login_is_not_reported_as_a_wrong_key():
    async def go():
        s = await _session(Flaky(KEY, "mid"))
        with pytest.raises(C.LinkLostError) as err:
            await s.authenticate()
        assert not isinstance(err.value, C.AuthError)
    asyncio.run(go())
    assert issubclass(C.LinkLostError, C.CommError)


# ---- open_session: a couple of tries per poll, so one dropped link does not make the unit 'unavailable' ----
@pytest.fixture
def connector(monkeypatch):
    import sys
    import types
    st = types.SimpleNamespace(connects=0, clients=[], error=None)

    async def establish_connection(cls, dev, name, max_attempts=3, **kw):
        st.connects += 1
        if st.error:
            raise st.error
        return st.clients.pop(0)

    mod = types.ModuleType("bleak_retry_connector")
    mod.BleakClientWithServiceCache, mod.establish_connection = object, establish_connection
    monkeypatch.setitem(sys.modules, "bleak_retry_connector", mod)
    monkeypatch.setattr(C, "CONNECT_RETRY_PAUSE", 0, raising=False)
    return st


class Good(FakePurifier):
    is_connected = True


def test_a_dropped_link_is_retried_within_the_same_poll(connector):
    connector.clients = [Flaky(KEY, "gone"), Flaky(KEY, "mid"), Good(KEY)]
    client, sess = asyncio.run(C.open_session(object(), KEY, PROTO, "unit"))
    assert connector.connects == 3 and isinstance(client, Good)


def test_it_gives_up_after_three_dropped_links_and_says_when_they_dropped(connector):
    connector.clients = [Flaky(KEY, "mid") for _ in range(5)]
    with pytest.raises(C.LinkLostError, match=r"\d\.\d s after connecting"):
        asyncio.run(C.open_session(object(), KEY, PROTO, "unit"))
    assert connector.connects == 3


def test_a_refused_key_is_tried_once_more_then_reported_as_a_bad_key(connector):
    connector.clients = [Good(bytes(16)) for _ in range(5)]            # the unit has another key
    with pytest.raises(C.AuthError):
        asyncio.run(C.open_session(object(), KEY, PROTO, "unit"))
    assert connector.connects == 2


def test_connect_failures_and_wrong_units_are_not_retried(connector):
    connector.error = OSError("no adapter slot")
    with pytest.raises(C.CommError, match="cannot connect"):
        asyncio.run(C.open_session(object(), KEY, PROTO, "unit"))
    assert connector.connects == 1

    class Refuses(Good):
        async def read_gatt_char(self, uuid):
            raise OSError("Read Not Permitted")
    connector.error, connector.connects, connector.clients = None, 0, [Refuses(KEY)]
    with pytest.raises(C.UnlockError):
        asyncio.run(C.open_session(object(), KEY, PROTO, "unit"))
    assert connector.connects == 1
