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
