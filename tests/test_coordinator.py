"""The coordinator against a stand-in for Home Assistant's update-coordinator and Bluetooth API."""
import asyncio
import sys
import types
from types import SimpleNamespace

import pytest

from germguardian import client as C, protocol as P


class UpdateFailed(Exception):
    pass


class HomeAssistantError(Exception):
    pass


class StubCoordinator:
    def __class_getitem__(cls, item):
        return cls

    def __init__(self, hass, logger, *, name, config_entry=None, update_interval=None):
        self.hass, self.data, self.update_interval = hass, None, update_interval
        self.last_update_success, self.last_exception = True, None

    def async_set_updated_data(self, data):
        self.data, self.last_update_success = data, True

    def async_set_update_error(self, err):
        self.last_update_success, self.last_exception = False, err

    async def async_refresh(self):
        try:
            self.data = await self._async_update_data()
            self.last_update_success = True
        except UpdateFailed as err:
            self.last_update_success, self.last_exception = False, err

    async def async_shutdown(self):
        pass


LATER = []          # (delay, action, cancelled-flag holder) recorded by the async_call_later stand-in


def async_call_later(hass, delay, action):
    entry = {"delay": delay, "action": action, "cancelled": False}
    LATER.append(entry)

    def cancel():
        entry["cancelled"] = True
    return cancel


@pytest.fixture
def coord_module():
    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        return m

    bt = mod("homeassistant.components.bluetooth", async_ble_device_from_address=lambda *a, **k: object())
    names = {
        "homeassistant": mod("homeassistant"),
        "homeassistant.components": mod("homeassistant.components", bluetooth=bt),
        "homeassistant.components.bluetooth": bt,
        "homeassistant.config_entries": mod("homeassistant.config_entries", ConfigEntry=object),
        "homeassistant.core": mod("homeassistant.core", HomeAssistant=object),
        "homeassistant.exceptions": mod("homeassistant.exceptions", HomeAssistantError=HomeAssistantError),
        "homeassistant.helpers": mod("homeassistant.helpers"),
        "homeassistant.helpers.device_registry": mod("homeassistant.helpers.device_registry", DeviceInfo=dict),
        "homeassistant.helpers.event": mod("homeassistant.helpers.event", async_call_later=async_call_later),
        "homeassistant.helpers.update_coordinator": mod(
            "homeassistant.helpers.update_coordinator",
            DataUpdateCoordinator=StubCoordinator, UpdateFailed=UpdateFailed,
        ),
    }
    LATER.clear()
    saved = {n: sys.modules.get(n) for n in names}
    sys.modules.update(names)
    sys.modules.pop("germguardian.coordinator", None)
    try:
        import germguardian.coordinator as cm
        yield cm
    finally:
        sys.modules.pop("germguardian.coordinator", None)
        for n, m in saved.items():
            sys.modules.pop(n, None) if m is None else sys.modules.__setitem__(n, m)


STATUS = P.Status(power=True, wind=3, auto=False, timer=0, uv=False,
                  air_quality=100, filter_hours=10, bulb_hours=5)


def make(cm, options=None):
    entry = SimpleNamespace(
        unique_id="00000000-24f6-4000-a000-0fedf19130a2",
        data={"address": "00:1C:4D:4B:F0:80", "local_key": bytes(16).hex(),
              "protocol_number": 0xEEF3C48D, "model": "CDAP4500BCA", "master_uuid": "x"},
        options=options or {},
    )
    return cm.GuardianCoordinator(SimpleNamespace(), entry)


def script(coord, outcomes):
    """Make each poll return the next outcome: a Status, or an exception to raise."""
    async def with_session(fn):
        out = outcomes.pop(0)
        if isinstance(out, BaseException):
            raise out
        return out
    coord._with_session = with_session


def poll(coord):
    return asyncio.run(coord._async_update_data())


def test_a_short_gap_keeps_the_last_reading_instead_of_flipping_to_unavailable(coord_module):
    coord = make(coord_module)
    script(coord, [STATUS, UpdateFailed("link dropped"), UpdateFailed("link dropped"), STATUS])
    coord.data = poll(coord)
    for _ in range(coord_module.TOLERATED_FAILURES):
        assert poll(coord) == STATUS                     # still shows the last good reading
    assert poll(coord) == STATUS                         # and a good poll is simply a good poll


def test_a_longer_outage_does_become_unavailable(coord_module):
    coord = make(coord_module)
    n = coord_module.TOLERATED_FAILURES
    script(coord, [STATUS] + [UpdateFailed("gone")] * (n + 1))
    coord.data = poll(coord)
    for _ in range(n):
        poll(coord)
    with pytest.raises(UpdateFailed, match="gone"):
        poll(coord)


def test_a_good_poll_resets_the_count(coord_module):
    coord = make(coord_module)
    n = coord_module.TOLERATED_FAILURES
    script(coord, [STATUS] + [UpdateFailed("x")] * n + [STATUS] + [UpdateFailed("x")] * n)
    coord.data = poll(coord)
    for _ in range(n):
        poll(coord)
    poll(coord)                                          # recovers
    for _ in range(n):
        assert poll(coord) == STATUS                     # tolerated again from zero


def test_no_data_yet_means_the_first_failure_is_reported(coord_module):
    coord = make(coord_module)                           # setup: nothing to fall back on
    script(coord, [UpdateFailed("never connected")])
    with pytest.raises(UpdateFailed, match="never connected"):
        poll(coord)


def test_an_unexpected_library_error_becomes_a_plain_failed_update(coord_module):
    """HA prints 'Unexpected error' with a full traceback for anything that is not UpdateFailed."""
    coord = make(coord_module)

    class Boom(Exception):
        pass

    async def explode(*a, **k):
        raise Boom("service discovery")

    async def go():
        import germguardian.coordinator as cm
        cm.open_session = explode
        return await coord._with_session(lambda s: s.get_status())

    with pytest.raises(UpdateFailed, match="Boom.*service discovery"):
        asyncio.run(go())


def test_commands_do_not_hide_failures(coord_module):
    coord = make(coord_module)
    script(coord, [UpdateFailed("link dropped")])
    with pytest.raises(HomeAssistantError, match="link dropped"):
        asyncio.run(coord.async_set(power=True))


def test_the_first_failed_poll_in_a_row_is_logged_with_its_reason_then_it_stays_quiet(coord_module, caplog):
    import logging
    coord = make(coord_module)
    script(coord, [STATUS, UpdateFailed("link dropped [0.4 s after connecting]"), UpdateFailed("again")])
    coord.data = poll(coord)
    with caplog.at_level(logging.DEBUG):
        poll(coord)
        poll(coord)
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warned) == 1 and "0.4 s after connecting" in warned[0].getMessage()


# ---- how often to check: a gentler default, an option, and "only when I send a command" ----
def test_checks_once_a_minute_by_default(coord_module):
    from datetime import timedelta
    assert make(coord_module).update_interval == timedelta(seconds=60)


def test_the_check_interval_comes_from_the_options(coord_module):
    from datetime import timedelta
    assert make(coord_module, {"update_interval": 300}).update_interval == timedelta(seconds=300)


def test_only_on_command_means_no_polling_at_all(coord_module):
    assert make(coord_module, {"update_interval": 0}).update_interval is None


# ---- a failed command must not leave a state on screen that we could not change or confirm ----
def test_a_failed_command_marks_the_purifier_unavailable_instead_of_keeping_the_old_state(coord_module):
    coord = make(coord_module)
    coord.data = STATUS                                   # shows "on"
    script(coord, [UpdateFailed("link dropped")])
    with pytest.raises(HomeAssistantError):
        asyncio.run(coord.async_set(power=False))
    assert coord.last_update_success is False             # -> entities show "unavailable"


def test_after_a_failed_command_the_next_failed_check_is_not_hidden(coord_module):
    coord = make(coord_module)
    script(coord, [STATUS, UpdateFailed("command"), UpdateFailed("check")])
    coord.data = poll(coord)
    with pytest.raises(HomeAssistantError):
        asyncio.run(coord.async_set(power=False))
    with pytest.raises(UpdateFailed, match="check"):
        poll(coord)


def test_command_only_mode_checks_again_later_until_it_reaches_the_purifier(coord_module):
    coord = make(coord_module, {"update_interval": 0})
    coord.data = STATUS
    off = P.Status(power=False, wind=3, auto=False, timer=0, uv=False,
                   air_quality=100, filter_hours=10, bulb_hours=5)
    script(coord, [UpdateFailed("link dropped"), UpdateFailed("still"), off])
    with pytest.raises(HomeAssistantError):
        asyncio.run(coord.async_set(power=False))
    assert len(LATER) == 1 and LATER[0]["delay"] == coord_module.RECOVERY_CHECK_SECONDS
    asyncio.run(LATER[0]["action"](None))                 # check fails -> try again later
    assert coord.last_update_success is False and len(LATER) == 2
    asyncio.run(LATER[1]["action"](None))                 # check works -> real state, no more checks
    assert coord.last_update_success is True and coord.data == off and len(LATER) == 2


def test_only_one_recovery_check_is_pending_at_a_time(coord_module):
    coord = make(coord_module, {"update_interval": 0})
    script(coord, [UpdateFailed("a"), UpdateFailed("b")])
    for _ in range(2):
        with pytest.raises(HomeAssistantError):
            asyncio.run(coord.async_set(power=False))
    assert len(LATER) == 1


def test_polling_mode_needs_no_extra_recovery_check(coord_module):
    coord = make(coord_module)
    script(coord, [UpdateFailed("a")])
    with pytest.raises(HomeAssistantError):
        asyncio.run(coord.async_set(power=False))
    assert LATER == []


def test_unloading_cancels_a_pending_recovery_check(coord_module):
    coord = make(coord_module, {"update_interval": 0})
    script(coord, [UpdateFailed("a")])
    with pytest.raises(HomeAssistantError):
        asyncio.run(coord.async_set(power=False))
    asyncio.run(coord.async_shutdown())
    assert LATER[0]["cancelled"] is True


# ---- nothing may hold the integration up forever (it would sit silently on the old state) ----
class SlowClient:
    def __init__(self, hang_disconnect=False):
        self.hang_disconnect, self.disconnects = hang_disconnect, 0

    async def disconnect(self):
        self.disconnects += 1
        if self.hang_disconnect:
            await asyncio.sleep(30)


def test_a_bluetooth_session_that_never_answers_times_out_and_frees_the_lock(coord_module, monkeypatch):
    import germguardian.coordinator as cm
    monkeypatch.setattr(cm, "SESSION_TIMEOUT", 0.05)
    coord = make(cm)
    client = SlowClient()

    async def fake_open(*a, **k):
        return client, SimpleNamespace(get_status=None)
    monkeypatch.setattr(cm, "open_session", fake_open)

    async def hang(sess):
        await asyncio.sleep(30)

    async def ok(sess):
        return STATUS

    async def go():
        with pytest.raises(UpdateFailed, match="did not respond"):
            await coord._with_session(hang)
        return await asyncio.wait_for(coord._with_session(ok), 2)   # the lock is free again

    assert asyncio.run(go()) == STATUS and client.disconnects == 2


def test_a_disconnect_that_never_finishes_does_not_hang_the_integration(coord_module, monkeypatch):
    import germguardian.coordinator as cm
    monkeypatch.setattr(C, "DISCONNECT_TIMEOUT", 0.05)
    coord = make(cm)

    async def fake_open(*a, **k):
        return SlowClient(hang_disconnect=True), None
    monkeypatch.setattr(cm, "open_session", fake_open)

    async def ok(sess):
        return STATUS

    assert asyncio.run(asyncio.wait_for(coord._with_session(ok), 2)) == STATUS
