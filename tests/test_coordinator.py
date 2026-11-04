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
        self.hass, self.data = hass, None

    def async_set_updated_data(self, data):
        self.data = data


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
        "homeassistant.helpers.update_coordinator": mod(
            "homeassistant.helpers.update_coordinator",
            DataUpdateCoordinator=StubCoordinator, UpdateFailed=UpdateFailed,
        ),
    }
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


def make(cm):
    entry = SimpleNamespace(
        unique_id="00000000-24f6-4000-a000-0fedf19130a2",
        data={"address": "00:1C:4D:4B:F0:80", "local_key": bytes(16).hex(),
              "protocol_number": 0xEEF3C48D, "model": "CDAP4500BCA", "master_uuid": "x"},
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
