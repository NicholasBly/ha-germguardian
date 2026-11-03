"""Drive the real config_flow.py against a stand-in for Home Assistant's Bluetooth API."""
import asyncio
import sys
import types
from types import SimpleNamespace

import pytest

MASTER = "00000000-24f6-4000-a000-0fedf19130a2"


class StubFlow:
    def __init_subclass__(cls, domain=None, **kw):
        cls.domain = domain

    def __init__(self):
        self.context, self.unique_id, self.configured = {}, None, set()

    def async_abort(self, *, reason, description_placeholders=None):
        return {"type": "abort", "reason": reason, "placeholders": description_placeholders}

    def async_show_form(self, *, step_id, data_schema=None, errors=None, description_placeholders=None):
        return {"type": "form", "step_id": step_id, "schema": data_schema, "errors": errors}

    async def async_set_unique_id(self, uid):
        self.unique_id = uid

    def _abort_if_unique_id_configured(self):
        pass

    def _async_current_ids(self):
        return set(self.configured)


@pytest.fixture
def flow_module():
    ha = types.ModuleType("homeassistant")
    comps = types.ModuleType("homeassistant.components")
    bt = types.ModuleType("homeassistant.components.bluetooth")
    ce = types.ModuleType("homeassistant.config_entries")
    bt.BluetoothServiceInfoBleak = object
    bt.async_discovered_service_info = lambda hass, connectable=True: hass.infos
    bt.async_scanner_count = lambda hass, connectable=True: hass.scanners
    bt.async_ble_device_from_address = lambda hass, addr, connectable=True: None
    ce.ConfigFlow, ce.ConfigFlowResult = StubFlow, dict
    comps.bluetooth, ha.components, ha.config_entries = bt, comps, ce
    names = {"homeassistant": ha, "homeassistant.components": comps,
             "homeassistant.components.bluetooth": bt, "homeassistant.config_entries": ce}
    saved = {n: sys.modules.get(n) for n in names}
    sys.modules.update(names)
    sys.modules.pop("germguardian.config_flow", None)
    try:
        import germguardian.config_flow as cf
        yield cf
    finally:
        sys.modules.pop("germguardian.config_flow", None)
        for n, m in saved.items():
            sys.modules.pop(n, None) if m is None else sys.modules.__setitem__(n, m)


def info(address="00:1C:4D:4B:F0:80", uuids=(MASTER,), connectable=True, rssi=-60):
    return SimpleNamespace(address=address, service_uuids=list(uuids), connectable=connectable, rssi=rssi)


def run_user(cf, infos, scanners=1, configured=()):
    flow = cf.GermGuardianFlow()
    flow.hass = SimpleNamespace(infos=infos, scanners=scanners)
    flow.configured = set(configured)
    return asyncio.run(flow.async_step_user()), flow


def test_unit_with_master_uuid_is_listed(flow_module):
    res, flow = run_user(flow_module, [info(), info("AA:BB:CC:DD:EE:FF", uuids=())])
    assert res["type"] == "form" and list(flow._found) == [MASTER]


def test_unit_known_only_by_aplix_address_is_listed(flow_module):
    res, flow = run_user(flow_module, [info("00:1C:4D:4B:18:DA", uuids=())])
    assert res["type"] == "form" and list(flow._found) == ["00:1c:4d:4b:18:da"]


def test_no_adapter_or_proxy_says_so(flow_module):
    res, _ = run_user(flow_module, [], scanners=0)
    assert res["reason"] == "no_scanner"


def test_adapter_works_but_unit_not_heard_reports_count(flow_module):
    res, _ = run_user(flow_module, [info("AA:BB:CC:DD:EE:FF", uuids=())] * 3)
    assert res["reason"] == "no_devices_found" and res["placeholders"] == {"seen": "3"}


def test_unit_already_set_up_is_not_reported_as_missing(flow_module):
    res, _ = run_user(flow_module, [info()], configured=[MASTER])
    assert res["reason"] == "already_configured"


def test_gateway_picked_by_mistake_gets_a_clear_message(flow_module, monkeypatch):
    from germguardian import client
    async def refuses(*a, **k):
        raise client.UnlockError("cannot read challenge: Read Not Permitted")
    monkeypatch.setattr(flow_module, "open_session", refuses)
    monkeypatch.setattr(flow_module.bluetooth, "async_ble_device_from_address", lambda *a, **k: object())
    flow = flow_module.GermGuardianFlow()
    flow.hass = SimpleNamespace()
    flow._info = info()
    assert asyncio.run(flow._try(bytes(16), 0xEEF3C48D)) == "wrong_unit"
