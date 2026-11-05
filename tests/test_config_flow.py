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

    def async_create_entry(self, *, title, data):
        return {"type": "create_entry", "title": title, "data": data}

    async def async_set_unique_id(self, uid):
        self.unique_id = uid

    def _abort_if_unique_id_configured(self):
        pass

    def _async_current_ids(self):
        return set(self.configured)


class StubOptionsFlow:
    def async_show_form(self, *, step_id, data_schema=None, errors=None, description_placeholders=None):
        return {"type": "form", "step_id": step_id, "schema": data_schema, "errors": errors}

    def async_create_entry(self, *, data, title=""):
        return {"type": "create_entry", "data": data}


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
    ce.ConfigFlow, ce.ConfigFlowResult, ce.OptionsFlow, ce.ConfigEntry = StubFlow, dict, StubOptionsFlow, object
    core = types.ModuleType("homeassistant.core")
    core.callback = lambda f: f
    comps.bluetooth, ha.components, ha.config_entries, ha.core = bt, comps, ce, core
    names = {"homeassistant": ha, "homeassistant.components": comps,
             "homeassistant.components.bluetooth": bt, "homeassistant.config_entries": ce,
             "homeassistant.core": core}
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


# ---- right after pairing the unit may need a moment before it accepts a connection ----
def _setup_flow(cf, monkeypatch, try_results):
    from germguardian.pairing import PairResult
    monkeypatch.setattr(cf, "PAIR_RETRY_DELAY", 0)
    flow = cf.GermGuardianFlow()
    flow.hass = SimpleNamespace()
    flow._info = info()
    flow.unique_id = MASTER
    flow.calls = {"pair": 0, "try": 0}

    async def fake_pair(proto):
        flow.calls["pair"] += 1
        return PairResult(bytes(range(16)), 0xEEF3C48D), None

    async def fake_try(key, proto):
        flow.calls["try"] += 1
        return try_results.pop(0) if try_results else None

    flow._pair, flow._try = fake_pair, fake_try
    return flow


FORM = {"model": "CDAP4500BCA", "local_key": "", "protocol_number": "EEF3C48D"}


def test_check_after_pairing_is_retried_while_the_unit_settles(flow_module, monkeypatch):
    flow = _setup_flow(flow_module, monkeypatch, ["cannot_connect", "not_in_range", None])
    res = asyncio.run(flow.async_step_setup(dict(FORM)))
    assert res["type"] == "create_entry" and res["data"]["local_key"] == bytes(range(16)).hex()
    assert flow.calls == {"pair": 1, "try": 3}


def test_paired_key_is_kept_so_link_is_not_needed_twice(flow_module, monkeypatch):
    flow = _setup_flow(flow_module, monkeypatch, ["cannot_connect"] * 4)
    res = asyncio.run(flow.async_step_setup(dict(FORM)))
    assert res["type"] == "form" and res["errors"] == {"base": "cannot_connect"}
    res = asyncio.run(flow.async_step_setup(dict(FORM)))       # user presses Submit again
    assert res["type"] == "create_entry"
    assert flow.calls["pair"] == 1                              # did not pair a second time


def test_wrong_key_is_not_retried(flow_module, monkeypatch):
    flow = _setup_flow(flow_module, monkeypatch, ["invalid_auth"])
    res = asyncio.run(flow.async_step_setup(dict(FORM)))
    assert res["errors"] == {"base": "invalid_auth"} and flow.calls["try"] == 1


# ---- pairing starts when the unit's LINK signal is on the air, like the command-line tool ----
UNIT_ADDR = "00:1C:4D:4B:F0:80"


def _pair_flow(cf, monkeypatch, polls):
    """`polls` is a list: what Bluetooth sees on each look (the last entry repeats)."""
    from germguardian.pairing import PairResult
    monkeypatch.setattr(cf, "LINK_POLL_SECONDS", 0.001)
    monkeypatch.setattr(cf, "LINK_WAIT_SECONDS", 0.05)
    looks = {"n": 0}

    def discovered(hass, connectable=True):
        i = min(looks["n"], len(polls) - 1)
        looks["n"] += 1
        return polls[i]

    monkeypatch.setattr(cf.bluetooth, "async_discovered_service_info", discovered)
    monkeypatch.setattr(cf.bluetooth, "async_ble_device_from_address", lambda *a, **k: object())
    paired = {"n": 0}

    async def fake_pair_over_ble(dev, mu, proto, progress=None):
        paired["n"] += 1
        if progress:
            progress("Connecting to the purifier")
        return PairResult(bytes(range(16)), 0xEEF3C48D)

    monkeypatch.setattr(cf, "pair_over_ble", fake_pair_over_ble)
    flow = cf.GermGuardianFlow()
    flow.hass, flow._info, flow.unique_id = SimpleNamespace(), info(), MASTER
    return flow, looks, paired


LINK_BEACON = info("C2:1C:4D:4B:F0:80", uuids=(), connectable=False)
OTHER_UNITS_BEACON = info("C1:1C:4D:4B:18:DA", uuids=(), connectable=False)


def test_link_signal_is_recognised_per_unit(flow_module):
    hass = SimpleNamespace(infos=[LINK_BEACON, OTHER_UNITS_BEACON], scanners=1)
    assert flow_module.link_visible(hass, UNIT_ADDR)
    assert not flow_module.link_visible(SimpleNamespace(infos=[OTHER_UNITS_BEACON]), UNIT_ADDR)
    assert not flow_module.link_visible(SimpleNamespace(infos=[info()]), UNIT_ADDR)   # the unit itself


def test_an_old_link_signal_does_not_count(flow_module):
    """HA remembers the last advertisement of every device for minutes. A beacon from the
    previous attempt must not make the next attempt think LINK is held right now."""
    import time
    old = info("C2:1C:4D:4B:F0:80", uuids=(), connectable=False)
    old.time = time.monotonic() - 60
    fresh = info("C2:1C:4D:4B:F0:80", uuids=(), connectable=False)
    fresh.time = time.monotonic() - 1
    assert not flow_module.link_visible(SimpleNamespace(infos=[old]), UNIT_ADDR)
    assert flow_module.link_visible(SimpleNamespace(infos=[old, fresh]), UNIT_ADDR)


def test_an_unexpected_error_is_a_pairing_failure_with_a_reason_not_unknown_error(
    flow_module, monkeypatch, caplog
):
    flow, _, _ = _pair_flow(flow_module, monkeypatch, [[LINK_BEACON]])

    async def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(flow_module, "pair_over_ble", boom)
    res, err = asyncio.run(flow._pair(0xEEF3C48D))
    assert res is None and err == "pair_failed"
    assert "kaboom" in flow._pair_error                  # shown on the form
    assert "kaboom" in caplog.text                       # and logged with its traceback


def test_pairing_waits_for_link_then_goes(flow_module, monkeypatch):
    flow, looks, paired = _pair_flow(flow_module, monkeypatch, [[], [], [OTHER_UNITS_BEACON], [LINK_BEACON]])
    res, err = asyncio.run(flow._pair(0xEEF3C48D))
    assert err is None and res.key == bytes(range(16))
    assert paired["n"] == 1 and looks["n"] == 4         # it looked until the signal appeared


def test_pairing_still_tries_if_the_signal_is_never_seen(flow_module, monkeypatch):
    flow, looks, paired = _pair_flow(flow_module, monkeypatch, [[OTHER_UNITS_BEACON]])
    res, err = asyncio.run(flow._pair(0xEEF3C48D))
    assert err is None and paired["n"] == 1             # some adapters hide it: do not block
    assert looks["n"] > 5                               # but it did wait first


def test_pairing_steps_are_logged_for_the_ha_log(flow_module, monkeypatch, caplog):
    import logging
    flow, _, _ = _pair_flow(flow_module, monkeypatch, [[LINK_BEACON]])
    with caplog.at_level(logging.INFO):
        asyncio.run(flow._pair(0xEEF3C48D))
    text = caplog.text
    assert "LINK signal seen" in text and "Connecting to the purifier" in text


# ---- options: how often Home Assistant checks the purifier ----
def _options(cf, current):
    flow = cf.GermGuardianFlow.async_get_options_flow(SimpleNamespace(options=current))
    flow.config_entry = SimpleNamespace(options=current)       # HA sets this itself
    return flow


def _default(form):
    (key,) = list(form["schema"].schema)
    return key.default()


def test_options_offer_the_check_interval_with_the_current_choice_selected(flow_module):
    form = asyncio.run(_options(flow_module, {}).async_step_init())
    assert form["type"] == "form" and _default(form) == "60"
    form = asyncio.run(_options(flow_module, {"update_interval": 300}).async_step_init())
    assert _default(form) == "300"
    (key,) = list(form["schema"].schema)
    choices = form["schema"].schema[key].container
    assert "0" in choices and "only" in choices["0"].lower()


def test_options_save_the_interval_as_seconds(flow_module):
    res = asyncio.run(_options(flow_module, {}).async_step_init({"update_interval": "0"}))
    assert res == {"type": "create_entry", "data": {"update_interval": 0}}
