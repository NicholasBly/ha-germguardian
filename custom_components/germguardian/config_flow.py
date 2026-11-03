"""Config flow: pick the unit, pick the model, give it the key you already have."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from . import protocol as P
from .client import AuthError, GuardianError, open_session
from .const import (
    CONF_KEY, CONF_MASTER_UUID, CONF_MODEL, CONF_PROTOCOL, DEFAULT_PROTOCOL,
    DOMAIN, FEF8_UUID, MASTER_PREFIX, MODELS,
)

_LOGGER = logging.getLogger(__name__)


def master_uuid(info: BluetoothServiceInfoBleak) -> str | None:
    for u in info.service_uuids:
        if u.lower().startswith(MASTER_PREFIX):
            return u.lower()
    return None


def _is_unit(info: BluetoothServiceInfoBleak) -> bool:
    return info.connectable and (
        master_uuid(info) is not None or FEF8_UUID in [u.lower() for u in info.service_uuids]
    )


class GermGuardianFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._info: BluetoothServiceInfoBleak | None = None
        self._found: dict[str, BluetoothServiceInfoBleak] = {}

    def _uid(self, info: BluetoothServiceInfoBleak) -> str:
        return master_uuid(info) or info.address.lower()

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak) -> ConfigFlowResult:
        await self.async_set_unique_id(self._uid(discovery_info))
        self._abort_if_unique_id_configured()
        self._info = discovery_info
        self.context["title_placeholders"] = {"name": f"GermGuardian {discovery_info.address}"}
        return await self.async_step_setup()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            self._info = self._found[user_input["unit"]]
            await self.async_set_unique_id(self._uid(self._info))
            self._abort_if_unique_id_configured()
            return await self.async_step_setup()
        self._found = {
            self._uid(i): i
            for i in bluetooth.async_discovered_service_info(self.hass, connectable=True)
            if _is_unit(i) and self._uid(i) not in self._async_current_ids()
        }
        if not self._found:
            return self.async_abort(reason="no_devices_found")
        opts = {k: f"{v.address} ({v.rssi} dBm)" for k, v in self._found.items()}
        return self.async_show_form(
            step_id="user", data_schema=vol.Schema({vol.Required("unit"): vol.In(opts)})
        )

    async def async_step_setup(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        assert self._info is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                key = P.parse_key(user_input[CONF_KEY])
                proto = int(user_input[CONF_PROTOCOL].replace("0x", ""), 16)
            except ValueError:
                errors["base"] = "bad_key"
            else:
                err = await self._try(key, proto)
                if err:
                    errors["base"] = err
                else:
                    return self.async_create_entry(
                        title=f"GermGuardian {user_input[CONF_MODEL]}",
                        data={
                            CONF_MASTER_UUID: self.unique_id,
                            "address": self._info.address,
                            CONF_KEY: key.hex(),
                            CONF_MODEL: user_input[CONF_MODEL],
                            CONF_PROTOCOL: proto,
                        },
                    )
        schema = vol.Schema({
            vol.Required(CONF_MODEL, default="CDAP4500BCA"): vol.In(list(MODELS)),
            vol.Required(CONF_KEY): str,
            vol.Required(CONF_PROTOCOL, default=f"{DEFAULT_PROTOCOL:08X}"): str,
        })
        return self.async_show_form(
            step_id="setup", data_schema=schema, errors=errors,
            description_placeholders={"address": self._info.address},
        )

    async def _try(self, key: bytes, proto: int) -> str | None:
        dev = bluetooth.async_ble_device_from_address(self.hass, self._info.address, connectable=True)
        if dev is None:
            return "not_in_range"
        client = None
        try:
            client, sess = await open_session(dev, key, proto, self._info.address)
            await sess.get_status()
        except AuthError:
            return "invalid_auth"
        except GuardianError:
            return "cannot_connect"
        finally:
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
        return None
