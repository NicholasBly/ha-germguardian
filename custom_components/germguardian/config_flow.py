"""Config flow: pick the unit, pick the model, give it the key you already have."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from . import protocol as P
from .client import AuthError, GuardianError, UnlockError, open_session
from .pairing import PairResult, pair_over_ble
from .const import (
    CONF_KEY, CONF_MASTER_UUID, CONF_MODEL, CONF_PROTOCOL, DEFAULT_PROTOCOL,
    DOMAIN, FEF8_UUID, MASTER_PREFIX, MODELS,
)

_LOGGER = logging.getLogger(__name__)

# Right after registration the unit needs a few seconds before it accepts a connection again.
PAIR_SETTLE_ATTEMPTS = 4
PAIR_RETRY_DELAY = 3.0


def master_uuid(info: BluetoothServiceInfoBleak) -> str | None:
    for u in info.service_uuids:
        if u.lower().startswith(MASTER_PREFIX):
            return u.lower()
    return None


def _is_unit(info: BluetoothServiceInfoBleak) -> bool:
    return info.connectable and (
        master_uuid(info) is not None
        or FEF8_UUID in [u.lower() for u in info.service_uuids]
        or info.address.upper().startswith("00:1C:4D:")  # Aplix OUI
    )


class GermGuardianFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._info: BluetoothServiceInfoBleak | None = None
        self._found: dict[str, BluetoothServiceInfoBleak] = {}
        self._paired: PairResult | None = None   # kept, so LINK is only needed once per flow

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
        infos = list(bluetooth.async_discovered_service_info(self.hass, connectable=True))
        units = [i for i in infos if _is_unit(i)]
        configured = self._async_current_ids()
        self._found = {self._uid(i): i for i in units if self._uid(i) not in configured}
        if not self._found:
            if units:
                return self.async_abort(reason="already_configured")
            # Say WHY nothing was found: no adapter/proxy at all, or it just can't hear the unit.
            scanners = bluetooth.async_scanner_count(self.hass, connectable=True)
            _LOGGER.warning(
                "No GermGuardian purifier found: %d connectable Bluetooth scanner(s), %d devices seen",
                scanners, len(infos),
            )
            if scanners == 0:
                return self.async_abort(reason="no_scanner")
            return self.async_abort(
                reason="no_devices_found", description_placeholders={"seen": str(len(infos))}
            )
        opts = {k: f"{v.address} ({v.rssi} dBm)" for k, v in self._found.items()}
        return self.async_show_form(
            step_id="user", data_schema=vol.Schema({vol.Required("unit"): vol.In(opts)})
        )

    async def async_step_setup(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        assert self._info is not None
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                text = user_input.get(CONF_KEY, "").strip()
                key = P.parse_key(text) if text else None
                proto = int(user_input[CONF_PROTOCOL].replace("0x", ""), 16)
            except ValueError:
                errors["base"] = "bad_key"
            else:
                err = None
                after_pairing = False
                if key is None:
                    if self._paired is None:
                        self._paired, err = await self._pair(proto)
                    if self._paired is not None:
                        key, proto = self._paired.key, self._paired.protocol   # server's number wins
                        after_pairing = True
                if not err:
                    check = self._try_after_pairing if after_pairing else self._try
                    err = await check(key, proto)
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
            vol.Optional(CONF_KEY, default=""): str,
            vol.Required(CONF_PROTOCOL, default=f"{DEFAULT_PROTOCOL:08X}"): str,
        })
        return self.async_show_form(
            step_id="setup", data_schema=schema, errors=errors,
            description_placeholders={
                "address": self._info.address,
                "detail": getattr(self, "_pair_error", ""),
            },
        )

    async def _try_after_pairing(self, key: bytes, proto: int) -> str | None:
        err = None
        for attempt in range(PAIR_SETTLE_ATTEMPTS):
            err = await self._try(key, proto)
            if err not in ("cannot_connect", "not_in_range"):
                return err
            if attempt < PAIR_SETTLE_ATTEMPTS - 1:
                await asyncio.sleep(PAIR_RETRY_DELAY)
        return err

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
        except UnlockError:
            return "wrong_unit"
        except GuardianError:
            return "cannot_connect"
        finally:
            if client is not None:
                try:
                    await client.disconnect()
                except Exception:  # noqa: BLE001
                    pass
        return None

    async def _pair(self, proto: int) -> tuple[PairResult | None, str | None]:
        mu = self.unique_id if (self.unique_id or "").startswith(MASTER_PREFIX) else None
        if mu is None:
            return None, "no_master_uuid"
        dev = bluetooth.async_ble_device_from_address(self.hass, self._info.address, connectable=True)
        if dev is None:
            return None, "not_in_range"
        try:
            return await pair_over_ble(dev, mu, proto), None
        except GuardianError as err:
            _LOGGER.warning("pairing failed: %s", err)
            self._pair_error = str(err)
            return None, "pair_failed"
