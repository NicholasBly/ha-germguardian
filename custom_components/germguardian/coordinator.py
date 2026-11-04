"""Polls the purifier over a short-lived BLE connection."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import protocol as P
from .client import GuardianError, open_session
from .const import (
    CONF_KEY, CONF_MASTER_UUID, CONF_MODEL, CONF_PROTOCOL, DOMAIN, MODELS,
    SCAN_INTERVAL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)

# A poll that fails keeps showing the last reading this many times before the entities turn
# 'unavailable' (30 s apart, so about a minute and a half): one dropped link is not an outage.
TOLERATED_FAILURES = 2


class GuardianCoordinator(DataUpdateCoordinator[P.Status]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass, _LOGGER, name=DOMAIN, config_entry=entry,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.address: str = entry.unique_id or entry.data[CONF_MASTER_UUID]
        self.mac: str = entry.data["address"]
        self._key = P.parse_key(entry.data[CONF_KEY])
        self._proto: int = entry.data[CONF_PROTOCOL]
        self._lock = asyncio.Lock()
        self._failures = 0
        model = entry.data[CONF_MODEL]
        self.device_info = DeviceInfo(
            identifiers={(DOMAIN, self.address)},
            name=f"GermGuardian {model}",
            manufacturer="Guardian Technologies",
            model=f"{model} ({MODELS.get(model, '?')})",
        )

    async def _with_session(self, fn: Any) -> Any:
        dev = bluetooth.async_ble_device_from_address(self.hass, self.mac, connectable=True)
        if dev is None:
            raise UpdateFailed("purifier is not in Bluetooth range")
        async with self._lock:
            client = None
            try:
                client, sess = await open_session(dev, self._key, self._proto, self.mac)
                return await fn(sess)
            except GuardianError as err:
                raise UpdateFailed(str(err)) from err
            except Exception as err:  # noqa: BLE001 - a raw library error must not reach HA as "Unexpected error"
                _LOGGER.debug("unexpected error talking to the purifier", exc_info=True)
                raise UpdateFailed(f"unexpected {type(err).__name__}: {err}") from err
            finally:
                if client is not None:
                    try:
                        await client.disconnect()
                    except Exception:  # noqa: BLE001
                        pass

    async def _async_update_data(self) -> P.Status:
        try:
            status = await self._with_session(lambda s: s.get_status())
        except UpdateFailed as err:
            self._failures += 1
            if self.data is not None and self._failures <= TOLERATED_FAILURES:
                _LOGGER.debug(
                    "poll failed (%d of %d tolerated), keeping the last reading: %s",
                    self._failures, TOLERATED_FAILURES, err,
                )
                return self.data
            raise
        self._failures = 0
        return status

    async def async_set(self, **kw: Any) -> None:
        async def run(s: Any) -> P.Status:
            await s.set(**kw)
            await asyncio.sleep(0.35)  # MCU updates asynchronously
            return await s.get_status()

        try:
            status = await self._with_session(run)
        except UpdateFailed as err:
            raise HomeAssistantError(str(err)) from err
        self._failures = 0
        self.async_set_updated_data(status)
