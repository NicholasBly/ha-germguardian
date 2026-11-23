"""Reads the purifier over a short-lived BLE connection, as often as the options say."""
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
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import protocol as P
from .client import GuardianError, open_session, safe_disconnect
from .const import (
    CONF_KEY, CONF_MASTER_UUID, CONF_MODEL, CONF_PROTOCOL, CONF_UPDATE_INTERVAL,
    DEFAULT_UPDATE_INTERVAL, DOMAIN, MODELS,
)

_LOGGER = logging.getLogger(__name__)

# A poll that fails keeps showing the last reading this many times before the entities turn
# 'unavailable': one dropped link is not an outage.
TOLERATED_FAILURES = 2

# A whole connect-login-talk session that takes longer than this is stuck (a frozen adapter can
# leave a Bluetooth call unanswered); give up so the integration does not freeze on the old state.
SESSION_TIMEOUT = 120.0

# "Only when I send a command": after a failed command nothing else would ever look again, so
# check every few minutes until the purifier answers, then stop.
RECOVERY_CHECK_SECONDS = 300


def update_interval(entry: ConfigEntry) -> timedelta | None:
    """The check interval from the options; None = only when a command is sent."""
    seconds = int(entry.options.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL))
    return timedelta(seconds=seconds) if seconds > 0 else None


class GuardianCoordinator(DataUpdateCoordinator[P.Status]):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass, _LOGGER, name=DOMAIN, config_entry=entry,
            update_interval=update_interval(entry),
        )
        self.address: str = entry.unique_id or entry.data[CONF_MASTER_UUID]
        self.mac: str = entry.data["address"]
        self._key = P.parse_key(entry.data[CONF_KEY])
        self._proto: int = entry.data[CONF_PROTOCOL]
        self._lock = asyncio.Lock()
        self._failures = 0
        self._recovery: Any = None          # cancel-function of a pending recovery check
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
            limit = asyncio.timeout(SESSION_TIMEOUT)
            try:
                async with limit:
                    client, sess = await open_session(dev, self._key, self._proto, self.mac)
                    return await fn(sess)
            except TimeoutError as err:
                if limit.expired():
                    raise UpdateFailed(
                        f"the purifier did not respond within {SESSION_TIMEOUT:.0f} s "
                        "(Bluetooth adapter stuck?)"
                    ) from err
                raise UpdateFailed(f"timed out: {err}") from err
            except GuardianError as err:
                raise UpdateFailed(str(err)) from err
            except Exception as err:  # noqa: BLE001 - a raw library error must not reach HA as "Unexpected error"
                _LOGGER.debug("unexpected error talking to the purifier", exc_info=True)
                raise UpdateFailed(f"unexpected {type(err).__name__}: {err}") from err
            finally:
                if client is not None:
                    await safe_disconnect(client)

    async def _async_update_data(self) -> P.Status:
        try:
            status = await self._with_session(lambda s: s.get_status())
        except UpdateFailed as err:
            self._failures += 1
            if self.data is not None and self._failures <= TOLERATED_FAILURES:
                # The first failure of a streak is worth a log line (the reason is the clue).
                (_LOGGER.warning if self._failures == 1 else _LOGGER.debug)(
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
            self._command_failed(err)
            raise HomeAssistantError(str(err)) from err
        self._failures = 0
        self.async_set_updated_data(status)

    def _command_failed(self, err: Exception) -> None:
        """Do not keep showing a state we could neither change nor confirm."""
        self._failures = TOLERATED_FAILURES      # the next failed check is not hidden either
        self.async_set_update_error(err)         # entities show "unavailable"
        if self.update_interval is None:
            self._schedule_recovery()

    def _schedule_recovery(self) -> None:
        if self._recovery is not None:
            return

        async def check(_now: Any) -> None:
            self._recovery = None
            await self.async_refresh()
            if not self.last_update_success and self.update_interval is None:
                self._schedule_recovery()

        self._recovery = async_call_later(self.hass, RECOVERY_CHECK_SECONDS, check)

    async def async_shutdown(self) -> None:
        if self._recovery is not None:
            self._recovery()
            self._recovery = None
        await super().async_shutdown()
