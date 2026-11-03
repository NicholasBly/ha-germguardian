from __future__ import annotations

from homeassistant.components.select import SelectEntity

from . import protocol as P
from .entity import GuardianEntity

OPTIONS = {h: ("off" if h == 0 else f"{h}h") for h in P.TIMER_HOURS}


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([GuardianTimer(entry.runtime_data)])


class GuardianTimer(GuardianEntity, SelectEntity):
    _attr_translation_key = "timer"
    _attr_options = list(OPTIONS.values())

    def __init__(self, coord) -> None:
        super().__init__(coord, "timer")

    @property
    def current_option(self) -> str | None:
        return OPTIONS.get(self.coordinator.data.timer)

    async def async_select_option(self, option: str) -> None:
        hours = next(h for h, o in OPTIONS.items() if o == option)
        await self.coordinator.async_set(timer=hours)
