from __future__ import annotations

from typing import Any

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.util.percentage import (
    percentage_to_ranged_value, ranged_value_to_percentage,
)

from .entity import GuardianEntity

SPEEDS = (1, 5)


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([GuardianFan(entry.runtime_data)])


class GuardianFan(GuardianEntity, FanEntity):
    _attr_name = None
    _attr_speed_count = 5
    _attr_preset_modes = ["auto"]
    _attr_supported_features = (
        FanEntityFeature.TURN_ON | FanEntityFeature.TURN_OFF
        | FanEntityFeature.SET_SPEED | FanEntityFeature.PRESET_MODE
    )

    def __init__(self, coord) -> None:
        super().__init__(coord, "fan")

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.power

    @property
    def percentage(self) -> int | None:
        d = self.coordinator.data
        if not d.power or d.wind == 0:
            return 0
        return ranged_value_to_percentage(SPEEDS, d.wind)

    @property
    def preset_mode(self) -> str | None:
        d = self.coordinator.data
        return "auto" if d.power and d.auto else None

    async def async_turn_on(self, percentage=None, preset_mode=None, **kwargs: Any) -> None:
        if preset_mode == "auto":
            await self.coordinator.async_set(power=True, auto=True)
        elif percentage:
            await self.async_set_percentage(percentage)
        else:
            await self.coordinator.async_set(power=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set(power=False)

    async def async_set_percentage(self, percentage: int) -> None:
        if percentage == 0:
            await self.async_turn_off()
            return
        wind = round(percentage_to_ranged_value(SPEEDS, percentage))
        wind = max(1, min(5, wind))
        await self.coordinator.async_set(power=True, auto=False, wind=wind)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        await self.coordinator.async_set(power=True, auto=True)
