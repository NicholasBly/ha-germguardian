from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity

from .entity import GuardianEntity


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities([GuardianUV(entry.runtime_data)])


class GuardianUV(GuardianEntity, SwitchEntity):
    _attr_translation_key = "uv"

    def __init__(self, coord) -> None:
        super().__init__(coord, "uv")

    @property
    def is_on(self) -> bool:
        return self.coordinator.data.uv

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set(uv=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set(uv=False)
