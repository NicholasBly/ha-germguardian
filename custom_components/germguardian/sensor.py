from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.const import PERCENTAGE, UnitOfTime

from .const import BULB_LIFE_HOURS, FILTER_LIFE_HOURS
from .entity import GuardianEntity


def _life(used: int, total: int) -> int:
    return max(0, round(100 * (total - used) / total))


SENSORS = (
    ("air_quality", None, None, lambda d: d.air_quality),
    ("filter_hours", UnitOfTime.HOURS, None, lambda d: d.filter_hours),
    ("filter_life", None, PERCENTAGE, lambda d: _life(d.filter_hours, FILTER_LIFE_HOURS)),
    ("bulb_hours", UnitOfTime.HOURS, None, lambda d: d.bulb_hours),
    ("bulb_life", None, PERCENTAGE, lambda d: _life(d.bulb_hours, BULB_LIFE_HOURS)),
)


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities(GuardianSensor(entry.runtime_data, *s) for s in SENSORS)


class GuardianSensor(GuardianEntity, SensorEntity):
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coord, key, _unit_time, unit_pct, fn) -> None:
        super().__init__(coord, key)
        self._attr_translation_key = key
        self._attr_native_unit_of_measurement = _unit_time or unit_pct
        self._fn = fn

    @property
    def native_value(self):
        return self._fn(self.coordinator.data)
