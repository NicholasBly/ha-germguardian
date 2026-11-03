from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import GuardianCoordinator


class GuardianEntity(CoordinatorEntity[GuardianCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coord: GuardianCoordinator, key: str) -> None:
        super().__init__(coord)
        self._attr_unique_id = f"{coord.address}_{key}"
        self._attr_device_info = coord.device_info
