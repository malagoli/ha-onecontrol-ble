"""Number entity for SoloMini BLE."""

from __future__ import annotations

import logging

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .ble_client import SoloMiniClient

_LOGGER = logging.getLogger(__name__)
DOMAIN = "onecontrol_ble"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    client: SoloMiniClient = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for action in client.actions:
        entities.append(SoloMiniOpeningTime(client, entry, action))
    async_add_entities(entities)


class SoloMiniOpeningTime(NumberEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:timer"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_min_value = 0
    _attr_native_max_value = 120
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_mode = NumberMode.BOX
    _attr_native_value: float = 0

    def __init__(self, client: SoloMiniClient, entry: ConfigEntry, action: int = 0) -> None:
        self._client = client
        self._entry = entry
        self._action = action
        
        address_clean = entry.data["address"].replace(":", "").lower()
        if action == 0:
            self._attr_unique_id = f"onecontrol_{address_clean}_opening_time"
            self._attr_name = "Opening time"
        else:
            self._attr_unique_id = f"onecontrol_{address_clean}_opening_time_action_{action}"
            self._attr_name = f"Opening time (Action {action + 1})"

        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, entry.data["address"])},
        )

    async def async_set_native_value(self, value: float) -> None:
        time_s: int = int(value)
        action = self._action
        _LOGGER.info("Setting opening time to %ds for action=%d", time_s, action)
        result = await self._client.set_opening_time(action, time_s)
        if result is not None:
            self._attr_native_value = float(time_s)
            self.async_write_ha_state()
            _LOGGER.info("Opening time set successfully")
        else:
            _LOGGER.error("Failed to set opening time")
