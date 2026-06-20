"""Button entity for 1Control SoloMini BLE."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .ble_client import SoloMiniClient

_LOGGER = logging.getLogger(__name__)
DOMAIN = "onecontrol_ble"

BUTTON_DESCRIPTIONS: tuple[ButtonEntityDescription, ...] = (
    ButtonEntityDescription(
        key="clone_remote",
        name="Clone remote",
        icon="mdi:remote",
        entity_category=EntityCategory.CONFIG,
    ),
    ButtonEntityDescription(
        key="start_scanner",
        name="1. Start learning",
        icon="mdi:antenna",
        entity_category=EntityCategory.CONFIG,
    ),
    ButtonEntityDescription(
        key="confirm_scanner",
        name="2. Test remote",
        icon="mdi:remote-tv",
        entity_category=EntityCategory.CONFIG,
    ),
    ButtonEntityDescription(
        key="complete_scanner",
        name="3. Save remote",
        icon="mdi:content-save",
        entity_category=EntityCategory.CONFIG,
    ),
    ButtonEntityDescription(
        key="undo_scanner",
        name="Cancel learning",
        icon="mdi:cancel",
        entity_category=EntityCategory.CONFIG,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    client: SoloMiniClient = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for action in client.actions:
        for description in BUTTON_DESCRIPTIONS:
            entities.append(SoloMiniButton(client, entry, description, action))
    async_add_entities(entities)


class SoloMiniButton(ButtonEntity):
    _attr_has_entity_name = True

    def __init__(
        self,
        client: SoloMiniClient,
        entry: ConfigEntry,
        description: ButtonEntityDescription,
        action: int = 0,
    ) -> None:
        self._client = client
        self._entry = entry
        self.entity_description = description
        self._action = action
        
        address_clean = entry.data["address"].replace(":", "").lower()
        if action == 0:
            self._attr_unique_id = f"onecontrol_{address_clean}_{description.key}"
            self._attr_name = description.name
        else:
            self._attr_unique_id = f"onecontrol_{address_clean}_{description.key}_action_{action}"
            self._attr_name = f"{description.name} (Action {action + 1})"

        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, entry.data["address"])},
        )

    async def async_press(self, **kwargs: Any) -> None:
        action = self._action
        key = self.entity_description.key
        success = False

        if key == "clone_remote":
            result = await self._client.clone_remote(action)
            if result is not None:
                _LOGGER.info("Remote cloned, slot=%d", result)
                success = True
            else:
                _LOGGER.error("Remote clone failed")

        elif key == "start_scanner":
            ok = await self._client.start_scanner(action)  # type: ignore[attr-defined]
            _LOGGER.info("Start scanner: %s", "OK" if ok else "FAILED")
            success = ok

        elif key == "confirm_scanner":
            ok = await self._client.confirm_scanner(action)  # type: ignore[attr-defined]
            _LOGGER.info("Confirm scanner: %s", "OK" if ok else "FAILED")
            success = ok

        elif key == "complete_scanner":
            ok = await self._client.complete_scanner(action)  # type: ignore[attr-defined]
            _LOGGER.info("Complete scanner: %s", "OK" if ok else "FAILED")
            success = ok

        elif key == "undo_scanner":
            ok = await self._client.undo_scanner(action)  # type: ignore[attr-defined]
            _LOGGER.info("Undo scanner: %s", "OK" if ok else "FAILED")
            success = ok

        if success:
            coordinator = self.hass.data[DOMAIN][f"{self._entry.entry_id}_coordinator"]
            self.hass.async_create_task(coordinator.async_request_refresh())
