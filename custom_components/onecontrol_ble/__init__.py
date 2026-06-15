"""1Control SoloMini BLE integration for Home Assistant."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothChange,
    BluetoothScanningMode,
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_register_callback,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .ble_client import SoloMiniClient
from .protocol import SecurityData

_LOGGER = logging.getLogger(__name__)
DOMAIN = "onecontrol_ble"
PLATFORMS = ["button", "cover", "number", "sensor", "switch", "text"]
SCAN_INTERVAL = timedelta(hours=1)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    sec = SecurityData(
        ltk=bytes.fromhex(entry.data["ltk"]),
        session_key=bytes.fromhex(entry.data["session_key"]),
        session_id=bytes.fromhex(entry.data["session_id"]),
        user_id=entry.data.get("user_id", 0),
        last_cc=entry.data.get("last_cc", 0),
    )

    address = entry.data["address"]
    ble_device = async_ble_device_from_address(hass, address, connectable=True)

    action_data = entry.data.get("action", 0)
    if isinstance(action_data, int):
        actions = [action_data]
    elif isinstance(action_data, str):
        try:
            actions = [int(x.strip()) for x in action_data.split(",") if x.strip()]
        except Exception:
            actions = [0]
    else:
        actions = [0]
    if not actions:
        actions = [0]

    client = SoloMiniClient(
        address=address,
        security=sec,
        actions=actions,
        ble_device=ble_device,
    )

    async def _fetch_all() -> dict:
        result: dict = {}
        try:
            system_info = await client.get_system_info()
            result.update(system_info)
        except Exception as e:
            _LOGGER.error("Failed to get system info: %s", e)

        try:
            users = await client.get_users()
            result["users"] = users
        except Exception as e:
            _LOGGER.error("Failed to get users: %s", e)
            result["users"] = []

        return result

    coordinator: DataUpdateCoordinator[dict] = DataUpdateCoordinator(
        hass,
        _LOGGER,
        config_entry=entry,
        name=f"onecontrol_{address}",
        update_method=_fetch_all,
        update_interval=SCAN_INTERVAL,
    )

    hass.data[DOMAIN][entry.entry_id] = client
    hass.data[DOMAIN][f"{entry.entry_id}_coordinator"] = coordinator
    hass.data[DOMAIN][f"{entry.entry_id}_users_coordinator"] = coordinator

    @callback
    def _async_update_ble(
        service_info: BluetoothServiceInfoBleak,
        change: BluetoothChange,
    ) -> None:
        client.set_ble_device(service_info.device)
        _LOGGER.debug("BLE device updated: %s", service_info.address)

    entry.async_on_unload(
        async_register_callback(
            hass,
            _async_update_ble,
            BluetoothCallbackMatcher(address=address),
            BluetoothScanningMode.ACTIVE,
        )
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    hass.async_create_task(coordinator.async_request_refresh())

    from homeassistant.core import ServiceCall

    async def handle_add_user(call: ServiceCall) -> None:
        entry_id = call.data["config_entry_id"]
        c: SoloMiniClient = hass.data[DOMAIN].get(entry_id)
        if not c:
            return
        result = await c.add_user()  # type: ignore[attr-defined]
        if result:
            _LOGGER.warning(
                "User added: uid=%d, ltk=%s (save this LTK!)", result["uid"], result["ltk"]
            )
            uc = hass.data[DOMAIN].get(f"{entry_id}_coordinator")
            if uc:
                await uc.async_request_refresh()

    async def handle_delete_user(call: ServiceCall) -> None:
        entry_id = call.data["config_entry_id"]
        uid = int(call.data["uid"])
        c: SoloMiniClient = hass.data[DOMAIN].get(entry_id)
        if not c:
            return
        ok = await c.delete_user(uid)  # type: ignore[attr-defined]
        _LOGGER.info("Delete user uid=%d: %s", uid, "OK" if ok else "FAILED")
        if ok:
            uc = hass.data[DOMAIN].get(f"{entry_id}_coordinator")
            if uc:
                await uc.async_request_refresh()

    async def handle_set_user_name(call: ServiceCall) -> None:
        entry_id = call.data["config_entry_id"]
        uid = int(call.data["uid"])
        name = str(call.data["name"])
        c: SoloMiniClient = hass.data[DOMAIN].get(entry_id)
        if not c:
            return
        ok = await c.set_user_name(uid, name)  # type: ignore[attr-defined]
        _LOGGER.info("Set user name uid=%d name=%s: %s", uid, name, "OK" if ok else "FAILED")
        if ok:
            uc = hass.data[DOMAIN].get(f"{entry_id}_coordinator")
            if uc:
                await uc.async_request_refresh()

    hass.services.async_register(DOMAIN, "add_user", handle_add_user)
    hass.services.async_register(DOMAIN, "delete_user", handle_delete_user)
    hass.services.async_register(DOMAIN, "set_user_name", handle_set_user_name)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
