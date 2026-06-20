"""Tests for multi-action support."""

from unittest.mock import MagicMock, AsyncMock, patch
import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from custom_components.onecontrol_ble import async_setup_entry
from custom_components.onecontrol_ble.config_flow import OneControlConfigFlow
from custom_components.onecontrol_ble.cover import async_setup_entry as async_setup_cover
from custom_components.onecontrol_ble.button import async_setup_entry as async_setup_button
from custom_components.onecontrol_ble.number import async_setup_entry as async_setup_number
from custom_components.onecontrol_ble.ble_client import SoloMiniClient
from custom_components.onecontrol_ble.protocol import SecurityData
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak

@pytest.mark.asyncio
async def test_config_flow_discovery():
    flow = OneControlConfigFlow()
    flow.hass = MagicMock()
    
    mock_service_info = MagicMock(spec=BluetoothServiceInfoBleak)
    mock_service_info.address = "AA:BB:CC:DD:EE:FF"
    mock_service_info.name = "My SoloMini"
    mock_service_info.service_uuids = ["d973f2e0-b19e-11e2-9e96-0800200c9a66"]
    
    with patch("custom_components.onecontrol_ble.config_flow.async_discovered_service_info", return_value=[mock_service_info]) as mock_discovered, \
         patch.object(flow, "async_step_pick_device", return_value=AsyncMock()) as mock_pick_device:
        
        await flow.async_step_user()
        
        mock_discovered.assert_called_once_with(flow.hass, connectable=False)
        mock_pick_device.assert_called_once()
        assert flow._discovered_devices["AA:BB:CC:DD:EE:FF"] == "My SoloMini (AA:BB:CC:DD:EE:FF)"

# Mocking config flow
@pytest.mark.asyncio
async def test_config_flow_validation():
    flow = OneControlConfigFlow()
    flow.hass = MagicMock()
    flow._discovered_address = "AA:BB:CC:DD:EE:FF"
    flow._discovered_name = "SoloMini"
    flow._parsed = {}
    flow.async_set_unique_id = AsyncMock()
    flow._abort_if_unique_id_configured = MagicMock()
    flow.async_create_entry = MagicMock()

    # Valid input
    user_input = {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "SoloMini",
        "ltk": "11223344556677889900aabbccddeeff",
        "session_key": "11223344556677889900aabbccddeeff",
        "session_id": "1122334455667788",
        "user_id": 0,
        "action": "0, 1, 2",
    }
    
    with patch("custom_components.onecontrol_ble.config_flow._is_hex", return_value=True):
        await flow.async_step_device(user_input)
        flow.async_create_entry.assert_called_once()
        args, kwargs = flow.async_create_entry.call_args
        assert kwargs["data"]["action"] == "0, 1, 2"

    # Invalid input: negative action
    flow.async_create_entry.reset_mock()
    user_input["action"] = "0, -1"
    with patch("custom_components.onecontrol_ble.config_flow._is_hex", return_value=True), \
         patch.object(flow, "async_show_form") as mock_show_form:
        await flow.async_step_device(user_input)
        flow.async_create_entry.assert_not_called()
        mock_show_form.assert_called_once()
        errors = mock_show_form.call_args[1]["errors"]
        assert errors.get("action") == "invalid_actions"

    # Invalid input: non-integer action
    flow.async_create_entry.reset_mock()
    user_input["action"] = "0, abc"
    with patch("custom_components.onecontrol_ble.config_flow._is_hex", return_value=True), \
         patch.object(flow, "async_show_form") as mock_show_form:
        await flow.async_step_device(user_input)
        flow.async_create_entry.assert_not_called()
        mock_show_form.assert_called_once()
        errors = mock_show_form.call_args[1]["errors"]
        assert errors.get("action") == "invalid_actions"


@pytest.mark.asyncio
async def test_init_setup_entry_parsing():
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)
    
    # 1. New multiple actions config entry
    entry_multi = MagicMock(spec=ConfigEntry)
    entry_multi.entry_id = "test_entry_id"
    entry_multi.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "ltk": "11223344556677889900aabbccddeeff",
        "session_key": "11223344556677889900aabbccddeeff",
        "session_id": "1122334455667788",
        "action": "0, 1, 3",
        "last_cc": 0,
    }
    
    with patch("custom_components.onecontrol_ble.async_ble_device_from_address", return_value=MagicMock()), \
         patch("custom_components.onecontrol_ble.SoloMiniClient") as mock_client_cls, \
         patch("custom_components.onecontrol_ble.SecurityData") as mock_sec_cls, \
         patch("custom_components.onecontrol_ble.async_register_callback") as mock_reg_cb:
        
        await async_setup_entry(hass, entry_multi)
        
        # Verify SoloMiniClient was called with actions=[0, 1, 3]
        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args[1]
        assert kwargs["actions"] == [0, 1, 3]

    # 2. Old single action config entry (backward compatibility)
    entry_old = MagicMock(spec=ConfigEntry)
    entry_old.entry_id = "test_entry_id_old"
    entry_old.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "ltk": "11223344556677889900aabbccddeeff",
        "session_key": "11223344556677889900aabbccddeeff",
        "session_id": "1122334455667788",
        "action": 2, # Old int action
        "last_cc": 0,
    }
    
    with patch("custom_components.onecontrol_ble.async_ble_device_from_address", return_value=MagicMock()), \
         patch("custom_components.onecontrol_ble.SoloMiniClient") as mock_client_cls, \
         patch("custom_components.onecontrol_ble.SecurityData") as mock_sec_cls, \
         patch("custom_components.onecontrol_ble.async_register_callback") as mock_reg_cb:
        
        mock_client_cls.reset_mock()
        await async_setup_entry(hass, entry_old)
        
        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args[1]
        assert kwargs["actions"] == [2]


@pytest.mark.asyncio
async def test_entities_creation():
    hass = MagicMock()
    entry = MagicMock(spec=ConfigEntry)
    entry.entry_id = "test_entry_id"
    entry.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "SoloMini Device",
    }
    
    client = SoloMiniClient(
        address="AA:BB:CC:DD:EE:FF",
        security=MagicMock(spec=SecurityData),
        actions=[0, 1, 2]
    )
    hass.data = {"onecontrol_ble": {entry.entry_id: client}}

    # 1. Cover entities creation
    added_covers = []
    def add_covers(entities, update_before_add=False):
        added_covers.extend(entities)
    
    await async_setup_cover(hass, entry, add_covers)
    
    assert len(added_covers) == 3
    # Check naming and IDs
    assert added_covers[0]._attr_unique_id == "onecontrol_aabbccddeeff"
    assert added_covers[0]._attr_name is None
    assert added_covers[0]._action == 0

    assert added_covers[1]._attr_unique_id == "onecontrol_aabbccddeeff_action_1"
    assert added_covers[1]._attr_name == "Action 2"
    assert added_covers[1]._action == 1

    assert added_covers[2]._attr_unique_id == "onecontrol_aabbccddeeff_action_2"
    assert added_covers[2]._attr_name == "Action 3"
    assert added_covers[2]._action == 2

    # 2. Button entities creation (5 button descriptions per action)
    added_buttons = []
    def add_buttons(entities):
        added_buttons.extend(entities)
        
    await async_setup_button(hass, entry, add_buttons)
    
    # 3 actions * 5 buttons = 15 entities
    assert len(added_buttons) == 15
    # Let's inspect buttons for action 0
    action0_buttons = [b for b in added_buttons if b._action == 0]
    assert len(action0_buttons) == 5
    assert action0_buttons[0]._attr_unique_id == "onecontrol_aabbccddeeff_clone_remote"
    assert action0_buttons[0]._attr_name == "Clone remote"

    # Let's inspect buttons for action 1
    action1_buttons = [b for b in added_buttons if b._action == 1]
    assert len(action1_buttons) == 5
    assert action1_buttons[0]._attr_unique_id == "onecontrol_aabbccddeeff_clone_remote_action_1"
    assert action1_buttons[0]._attr_name == "Clone remote (Action 2)"

    # 3. Number entities creation (1 opening time entity per action)
    added_numbers = []
    def add_numbers(entities):
        added_numbers.extend(entities)
        
    await async_setup_number(hass, entry, add_numbers)
    
    assert len(added_numbers) == 3
    assert added_numbers[0]._attr_unique_id == "onecontrol_aabbccddeeff_opening_time"
    assert added_numbers[0]._attr_name == "Opening time"
    assert added_numbers[0]._action == 0

    assert added_numbers[1]._attr_unique_id == "onecontrol_aabbccddeeff_opening_time_action_1"
    assert added_numbers[1]._attr_name == "Opening time (Action 2)"
    assert added_numbers[1]._action == 1


@pytest.mark.asyncio
async def test_cover_open_updates_battery():
    hass = MagicMock()
    entry = MagicMock(spec=ConfigEntry)
    entry.entry_id = "test_entry_id"
    entry.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "SoloMini Device",
    }
    
    mock_sec = MagicMock(spec=SecurityData)
    mock_sec.last_cc = 5
    mock_sec.battery_raw = 2700
    
    client = MagicMock(spec=SoloMiniClient)
    client.actions = [0]
    client.action = 0
    client.security = mock_sec
    client.open_gate = AsyncMock(return_value=True)
    
    coordinator = MagicMock()
    coordinator.data = {"battery_raw": 2600}
    coordinator.async_set_updated_data = MagicMock()
    
    hass.data = {
        "onecontrol_ble": {
            entry.entry_id: client,
            f"{entry.entry_id}_coordinator": coordinator,
        }
    }
    
    added_covers = []
    def add_covers(entities, update_before_add=False):
        added_covers.extend(entities)
        
    await async_setup_cover(hass, entry, add_covers)
    assert len(added_covers) == 1
    
    cover = added_covers[0]
    cover.hass = hass
    cover.async_write_ha_state = MagicMock()
    
    # Trigger opening
    await cover.async_open_cover()
    
    # Assertions
    client.open_gate.assert_called_once_with(0)
    assert coordinator.data["battery_raw"] == 2700
    coordinator.async_set_updated_data.assert_called_once_with({"battery_raw": 2700})
    hass.async_create_task.assert_called_once()
    coordinator.async_request_refresh.assert_called_once()


@pytest.mark.asyncio
async def test_button_press_refreshes_coordinator():
    hass = MagicMock()
    entry = MagicMock(spec=ConfigEntry)
    entry.entry_id = "test_entry_id"
    entry.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "SoloMini Device",
    }
    
    client = MagicMock(spec=SoloMiniClient)
    client.actions = [0]
    client.action = 0
    client.start_scanner = AsyncMock(return_value=True)
    
    coordinator = MagicMock()
    
    hass.data = {
        "onecontrol_ble": {
            entry.entry_id: client,
            f"{entry.entry_id}_coordinator": coordinator,
        }
    }
    
    added_buttons = []
    def add_buttons(entities):
        added_buttons.extend(entities)
        
    await async_setup_button(hass, entry, add_buttons)
    # Find the start_scanner button
    btn = next(b for b in added_buttons if b.entity_description.key == "start_scanner")
    btn.hass = hass
    
    await btn.async_press()
    
    client.start_scanner.assert_called_once_with(0)
    hass.async_create_task.assert_called_once()
    coordinator.async_request_refresh.assert_called_once()


@pytest.mark.asyncio
async def test_number_set_refreshes_coordinator():
    hass = MagicMock()
    entry = MagicMock(spec=ConfigEntry)
    entry.entry_id = "test_entry_id"
    entry.data = {
        "address": "AA:BB:CC:DD:EE:FF",
        "name": "SoloMini Device",
    }
    
    client = MagicMock(spec=SoloMiniClient)
    client.actions = [0]
    client.action = 0
    client.set_opening_time = AsyncMock(return_value=1)
    
    coordinator = MagicMock()
    
    hass.data = {
        "onecontrol_ble": {
            entry.entry_id: client,
            f"{entry.entry_id}_coordinator": coordinator,
        }
    }
    
    added_numbers = []
    def add_numbers(entities):
        added_numbers.extend(entities)
        
    await async_setup_number(hass, entry, add_numbers)
    num = added_numbers[0]
    num.hass = hass
    num.async_write_ha_state = MagicMock()
    
    await num.async_set_native_value(15.0)
    
    client.set_opening_time.assert_called_once_with(0, 15)
    hass.async_create_task.assert_called_once()
    coordinator.async_request_refresh.assert_called_once()
