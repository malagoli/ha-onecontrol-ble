"""Config flow for 1Control SoloMini BLE."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)

from .protocol import parse_mitm_log

_LOGGER = logging.getLogger(__name__)
DOMAIN = "onecontrol_ble"
SOLOMINI_SERVICE_UUID = "d973f2e0-b19e-11e2-9e96-0800200c9a66"


def _is_hex(s: str, length: int) -> bool:
    s = s.strip().lower().replace(" ", "")
    return len(s) == length and all(c in "0123456789abcdef" for c in s)


class OneControlConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    VERSION = 1

    def __init__(self) -> None:
        self._parsed: dict = {}
        self._discovered_address: str = ""
        self._discovered_name: str = "SoloMini"
        self._discovered_devices: dict[str, str] = {}
        self._paired_ltk: str = ""

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> config_entries.ConfigFlowResult:
        address = discovery_info.address
        await self.async_set_unique_id(address)
        self._abort_if_unique_id_configured()
        self._discovered_address = address
        self._discovered_name = discovery_info.name or "SoloMini"
        self.context["title_placeholders"] = {
            "name": self._discovered_name,
            "address": address,
        }
        return await self.async_step_keys()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        for info in async_discovered_service_info(self.hass, connectable=False):
            if SOLOMINI_SERVICE_UUID in [s.lower() for s in info.service_uuids]:
                self._discovered_devices[info.address] = (
                    f"{info.name or 'SoloMini'} ({info.address})"
                )

        if self._discovered_devices:
            return await self.async_step_pick_device()
        return await self.async_step_keys()

    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            address = user_input["address"]
            if address == "manual":
                return await self.async_step_keys()
            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()
            self._discovered_address = address
            name = self._discovered_devices.get(address, "SoloMini")
            self._discovered_name = name.split(" (")[0]
            return await self.async_step_keys()

        devices = dict(self._discovered_devices)
        devices["manual"] = "Zadat ručně..."

        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema(
                {
                    vol.Required("address"): vol.In(devices),
                }
            ),
        )

    async def async_step_keys(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        if user_input is not None:
            method = user_input.get("method", "mitm")
            if method == "pair":
                return await self.async_step_pair()
            return await self.async_step_mitm()

        return self.async_show_form(
            step_id="keys",
            data_schema=vol.Schema(
                {
                    vol.Required("method", default="mitm"): vol.In(
                        {
                            "mitm": "Mitmproxy log / ruční zadání",
                            "pair": "Párovat zařízení (factory reset)",
                        }
                    ),
                }
            ),
        )

    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input.get("address", self._discovered_address).upper().strip()
            if not address:
                errors["address"] = "address_required"
            else:
                try:
                    from .ble_client import SoloMiniClient
                    from .protocol import SecurityData

                    dummy_sec = SecurityData(
                        ltk=bytes(16),
                        session_key=bytes(16),
                        session_id=bytes(8),
                    )
                    client = SoloMiniClient(address=address, security=dummy_sec)
                    result = await client.pair()  # type: ignore[attr-defined]
                    if result is None:
                        errors["base"] = "pairing_failed"
                    else:
                        self._paired_ltk = result.ltk.hex().upper()
                        self._discovered_address = address
                        self._parsed = {"ltk": self._paired_ltk}
                        return await self.async_step_mitm()
                except Exception as e:
                    _LOGGER.error("Pairing failed: %s", e)
                    errors["base"] = "pairing_failed"

        default_address = self._discovered_address if self._discovered_address != "manual" else ""
        return self.async_show_form(
            step_id="pair",
            data_schema=vol.Schema(
                {
                    vol.Required("address", default=default_address): str,
                }
            ),
            errors=errors,
            description_placeholders={
                "instructions": (
                    "Ujistěte se, že je zařízení ve stavu factory reset "
                    "(nespárované). Poté klikněte na Odeslat."
                )
            },
        )

    async def async_step_mitm(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            mitm_log = user_input.get("mitm_log", "").strip()
            if mitm_log:
                parsed = parse_mitm_log(mitm_log)
                if parsed.get("ltk") and parsed.get("session_key") and parsed.get("session_id"):
                    self._parsed = parsed
                    if self._paired_ltk:
                        self._parsed["ltk"] = self._paired_ltk
                else:
                    errors["mitm_log"] = "parse_failed"
            if not errors:
                return await self.async_step_device()

        return self.async_show_form(
            step_id="mitm",
            data_schema=vol.Schema(
                {
                    vol.Optional("mitm_log", default=""): str,
                }
            ),
            errors=errors,
        )

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input["address"].upper().strip()
            ltk = user_input["ltk"].strip().lower().replace(" ", "")
            sk = user_input["session_key"].strip().lower().replace(" ", "")
            sid = user_input["session_id"].strip().lower().replace(" ", "")
            action = user_input.get("action", "0").strip()

            if not _is_hex(ltk, 32):
                errors["ltk"] = "invalid_hex"
            elif not _is_hex(sk, 32):
                errors["session_key"] = "invalid_hex"
            elif not _is_hex(sid, 16):
                errors["session_id"] = "invalid_hex"
            else:
                try:
                    # Validate comma-separated actions list
                    actions_list = [int(x.strip()) for x in action.split(",") if x.strip()]
                    if not actions_list:
                        raise ValueError
                    for a in actions_list:
                        if a < 0:
                            raise ValueError
                except ValueError:
                    errors["action"] = "invalid_actions"

            if not errors:
                if not self._discovered_address:
                    await self.async_set_unique_id(address)
                    self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input.get("name", self._discovered_name),
                    data={
                        "address": address,
                        "name": user_input.get("name", self._discovered_name),
                        "ltk": ltk,
                        "session_key": sk,
                        "session_id": sid,
                        "user_id": user_input.get("user_id", 0),
                        "action": action,
                        "last_cc": self._parsed.get("last_cc", 0),
                    },
                )

        default_address = self._discovered_address if self._discovered_address != "manual" else ""

        schema = vol.Schema(
            {
                vol.Required("address", default=default_address): str,
                vol.Optional("name", default=self._discovered_name): str,
                vol.Required("ltk", default=self._parsed.get("ltk", "")): str,
                vol.Required("session_key", default=self._parsed.get("session_key", "")): str,
                vol.Required("session_id", default=self._parsed.get("session_id", "")): str,
                vol.Optional("user_id", default=0): int,
                vol.Optional("action", default="0"): str,
            }
        )
        return self.async_show_form(
            step_id="device",
            data_schema=schema,
            errors=errors,
        )
