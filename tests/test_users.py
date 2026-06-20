"""Tests for get_users and user management."""

from __future__ import annotations

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.onecontrol_ble.ble_client import SoloMiniClient
from custom_components.onecontrol_ble.protocol import NACK, SecurityData
from tests.conftest import (
    TEST_LTK,
    TEST_RANDOM_A,
    TEST_RANDOM_B,
    TEST_SESSION_ID,
    TEST_SESSION_KEY,
)


@pytest.fixture(autouse=True)
def mock_urandom():
    with patch("os.urandom", return_value=bytes.fromhex(TEST_RANDOM_A)):
        yield


def make_session_response(random_b: bytes) -> bytes:
    return bytes([0x00, 0x0A, 0x90, 0x00]) + random_b


def make_probe_response(cc: int) -> bytes:
    return bytes([0x00, 0x0E, 0x01] + [0] * 9 + list(struct.pack("<H", cc)) + [0x00, 0x00])


def make_user_payload(uid: int, utype: int, name: str) -> bytes:
    bArr = bytearray(23 + len(name))
    struct.pack_into("<H", bArr, 0, uid)  # uid
    bArr[2] = utype  # type
    struct.pack_into("<H", bArr, 3, 0)  # id_token
    bArr[5] = 0  # options_mask
    bArr[6] = 1 if utype == 0 else 0  # actions_mask
    bArr[7] = 0x7F if utype == 0 else 0  # day_mask
    struct.pack_into("<H", bArr, 8, 0)  # tz_mask
    # time_mask 6B = zeros
    struct.pack_into("<I", bArr, 16, 0)  # start_date
    struct.pack_into("<H", bArr, 20, 0)  # duration_h
    bArr[22 : 22 + len(name)] = name.encode("utf-8")
    return bytes(bArr)


@pytest.fixture
def security() -> SecurityData:
    return SecurityData(
        ltk=bytes.fromhex(TEST_LTK),
        session_key=bytes.fromhex(TEST_SESSION_KEY),
        session_id=bytes.fromhex(TEST_SESSION_ID),
        user_id=0,
        last_cc=0,
    )


def make_client(security: SecurityData) -> SoloMiniClient:
    return SoloMiniClient(
        address="AA:BB:CC:DD:EE:FF",
        security=security,
        action=0,
    )


class FakeUserClient:
    def __init__(self, responses: list[bytes]):
        self._responses = list(responses)
        self._notify_callback = None
        self.written = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def start_notify(self, uuid, callback, **kwargs):
        self._notify_callback = callback

    async def write_gatt_char(self, uuid, data, response=True):
        self.written.append(bytes(data))
        if self._responses and self._notify_callback:
            resp = self._responses.pop(0)
            self._notify_callback(None, bytearray(resp))


def make_encrypted_user_response(
    security: SecurityData,
    last_cc: int,
    rc: int,
    payload: bytes,
) -> bytes:
    import struct as s

    from Crypto.Cipher import AES

    cc = last_cc + 1
    pt = bytes([rc]) + payload
    nonce = security.session_id[:8] + s.pack("<I", cc)
    aad = s.pack("<H", security.user_id) + s.pack("<I", cc) + b"\x07"
    cipher = AES.new(security.session_key, AES.MODE_CCM, nonce=nonce, mac_len=6)
    cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(pt)
    assembled = b"\x07" + ct + tag + bytes([0, 0]) + s.pack("<I", cc)
    return bytes([0x00, len(assembled)]) + assembled


class TestGetUsers:
    @pytest.mark.asyncio
    async def test_get_users_returns_list(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        user0_payload = make_user_payload(0, 1, "+420123456789")
        user1_payload = make_user_payload(1, 0, "+420987654321")

        responses = [
            make_session_response(random_b),
            make_probe_response(cc=10),
            make_encrypted_user_response(security, 10, 0, user0_payload),
            make_encrypted_user_response(security, 11, 0, user1_payload),
            make_encrypted_user_response(security, 12, 2, b""),
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert len(result) == 2
        assert result[0]["uid"] == 0
        assert result[0]["name"] == "+420123456789"
        assert result[0]["type"] == 1
        assert result[1]["uid"] == 1
        assert result[1]["name"] == "+420987654321"
        assert result[1]["type"] == 0

    @pytest.mark.asyncio
    async def test_get_users_empty(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        responses = [
            make_session_response(random_b),
            make_probe_response(cc=10),
            make_encrypted_user_response(security, 10, 2, b""),
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_users_nack_returns_empty(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        responses = [
            make_session_response(random_b),
            NACK,
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_users_connection_error_returns_empty(self, security):
        async def fail(*args, **kwargs):
            raise OSError("BLE error")

        fake_ctx = MagicMock()
        fake_ctx.__aenter__ = fail
        fake_ctx.__aexit__ = AsyncMock(return_value=False)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ctx,
        ):
            result = await client.get_users()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_users_admin_type(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        user_payload = make_user_payload(0, 1, "admin")
        responses = [
            make_session_response(random_b),
            make_probe_response(cc=10),
            make_encrypted_user_response(security, 10, 0, user_payload),
            make_encrypted_user_response(security, 11, 2, b""),
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert len(result) == 1
        assert result[0]["type"] == 1

    @pytest.mark.asyncio
    async def test_get_users_standard_user_has_restrictions(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        user_payload = make_user_payload(1, 0, "guest")
        responses = [
            make_session_response(random_b),
            make_probe_response(cc=10),
            make_encrypted_user_response(security, 10, 0, user_payload),
            make_encrypted_user_response(security, 11, 2, b""),
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert len(result) == 1
        assert result[0]["type"] == 0
        assert result[0]["actions_mask"] == 1
        assert result[0]["day_mask"] == 0x7F

    @pytest.mark.asyncio
    async def test_get_users_short_response_does_not_crash(self, security):
        random_b = bytes.fromhex(TEST_RANDOM_B)
        responses = [
            make_session_response(random_b),
            make_probe_response(cc=10),
            bytes([0x00, 0x02]),  # too short!
        ]
        fake_ble = FakeUserClient(responses)
        client = make_client(security)

        with patch(
            "custom_components.onecontrol_ble.ble_client.BleakClient",
            return_value=fake_ble,
        ):
            result = await client.get_users()

        assert result == []
