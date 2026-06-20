"""1Control SoloMini RE — BLE client."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
)

from .protocol import (
    RX_CHAR_UUID,
    TX_CHAR_UUID,
    SecurityData,
    build_open_command,
    derive_session,
    extract_response_cc,
    is_nack,
    parse_greeting,
)

_LOGGER = logging.getLogger(__name__)
CONNECT_TIMEOUT = 20.0
RESPONSE_TIMEOUT = 8.0


class SoloMiniClient:
    def __init__(
        self,
        address: str,
        security: SecurityData,
        actions: list[int] | None = None,
        action: int | None = None,
        ble_device: BLEDevice | None = None,
    ):
        self.address = address
        self.security = security
        if actions is not None:
            self.actions = actions
        elif action is not None:
            self.actions = [action]
        else:
            self.actions = [0]
        self.action = self.actions[0] if self.actions else 0
        self.ble_device = ble_device
        self._lock = asyncio.Lock()

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        self.ble_device = ble_device

    async def _get_client(self) -> BleakClient:
        if self.ble_device is not None:
            return await establish_connection(
                BleakClientWithServiceCache,
                self.ble_device,
                self.address,
                max_attempts=3,
            )
        return BleakClient(self.address, timeout=CONNECT_TIMEOUT)

    async def open_gate(self, action: int | None = None) -> bool:
        if self._lock.locked():
            _LOGGER.warning("Already in progress")
            return False
        async with self._lock:
            for attempt in range(3):
                try:
                    return await self._do_open(action)
                except Exception as e:
                    _LOGGER.warning("Attempt %d failed: %s", attempt + 1, e)
                    if attempt < 2:
                        await asyncio.sleep(3)
            return False

    async def _do_open(self, action: int | None = None) -> bool:
        target_action = action if action is not None else self.action
        random_a = os.urandom(8)
        q: asyncio.Queue[bytes] = asyncio.Queue()

        client = await self._get_client()
        async with client:
            _LOGGER.debug("Connected to %s", self.address)
            try:
                if hasattr(client, "_backend"):
                    client._backend._mtu_size = 247  # type: ignore[attr-defined]
                    _LOGGER.debug("MTU set to 247")
            except Exception:
                pass
            await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
            await asyncio.sleep(0.3)
            while not q.empty():
                q.get_nowait()

            await client.write_gatt_char(
                TX_CHAR_UUID,
                bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                response=True,
            )
            resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
            _LOGGER.debug("Session: %s", resp.hex())
            our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

            session_key = self.security.session_key
            session_id = self.security.session_id
            if not session_key or session_key == bytes(16):
                session_key = our_sk
                session_id = our_sid

            current_cc = self.security.last_cc
            _LOGGER.debug("Trying with last_cc=%d", current_cc)

            pkt = build_open_command(
                session_key,
                session_id,
                current_cc,
                self.security.user_id,
                target_action,
            )
            await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

            try:
                r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                _LOGGER.debug("RX: %s", r.hex())

                if is_nack(r):
                    _LOGGER.debug("NACK on last_cc=%d, probing...", current_cc)
                    probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
                    await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
                    r2 = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                    resp_cc = extract_response_cc(r2)
                    if resp_cc is None:
                        return False
                    _LOGGER.debug("Probe CC=%d", resp_cc)
                    pkt2 = build_open_command(
                        session_key,
                        session_id,
                        resp_cc,
                        self.security.user_id,
                        target_action,
                    )
                    await client.write_gatt_char(TX_CHAR_UUID, pkt2, response=True)
                    new_cc = await self._collect_response(q, resp_cc)

                elif len(r) == 16:
                    resp_cc = extract_response_cc(r)
                    if resp_cc is not None and resp_cc != current_cc + 1:
                        _LOGGER.debug("CC mismatch, retrying with CC=%d", resp_cc)
                        pkt3 = build_open_command(
                            self.security.session_key,
                            self.security.session_id,
                            resp_cc,
                            self.security.user_id,
                            target_action,
                        )
                        await client.write_gatt_char(TX_CHAR_UUID, pkt3, response=True)
                        new_cc = await self._collect_response(q, resp_cc)
                    else:
                        new_cc = await self._collect_response(q, current_cc, first=r)
                else:
                    new_cc = current_cc + 1

            except TimeoutError:
                new_cc = current_cc + 1

            self.security.last_cc = new_cc
            _LOGGER.info(
                "Gate opened! last_cc=%d battery_raw=%s",
                new_cc,
                self.security.battery_raw,
            )
            return True

    async def _collect_response(
        self,
        q: asyncio.Queue[bytes],
        last_cc: int,
        first: bytes | None = None,
    ) -> int:
        new_cc = last_cc + 1
        packets: list[bytes] = [first] if first is not None else []

        for _ in range(3):
            try:
                pkt = await asyncio.wait_for(q.get(), timeout=2.0)
                packets.append(pkt)
            except TimeoutError:
                break

        for pkt in packets:
            _LOGGER.debug("collect RX: %s", pkt.hex())
            if is_nack(pkt):
                _LOGGER.warning("NACK in collect_response")
                return new_cc
            if len(pkt) == 19 and pkt[1] == 0x11:
                parsed = parse_greeting(pkt)
                if parsed:
                    _, battery_raw, _, greeting_cc = parsed
                    self.security.battery_raw = battery_raw
                    new_cc = greeting_cc
                    _LOGGER.debug(
                        "Greeting: battery_raw=%d, CC=%d",
                        battery_raw,
                        greeting_cc,
                    )
            elif len(pkt) == 16:
                cc_from_resp = extract_response_cc(pkt)
                if cc_from_resp:
                    new_cc = cc_from_resp

        return new_cc

    async def get_system_info(self) -> dict[str, Any]:
        for attempt in range(3):
            if self._lock.locked():
                _LOGGER.debug("Lock busy, waiting... attempt %d", attempt + 1)
                await asyncio.sleep(5)
                continue
            async with self._lock:
                try:
                    return await self._do_get_system_info()
                except Exception as e:
                    _LOGGER.warning("get_system_info failed: %s", e)
                    if attempt < 2:
                        await asyncio.sleep(10)
        return {}

    async def _do_get_system_info(self) -> dict[str, Any]:
        from .protocol import (
            assemble_fragments,
            build_get_system_info,
            decrypt_system_info,
        )

        random_a = os.urandom(8)
        q: asyncio.Queue[bytes] = asyncio.Queue()

        client = await self._get_client()
        async with client:
            try:
                if hasattr(client, "_backend"):
                    client._backend._mtu_size = 247  # type: ignore[attr-defined]
                    _LOGGER.debug("MTU set to 247")
            except Exception:
                pass
            await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
            await asyncio.sleep(0.3)
            while not q.empty():
                q.get_nowait()

            # StartSession
            await client.write_gatt_char(
                TX_CHAR_UUID,
                bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                response=True,
            )
            resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
            our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

            # Probe
            probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
            await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
            r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
            if is_nack(r):
                return {}
            resp_cc = extract_response_cc(r)
            if resp_cc is None:
                return {}

            # GetSystemInfo
            pkt = build_get_system_info(
                our_sk,
                our_sid,
                resp_cc,
                self.security.user_id,
            )
            await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

            frags: list[bytes] = []
            for _ in range(5):
                try:
                    rx = await asyncio.wait_for(q.get(), timeout=2.0)
                    frags.append(rx)
                    if (rx[0] >> 4) == 4:
                        total = rx[2]
                        if len(frags) >= total:
                            break
                    else:
                        break
                except TimeoutError:
                    break

            assembled = assemble_fragments(frags)
            if not assembled:
                return {}

            info = decrypt_system_info(
                our_sk,
                our_sid,
                assembled,
            )
            if info:
                self.security.battery_raw = info["battery_raw"]
                _LOGGER.debug("SystemInfo: %s", info)
                return info
            return {}

    async def clone_remote(self, action: int = 0) -> int | None:
        return await self._do_transmit(bytes([0x02, action & 0xFF]))

    async def set_opening_time(self, action: int = 0, time_s: int = 0) -> int | None:
        return await self._do_transmit(
            bytes([0x07, action & 0xFF, time_s & 0xFF, (time_s >> 8) & 0xFF])
        )

    async def _do_transmit(self, plaintext: bytes, timeout: float = 15.0) -> int | None:
        try:
            random_a = os.urandom(8)
            q: asyncio.Queue[bytes] = asyncio.Queue()

            client = await self._get_client()
            async with client:
                try:
                    if hasattr(client, "_backend"):
                        client._backend._mtu_size = 247  # type: ignore[attr-defined]
                        _LOGGER.debug("MTU set to 247")
                except Exception:
                    pass
                await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
                await asyncio.sleep(0.3)
                while not q.empty():
                    q.get_nowait()

                # StartSession
                await client.write_gatt_char(
                    TX_CHAR_UUID,
                    bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                    response=True,
                )
                resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

                # Probe
                probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
                await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
                r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                if is_nack(r):
                    return None
                resp_cc = extract_response_cc(r)
                if resp_cc is None:
                    return None

                import struct as _struct

                from .protocol import CCM_TAG_LEN, build_tlv

                cc = resp_cc + 1
                nonce = our_sid[:8] + _struct.pack("<I", cc)
                aad = _struct.pack("<H", self.security.user_id) + _struct.pack("<I", cc) + b"\x01"
                from Crypto.Cipher import AES as _AES

                cipher = _AES.new(
                    our_sk,
                    _AES.MODE_CCM,
                    nonce=nonce,
                    mac_len=CCM_TAG_LEN,
                )
                cipher.update(aad)
                ct, tag = cipher.encrypt_and_digest(plaintext)
                payload = (
                    b"\x01"
                    + ct
                    + tag
                    + _struct.pack("<H", self.security.user_id)
                    + _struct.pack("<I", cc)
                )
                pkt = build_tlv(payload)

                await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

                ack = await asyncio.wait_for(q.get(), timeout=timeout)
                _LOGGER.debug("_do_transmit RX: %s", ack.hex())

                if is_nack(ack):
                    return None

                if len(ack) >= 8:
                    return ack[3] & 0xFF
                return 0

        except Exception as e:
            _LOGGER.error("_do_transmit failed: %s", e)
            return None

    async def pair(self) -> SecurityData | None:
        import hashlib

        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH,
            SECP256R1,
            EllipticCurvePublicNumbers,
            generate_private_key,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        try:
            private_key = generate_private_key(SECP256R1())
            public_key = private_key.public_key()
            pub_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]

            q: asyncio.Queue[bytes] = asyncio.Queue()
            client = await self._get_client()
            async with client:
                try:
                    if hasattr(client, "_backend"):
                        client._backend._mtu_size = 247  # type: ignore[attr-defined]
                        _LOGGER.debug("MTU set to 247")
                except Exception:
                    pass
                await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
                await asyncio.sleep(0.2)

                pkt = bytes([0x00, 0x42, 0x90, 0x01]) + pub_bytes
                _LOGGER.debug("TX StartPairing (%dB): %s", len(pkt), pkt.hex())
                await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

                resp = await asyncio.wait_for(q.get(), timeout=10.0)
                _LOGGER.debug("RX StartPairing (%dB): %s", len(resp), resp.hex())

                if len(resp) < 66 or resp[2] != 0x90:
                    _LOGGER.error("Unexpected pairing response: %s", resp.hex())
                    return None

                device_pub_bytes = resp[4:68]
                x = int.from_bytes(device_pub_bytes[:32], "big")
                y = int.from_bytes(device_pub_bytes[32:], "big")
                device_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()

                shared = private_key.exchange(ECDH(), device_pub)
                ltk = hashlib.sha256(shared).digest()[:16]
                _LOGGER.info("Pairing complete, LTK=%s", ltk.hex())

                return SecurityData(
                    ltk=ltk,
                    session_key=bytes(16),
                    session_id=bytes(8),
                    user_id=0,
                )
        except Exception as e:
            _LOGGER.error("Pairing failed: %s", e)
            return None

    async def start_scanner(self, action: int = 0) -> bool:
        result = await self._do_transmit(bytes([0x0C, action & 0xFF]), timeout=30.0)
        return result is not None

    async def confirm_scanner(self, action: int = 0) -> bool:
        result = await self._do_transmit(bytes([0x0D, action & 0xFF]))
        return result is not None

    async def complete_scanner(self, action: int = 0) -> bool:
        result = await self._do_transmit(bytes([0x0E, action & 0xFF]))
        return result is not None

    async def undo_scanner(self, action: int = 0) -> bool:
        result = await self._do_transmit(bytes([0x0F, action & 0xFF]))
        return result is not None

    async def set_device_name(self, name: str) -> bool:
        name_bytes = name.encode("utf-8")[:4]
        plaintext = bytes([0x02]) + name_bytes
        result = await self._do_settings(plaintext)
        return result is not None

    async def set_dst(self, enabled: bool) -> bool:
        plaintext = bytes([0x03, 0x01 if enabled else 0x00])
        result = await self._do_settings(plaintext)
        return result is not None

    async def _do_settings(self, plaintext: bytes) -> int | None:
        import struct as _struct

        try:
            random_a = os.urandom(8)
            q: asyncio.Queue[bytes] = asyncio.Queue()

            client = await self._get_client()
            async with client:
                try:
                    if hasattr(client, "_backend"):
                        client._backend._mtu_size = 247  # type: ignore[attr-defined]
                        _LOGGER.debug("MTU set to 247")
                except Exception:
                    pass
                await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
                await asyncio.sleep(0.3)
                while not q.empty():
                    q.get_nowait()

                # StartSession
                await client.write_gatt_char(
                    TX_CHAR_UUID,
                    bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                    response=True,
                )
                resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

                # Probe
                probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
                await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
                r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                if is_nack(r):
                    return None
                resp_cc = extract_response_cc(r)
                if resp_cc is None:
                    return None

                from Crypto.Cipher import AES as _AES

                from .protocol import CCM_TAG_LEN, build_tlv

                cc = resp_cc + 1
                nonce = our_sid[:8] + _struct.pack("<I", cc)
                aad = _struct.pack("<H", self.security.user_id) + _struct.pack("<I", cc) + b"\x10"
                cipher = _AES.new(
                    our_sk,
                    _AES.MODE_CCM,
                    nonce=nonce,
                    mac_len=CCM_TAG_LEN,
                )
                cipher.update(aad)
                ct, tag = cipher.encrypt_and_digest(plaintext)
                payload = (
                    b"\x10"
                    + ct
                    + tag
                    + _struct.pack("<H", self.security.user_id)
                    + _struct.pack("<I", cc)
                )
                pkt = build_tlv(payload)
                await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

                ack = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                _LOGGER.debug("_do_settings RX: %s", ack.hex())
                if is_nack(ack):
                    return None
                if len(ack) >= 4:
                    return ack[3] & 0xFF
                return 0

        except Exception as e:
            _LOGGER.error("_do_settings failed: %s", e)
            return None

    async def get_users_count(self) -> int | None:
        result = await self._do_user_cmd(bytes([0x02]))
        if result and len(result) >= 2:
            return int.from_bytes(result[:2], "little")
        return None

    async def get_user(self, uid: int) -> dict | None:
        result = await self._do_user_cmd(bytes([0x01, uid & 0xFF, (uid >> 8) & 0xFF]))
        if result:
            return self._parse_user(result)
        return None

    async def list_users(self, offset: int = 0) -> list[dict]:
        result = await self._do_user_cmd(bytes([0x03, offset & 0xFF, (offset >> 8) & 0xFF]))
        if not result:
            return []

        users = []
        pos = 0
        while pos < len(result):
            uid = int.from_bytes(result[pos : pos + 2], "little")
            if uid == 0xFFFF:
                break
            users.append({"uid": uid})
            pos += 2
        return users

    def _parse_user(self, bArr: bytes) -> dict:
        if len(bArr) < 22:
            return {}
        return {
            "uid": int.from_bytes(bArr[0:2], "little"),
            "type": bArr[2],
            "id_token": int.from_bytes(bArr[3:5], "little"),
            "options_mask": bArr[5],
            "actions_mask": bArr[6],
            "day_mask": bArr[7],
            "start_date": int.from_bytes(bArr[16:20], "little"),
            "duration_hours": int.from_bytes(bArr[20:22], "little"),
            "name": bArr[22:-1].decode("utf-8", "ignore") if len(bArr) > 23 else "",
        }

    async def _do_user_cmd(self, plaintext: bytes) -> bytes | None:
        import struct as _struct

        try:
            random_a = os.urandom(8)
            q: asyncio.Queue[bytes] = asyncio.Queue()

            client = await self._get_client()
            async with client:
                try:
                    if hasattr(client, "_backend"):
                        client._backend._mtu_size = 247  # type: ignore[attr-defined]
                        _LOGGER.debug("MTU set to 247")
                except Exception:
                    pass
                await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
                await asyncio.sleep(0.3)
                while not q.empty():
                    q.get_nowait()

                # StartSession
                await client.write_gatt_char(
                    TX_CHAR_UUID,
                    bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                    response=True,
                )
                resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

                # Probe
                probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
                await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
                r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
                if is_nack(r):
                    return None
                resp_cc = extract_response_cc(r)
                if resp_cc is None:
                    return None

                # User cmd (cmd=0x07)
                from Crypto.Cipher import AES as _AES

                from .protocol import CCM_TAG_LEN, build_tlv

                cc = resp_cc + 1
                nonce = our_sid[:8] + _struct.pack("<I", cc)
                aad = _struct.pack("<H", self.security.user_id) + _struct.pack("<I", cc) + b"\x07"
                cipher = _AES.new(
                    our_sk,
                    _AES.MODE_CCM,
                    nonce=nonce,
                    mac_len=CCM_TAG_LEN,
                )
                cipher.update(aad)
                ct, tag = cipher.encrypt_and_digest(plaintext)
                payload = (
                    b"\x07"
                    + ct
                    + tag
                    + _struct.pack("<H", self.security.user_id)
                    + _struct.pack("<I", cc)
                )
                pkt = build_tlv(payload)
                await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)

                frags: list[bytes] = []
                for _ in range(5):
                    try:
                        rx = await asyncio.wait_for(q.get(), timeout=2.0)
                        frags.append(rx)
                        if (rx[0] >> 4) == 4:
                            total = rx[2]
                            if len(frags) >= total:
                                break
                        else:
                            break
                    except TimeoutError:
                        break

                from .protocol import assemble_fragments as af

                assembled = af(frags)
                if not assembled:
                    return None

                d = assembled
                cc_r = (
                    (d[-4] & 0xFF)
                    | ((d[-3] & 0xFF) << 8)
                    | ((d[-2] & 0xFF) << 16)
                    | ((d[-1] & 0xFF) << 24)
                )
                b_arr = assembled[1:-6]
                cmd = assembled[0]
                nonce2 = our_sid[:8] + _struct.pack("<I", cc_r)
                aad2 = _struct.pack("<H", 0) + _struct.pack("<I", cc_r) + bytes([cmd])
                try:
                    c2 = _AES.new(
                        our_sk,
                        _AES.MODE_CCM,
                        nonce=nonce2,
                        mac_len=CCM_TAG_LEN,
                    )
                    c2.update(aad2)
                    pt = c2.decrypt_and_verify(b_arr[:-CCM_TAG_LEN], b_arr[-CCM_TAG_LEN:])
                    if pt[0] != 0:  # response code
                        return None
                    return pt[1:]
                except Exception:
                    return None

        except Exception as e:
            _LOGGER.error("_do_user_cmd failed: %s", e)
            return None

    async def get_users(self) -> list[dict]:
        try:
            return await self._do_get_users()
        except Exception as e:
            _LOGGER.error("get_users failed: %s", e)
            return []

    async def _do_get_users(self) -> list[dict]:
        import struct as _struct

        from Crypto.Cipher import AES as _AES

        from .protocol import CCM_TAG_LEN, assemble_fragments, build_tlv

        def build_user_cmd(last_cc: int, plaintext: bytes) -> bytes:
            cc = last_cc + 1
            nonce = our_sid[:8] + _struct.pack("<I", cc)
            aad = _struct.pack("<H", self.security.user_id) + _struct.pack("<I", cc) + b"\x07"
            cipher = _AES.new(
                our_sk,
                _AES.MODE_CCM,
                nonce=nonce,
                mac_len=CCM_TAG_LEN,
            )
            cipher.update(aad)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            payload = (
                b"\x07"
                + ct
                + tag
                + _struct.pack("<H", self.security.user_id)
                + _struct.pack("<I", cc)
            )
            return build_tlv(payload)

        def decrypt_user_response(assembled: bytes) -> tuple[int, bytes, int]:
            d = assembled
            cc = (
                (d[-4] & 0xFF)
                | ((d[-3] & 0xFF) << 8)
                | ((d[-2] & 0xFF) << 16)
                | ((d[-1] & 0xFF) << 24)
            )
            b_arr = assembled[1:-6]
            cmd = assembled[0]
            nonce = our_sid[:8] + _struct.pack("<I", cc)
            aad = _struct.pack("<H", 0) + _struct.pack("<I", cc) + bytes([cmd])
            cipher = _AES.new(
                our_sk,
                _AES.MODE_CCM,
                nonce=nonce,
                mac_len=CCM_TAG_LEN,
            )
            cipher.update(aad)
            pt = cipher.decrypt_and_verify(b_arr[:-CCM_TAG_LEN], b_arr[-CCM_TAG_LEN:])
            return pt[0], pt[1:], cc

        def parse_user(bArr: bytes) -> dict:
            if len(bArr) < 22:
                return {}
            import datetime

            start = int.from_bytes(bArr[16:20], "little")
            return {
                "uid": int.from_bytes(bArr[0:2], "little"),
                "type": bArr[2],
                "options_mask": bArr[5],
                "actions_mask": bArr[6],
                "day_mask": bArr[7],
                "start_date": datetime.datetime.fromtimestamp(start, tz=datetime.UTC).strftime(
                    "%Y-%m-%d"
                )
                if start
                else None,
                "duration_h": int.from_bytes(bArr[20:22], "little"),
                "name": bArr[22:].rstrip(b"\x00").decode("utf-8", "ignore"),
            }

        random_a = os.urandom(8)
        q: asyncio.Queue[bytes] = asyncio.Queue()

        client = await self._get_client()
        async with client:
            try:
                if hasattr(client, "_backend"):
                    client._backend._mtu_size = 247  # type: ignore[attr-defined]
                    _LOGGER.debug("MTU set to 247")
            except Exception:
                pass
            await client.start_notify(RX_CHAR_UUID, lambda _, d: q.put_nowait(bytes(d)))
            await asyncio.sleep(0.3)
            while not q.empty():
                q.get_nowait()

            # StartSession
            await client.write_gatt_char(
                TX_CHAR_UUID,
                bytes([0x00, 0x0A, 0x90, 0x02]) + random_a,
                response=True,
            )
            resp = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
            our_sid, our_sk = derive_session(self.security.ltk, random_a, resp[4:12])

            # Probe
            probe = build_open_command(our_sk, our_sid, 0, self.security.user_id)
            await client.write_gatt_char(TX_CHAR_UUID, probe, response=True)
            r = await asyncio.wait_for(q.get(), timeout=RESPONSE_TIMEOUT)
            if is_nack(r):
                return []
            resp_cc = extract_response_cc(r)
            if resp_cc is None:
                return []

            async def send_and_recv(last_cc: int, plaintext: bytes) -> tuple[int, bytes, int]:
                pkt = build_user_cmd(last_cc, plaintext)
                await client.write_gatt_char(TX_CHAR_UUID, pkt, response=True)
                frags: list[bytes] = []
                for _ in range(5):
                    try:
                        rx = await asyncio.wait_for(q.get(), timeout=2.0)
                        frags.append(rx)
                        if (rx[0] >> 4) == 4:
                            if len(frags) >= rx[2]:
                                break
                        else:
                            break
                    except TimeoutError:
                        break
                assembled = assemble_fragments(frags)
                if not assembled:
                    return -1, b"", last_cc + 1
                return decrypt_user_response(assembled)

            users: list[dict] = []
            offset = 0
            while True:
                rc, payload, resp_cc = await send_and_recv(
                    resp_cc, bytes([0x03, offset & 0xFF, (offset >> 8) & 0xFF])
                )
                if rc != 0 or not payload:
                    break
                user = parse_user(payload)
                if user:
                    users.append(user)
                offset += 1

            _LOGGER.debug("Loaded %d users", len(users))
            return users

    async def add_user(self) -> dict | None:
        result = await self._do_user_cmd(bytes([0x0C]))
        if result and len(result) >= 18:
            uid = int.from_bytes(result[0:2], "little")
            ltk = result[2:18].hex().upper()
            _LOGGER.info("User added: uid=%d, ltk=%s", uid, ltk)
            return {"uid": uid, "ltk": ltk}
        return None

    async def delete_user(self, uid: int) -> bool:
        result = await self._do_user_cmd(bytes([0x06, uid & 0xFF, (uid >> 8) & 0xFF]))
        return result is not None

    async def set_user_name(self, uid: int, name: str) -> bool:
        name_bytes = name.encode("utf-8")[:4]
        plaintext = bytes([0x04, uid & 0xFF, (uid >> 8) & 0xFF]) + name_bytes
        result = await self._do_user_cmd(plaintext)
        return result is not None
