"""1Control SoloMini — BLE protocol."""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

from Crypto.Cipher import AES

TX_CHAR_UUID = "d973f2e1-b19e-11e2-9e96-0800200c9a66"
RX_CHAR_UUID = "d973f2e2-b19e-11e2-9e96-0800200c9a66"
NACK = bytes([0x00, 0x02, 0x01, 0xCE])
CCM_TAG_LEN = 6


@dataclass
class SecurityData:
    ltk: bytes  # Long Term Key — from pairing
    session_key: bytes  # SHA256(LTK+sessionID)[:16]
    session_id: bytes  # sessionID
    user_id: int = 0
    last_cc: int = 0  # Last known CC — optional
    battery_raw: int | None = None  # Raw value


def derive_session(ltk: bytes, random_a: bytes, random_b: bytes) -> tuple[bytes, bytes]:
    data = random_a[:8] + random_b[:8]
    sid = hashlib.sha256(data).digest()[:8]
    sk = hashlib.sha256(ltk[:16] + sid).digest()[:16]
    return sid, sk


def build_tlv(payload: bytes) -> bytes:
    return bytes([0x00, len(payload)]) + payload


def build_open_command(
    session_key: bytes,
    session_id: bytes,
    last_cc: int,
    user_id: int = 0,
    action: int = 0,
) -> bytes:
    cc = last_cc + 1
    nonce = session_id[:8] + struct.pack("<I", cc)
    aad = struct.pack("<H", user_id) + struct.pack("<I", cc) + b"\x01"
    cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=CCM_TAG_LEN)
    cipher.update(aad)  # type: ignore[union-attr]
    ct, tag = cipher.encrypt_and_digest(bytes([0x01, action & 0xFF]))  # type: ignore[union-attr]
    payload = b"\x01" + ct + tag + struct.pack("<H", user_id) + struct.pack("<I", cc)
    return build_tlv(payload)


def is_nack(packet: bytes) -> bool:
    return packet[:4] == NACK


def extract_response_cc(packet: bytes) -> int | None:
    if len(packet) >= 16:
        return int.from_bytes(packet[12:14], "little")
    return None


def parse_greeting(packet: bytes) -> tuple[bytes, int, int, int] | None:
    if len(packet) < 19 or packet[0] != 0x00 or packet[1] != 0x11:
        return None
    p = packet[2:]
    sid = p[1:9]
    battery_raw = int.from_bytes(p[9:11], "little")
    uid = int.from_bytes(p[11:13], "little")
    cc = int.from_bytes(p[13:15], "little")
    return sid, battery_raw, uid, cc


def parse_mitm_log(log_text: str) -> dict:
    result: dict = {}
    for key, pattern in [
        ("ltk", r'"ltk":"([0-9A-Fa-f]+)"'),
        ("session_key", r'"sessionKey":"([0-9A-Fa-f]+)"'),
        ("session_id", r'"sessionID":"([0-9A-Fa-f]+)"'),
        ("last_cc", r'"lastCC":(\d+)'),
    ]:
        m = re.search(pattern, log_text)
        if m:
            result[key] = m.group(1).upper() if key != "last_cc" else int(m.group(1))
    return result


def build_get_system_info(
    session_key: bytes,
    session_id: bytes,
    last_cc: int,
    user_id: int = 0,
) -> bytes:
    cc = last_cc + 1
    nonce = session_id[:8] + struct.pack("<I", cc)
    aad = struct.pack("<H", user_id) + struct.pack("<I", cc) + b"\x14"
    cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=CCM_TAG_LEN)
    cipher.update(aad)  # type: ignore[union-attr]
    ct, tag = cipher.encrypt_and_digest(b"\xff")  # type: ignore[union-attr]
    payload = b"\x14" + ct + tag + struct.pack("<H", user_id) + struct.pack("<I", cc)
    return build_tlv(payload)


def assemble_fragments(packets: list[bytes]) -> bytes | None:
    parts: dict[int, bytes] = {}
    for pkt in packets:
        if not pkt:
            continue
        if (pkt[0] >> 4) == 4:  # FragmentedPacket
            length = pkt[1]
            index = pkt[3]
            data = pkt[4 : 2 + length]
            parts[index] = data
        else:
            # SimplePacket
            return pkt[2:]
    if not parts:
        return None
    return b"".join(parts[i] for i in sorted(parts.keys()))


def decrypt_system_info(
    session_key: bytes,
    session_id: bytes,
    assembled: bytes,
    user_id: int = 0,
    is_pad: bool = False,
) -> dict | None:
    if len(assembled) < 8:
        return None
    cmd = assembled[0]
    d = assembled
    cc = (d[-4] & 0xFF) | ((d[-3] & 0xFF) << 8) | ((d[-2] & 0xFF) << 16) | ((d[-1] & 0xFF) << 24)
    b_arr = assembled[1:-6]

    nonce = session_id[:8] + struct.pack("<I", cc)
    aad = struct.pack("<H", user_id) + struct.pack("<I", cc) + bytes([cmd])
    ct = b_arr[:-CCM_TAG_LEN]
    tag = b_arr[-CCM_TAG_LEN:]

    try:
        cipher = AES.new(session_key, AES.MODE_CCM, nonce=nonce, mac_len=CCM_TAG_LEN)
        cipher.update(aad)  # type: ignore[union-attr]
        pt = cipher.decrypt_and_verify(ct, tag)  # type: ignore[union-attr]
    except Exception:
        return None

    if len(pt) < 18 or pt[0] != 0:
        return None

    version = pt[15]
    if is_pad and version >= 20 and len(pt) > 20:
        name_bytes = pt[18:-2]
        pin_code = int.from_bytes(pt[-2:], "little")
    else:
        name_bytes = pt[18:]
        pin_code = 0

    result = {
        "serial": int.from_bytes(pt[1:5], "little"),
        "battery_raw": int.from_bytes(pt[5:7], "little"),
        "max_actions": pt[7],
        "cloned_mask": pt[8],
        "max_users": int.from_bytes(pt[9:11], "little"),
        "production": int.from_bytes(pt[11:15], "little"),
        "version": pt[15],
        "dst": bool(pt[16]),
        "sys_options": pt[17],
        "name": name_bytes.rstrip(b"\x00").decode("utf-8", "ignore"),
        "pin_code": pin_code,
    }
    return result

