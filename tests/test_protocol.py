"""BLE protocol tests (protocol.py)"""

from __future__ import annotations

import hashlib
import struct

from custom_components.onecontrol_ble.protocol import (
    NACK,
    assemble_fragments,
    build_get_system_info,
    build_open_command,
    decrypt_system_info,
    derive_session,
    extract_response_cc,
    is_nack,
    parse_greeting,
)
from tests.conftest import (
    TEST_LTK,
    TEST_RANDOM_A,
    TEST_RANDOM_B,
    TEST_SESSION_ID,
    TEST_SESSION_KEY,
)

TEST_GREETING = bytes.fromhex("0011014940cabe843d90f4330a00002a000000")
TEST_ASSEMBLED = bytes.fromhex(
    "14f481f9a38e9161bf69c43c44a5821a3ec71f8a3d59ed5f25ea03dcd152000002000000"
)


class TestDeriveSession:
    def test_deterministic(self):
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb = bytes.fromhex(TEST_RANDOM_B)
        sid1, sk1 = derive_session(ltk, ra, rb)
        sid2, sk2 = derive_session(ltk, ra, rb)
        assert sid1 == sid2
        assert sk1 == sk2

    def test_known_values(self):
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb = bytes.fromhex(TEST_RANDOM_B)
        sid, sk = derive_session(ltk, ra, rb)
        assert sid.hex().upper() == TEST_SESSION_ID
        assert sk.hex().upper() == TEST_SESSION_KEY

    def test_session_id_is_8_bytes(self):
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb = bytes.fromhex(TEST_RANDOM_B)
        sid, _ = derive_session(ltk, ra, rb)
        assert len(sid) == 8

    def test_session_key_is_16_bytes(self):
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb = bytes.fromhex(TEST_RANDOM_B)
        _, sk = derive_session(ltk, ra, rb)
        assert len(sk) == 16

    def test_different_random_different_session(self):
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb1 = bytes.fromhex(TEST_RANDOM_B)
        rb2 = bytes(reversed(bytes.fromhex(TEST_RANDOM_B)))
        sid1, sk1 = derive_session(ltk, ra, rb1)
        sid2, sk2 = derive_session(ltk, ra, rb2)
        assert sid1 != sid2
        assert sk1 != sk2

    def test_sk_derived_from_ltk_and_sid(self):
        """SK = SHA256(LTK || SID)[:16]."""
        ltk = bytes.fromhex(TEST_LTK)
        ra = bytes.fromhex(TEST_RANDOM_A)
        rb = bytes.fromhex(TEST_RANDOM_B)
        sid, sk = derive_session(ltk, ra, rb)
        expected_sk = hashlib.sha256(ltk + sid).digest()[:16]
        assert sk == expected_sk


class TestBuildOpenCommand:
    def test_length(self, security):
        pkt = build_open_command(security.session_key, security.session_id, 0, security.user_id)
        assert len(pkt) == 17  # 2B TLV header + 15B payload

    def test_tlv_header(self, security):
        pkt = build_open_command(security.session_key, security.session_id, 0, security.user_id)
        assert pkt[0] == 0x00
        assert pkt[1] == 0x0F  # payload length = 15

    def test_cmd_byte(self, security):
        pkt = build_open_command(security.session_key, security.session_id, 0, security.user_id)
        assert pkt[2] == 0x01

    def test_cc_in_packet(self, security):
        for last_cc in [0, 1, 42, 100, 500]:
            pkt = build_open_command(
                security.session_key, security.session_id, last_cc, security.user_id
            )
            cc_in_pkt = int.from_bytes(pkt[13:17], "little")
            assert cc_in_pkt == last_cc + 1

    def test_user_id_in_packet(self, security):
        for uid in [0, 1, 255]:
            pkt = build_open_command(security.session_key, security.session_id, 0, uid)
            uid_in_pkt = int.from_bytes(pkt[11:13], "little")
            assert uid_in_pkt == uid

    def test_different_cc_different_packet(self, security):
        pkt1 = build_open_command(security.session_key, security.session_id, 0)
        pkt2 = build_open_command(security.session_key, security.session_id, 1)
        assert pkt1 != pkt2

    def test_different_action_different_packet(self, security):
        pkt1 = build_open_command(security.session_key, security.session_id, 0, action=0)
        pkt2 = build_open_command(security.session_key, security.session_id, 0, action=1)
        assert pkt1 != pkt2

    def test_action_byte_clipped_to_byte(self, security):
        pkt1 = build_open_command(security.session_key, security.session_id, 0, action=0)
        pkt2 = build_open_command(security.session_key, security.session_id, 0, action=256)
        assert pkt1 == pkt2


class TestIsNack:
    def test_nack_detected(self):
        assert is_nack(NACK) is True

    def test_nack_detected_with_trailing(self):
        assert is_nack(NACK + bytes(4)) is True

    def test_not_nack(self):
        assert is_nack(bytes([0x00, 0x0E, 0x01, 0x00])) is False

    def test_empty(self):
        assert is_nack(b"") is False

    def test_too_short(self):
        assert is_nack(bytes([0x00, 0x02])) is False


class TestExtractResponseCc:
    def test_extracts_cc(self):
        pkt = bytes([0x00, 0x0E, 0x01] + [0] * 9 + [0x35, 0x02, 0x00, 0x00])
        assert extract_response_cc(pkt) == 0x0235

    def test_cc_zero(self):
        pkt = bytes(16)
        assert extract_response_cc(pkt) == 0

    def test_too_short(self):
        assert extract_response_cc(bytes(4)) is None

    def test_exactly_16_bytes(self):
        pkt = bytes([0] * 12 + [0x01, 0x00, 0x00, 0x00])
        assert extract_response_cc(pkt) == 1


class TestParseGreeting:
    def test_valid_greeting(self):
        result = parse_greeting(TEST_GREETING)
        assert result is not None
        sid, battery_raw, uid, cc = result
        assert sid == bytes.fromhex(TEST_SESSION_ID)
        assert battery_raw == 2611
        assert uid == 0
        assert cc == 42

    def test_wrong_type_byte(self):
        bad = bytes([0x00, 0x12]) + TEST_GREETING[2:]
        assert parse_greeting(bad) is None

    def test_wrong_first_byte(self):
        bad = bytes([0x01]) + TEST_GREETING[1:]
        assert parse_greeting(bad) is None

    def test_too_short(self):
        assert parse_greeting(bytes(10)) is None

    def test_empty(self):
        assert parse_greeting(b"") is None

    def test_different_battery(self):
        sid = bytes.fromhex(TEST_SESSION_ID)
        greeting = (
            bytes([0x00, 0x11, 0x01])
            + sid
            + struct.pack("<H", 3200)
            + struct.pack("<H", 0)
            + struct.pack("<H", 100)
            + bytes([0x00, 0x00])
        )
        result = parse_greeting(greeting)
        assert result is not None
        _, battery_raw, _, cc = result
        assert battery_raw == 3200
        assert cc == 100


class TestBuildGetSystemInfo:
    def test_length(self):
        pkt = build_get_system_info(
            bytes.fromhex(TEST_SESSION_KEY),
            bytes.fromhex(TEST_SESSION_ID),
            0,
        )
        assert len(pkt) == 16

    def test_tlv_header(self):
        pkt = build_get_system_info(
            bytes.fromhex(TEST_SESSION_KEY),
            bytes.fromhex(TEST_SESSION_ID),
            0,
        )
        assert pkt[0] == 0x00
        assert pkt[2] == 0x14  # cmd byte

    def test_different_cc_different_packet(self):
        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        pkt1 = build_get_system_info(sk, sid, 0)
        pkt2 = build_get_system_info(sk, sid, 1)
        assert pkt1 != pkt2

    def test_cc_in_packet(self):
        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        pkt = build_get_system_info(sk, sid, 41)
        cc_in_pkt = int.from_bytes(pkt[12:16], "little")
        assert cc_in_pkt == 42  # last_cc + 1


class TestAssembleFragments:
    def test_single_simple_packet(self):
        pkt = bytes([0x00, 0x05]) + b"hello"
        result = assemble_fragments([pkt])
        assert result == b"hello"

    def test_fragmented_three_parts(self):
        frag0 = bytes([0x40, 0x06, 0x03, 0x00]) + b"ab"
        frag1 = bytes([0x40, 0x06, 0x03, 0x01]) + b"cd"
        frag2 = bytes([0x40, 0x06, 0x03, 0x02]) + b"ef"
        result = assemble_fragments([frag0, frag1, frag2])
        assert result == b"abcdef"

    def test_fragmented_out_of_order(self):
        frag0 = bytes([0x40, 0x06, 0x03, 0x00]) + b"ab"
        frag1 = bytes([0x40, 0x06, 0x03, 0x01]) + b"cd"
        frag2 = bytes([0x40, 0x06, 0x03, 0x02]) + b"ef"
        result = assemble_fragments([frag2, frag0, frag1])
        assert result == b"abcdef"

    def test_empty_list(self):
        assert assemble_fragments([]) is None

    def test_assemble_fragments_skips_empty(self):
        frag0 = bytes([0x40, 0x06, 0x03, 0x00]) + b"ab"
        frag1 = bytes([0x40, 0x06, 0x03, 0x01]) + b"cd"
        frag2 = bytes([0x40, 0x06, 0x03, 0x02]) + b"ef"
        result = assemble_fragments([frag0, b"", frag1, frag2])
        assert result == b"abcdef"


class TestDecryptSystemInfo:
    def test_valid_decrypt(self):
        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        result = decrypt_system_info(sk, sid, TEST_ASSEMBLED)
        assert result is not None
        assert result["serial"] == 28524
        assert result["battery_raw"] == 2611
        assert result["max_actions"] == 1
        assert result["max_users"] == 6
        assert result["version"] == 17
        assert result["dst"] is True
        assert result["name"] == "testa"

    def test_wrong_key_fails(self):
        wrong_sk = bytes(16)
        sid = bytes.fromhex(TEST_SESSION_ID)
        result = decrypt_system_info(wrong_sk, sid, TEST_ASSEMBLED)
        assert result is None

    def test_too_short(self):
        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        assert decrypt_system_info(sk, sid, bytes(4)) is None

    def test_production_date(self):
        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        result = decrypt_system_info(sk, sid, TEST_ASSEMBLED)
        assert result is not None
        assert result["production"] == 1625135983

    def test_decrypt_system_info_bad_response_code(self):
        from Crypto.Cipher import AES

        sk = bytes.fromhex(TEST_SESSION_KEY)
        sid = bytes.fromhex(TEST_SESSION_ID)
        pt = bytes([0x01]) + bytes(17)  # rc=1
        resp_cc = 99
        nonce = bytes.fromhex(TEST_SESSION_ID)[:8] + struct.pack("<I", resp_cc)
        aad = struct.pack("<H", 0) + struct.pack("<I", resp_cc) + b"\x14"
        c = AES.new(sk, AES.MODE_CCM, nonce=nonce, mac_len=6)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(pt)
        assembled = bytes([0x14]) + ct + tag + bytes([0, 0]) + struct.pack("<I", resp_cc)
        assert decrypt_system_info(sk, sid, assembled) is None
