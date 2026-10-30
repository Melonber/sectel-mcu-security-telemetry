import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from decoder import DecodeError, decode_frame, parse_hex  # noqa: E402

# Real frames captured from ESP32-C3 (fw a2827a22...)
BOOT = parse_hex(
    "53 54 02 01 11 00 00 01 00 00 00 00 00 3d 00 00 00 00 00 00 00"
    "01 00 00 00 00 00 00 a2 82 7a 22 5c 93 95 56 01 31"
)
HEARTBEAT = parse_hex(
    "53 54 02 02 0f 00 00 01 00 01 00 00 00 5a 27 00 00 00 00 00 00"
    "0a 00 00 00 00 00 00 08 ec 04 00 a0 db 04 00"
)


def test_boot():
    e = decode_frame(BOOT)
    assert e["event"] == "boot"
    assert (e["boot_count"], e["seq"], e["uptime_ms"]) == (1, 0, 61)
    assert e["time_synced"] is False and e["device_ts"] is None
    d = e["data"]
    assert d["reset_reason"] == "poweron"
    assert d["secure_boot"] is False and d["flash_encryption"] == "off"
    assert d["last_uptime_s"] == 0
    assert d["elf_sha256_prefix"] == "a2827a225c939556"
    assert d["fw_version"] == "1"


def test_heartbeat():
    e = decode_frame(HEARTBEAT)
    assert e["event"] == "heartbeat"
    assert (e["seq"], e["uptime_ms"]) == (1, 10074)
    assert e["data"] == {
        "interval_s": 10, "queue_depth": 0, "dropped_total": 0,
        "free_heap": 322568, "min_free_heap": 318368,
    }


def test_overflow_flag():
    f = bytearray(HEARTBEAT)
    f[6] = 0x02
    assert decode_frame(bytes(f))["buffer_overflow"] is True


@pytest.mark.parametrize("frame,msg", [
    (b"XX" + HEARTBEAT[2:], "bad magic"),
    (HEARTBEAT[:10], "too short"),
    (HEARTBEAT[:-1], "payload_len"),
    (HEARTBEAT[:2] + b"\x09" + HEARTBEAT[3:], "schema version"),
])
def test_rejects_bad_frames(frame, msg):
    with pytest.raises(DecodeError, match=msg):
        decode_frame(frame)


def test_unknown_type_kept_raw():
    f = bytearray(HEARTBEAT)
    f[3] = 99
    e = decode_frame(bytes(f))
    assert e["event"] == "unknown_99" and "raw" in e["data"]


def _wifi_frame(payload: bytes) -> bytes:
    import struct
    hdr = struct.pack("<2sBBHBHIII", b"ST", 2, 3, len(payload), 0, 9, 4, 1500, 0)
    return hdr + payload


def test_wifi_connected():
    import struct
    p = struct.pack("<BH6sbBBH", 1, 0, bytes.fromhex("30ae7be574b1"), -38, 5, 3, 2)
    d = decode_frame(_wifi_frame(p))["data"]
    assert d["action"] == "connected" and d["bssid"] == "30:ae:7b:e5:74:b1"
    assert (d["rssi_dbm"], d["channel"], d["authmode"], d["disconnects"]) == (-38, 5, "wpa2_psk", 2)


def test_wifi_disconnected_reason():
    import struct
    p = struct.pack("<BH6sbBBH", 2, 201, bytes(6), -90, 0, 0, 1)
    d = decode_frame(_wifi_frame(p))["data"]
    assert d["action"] == "disconnected" and d["reason"] == "no_ap_found"
    assert d["channel"] is None and d["authmode"] is None


def test_wifi_no_ap_values_are_null():
    import struct
    p = struct.pack("<BH6sbBBH", 2, 201, bytes(6), -128, 0, 0, 5)
    d = decode_frame(_wifi_frame(p))["data"]
    assert d["bssid"] is None and d["rssi_dbm"] is None


def _tls_frame(payload: bytes) -> bytes:
    import struct
    hdr = struct.pack("<2sBBHBHIII", b"ST", 2, 4, len(payload), 1, 9, 7, 3000, 1792425361)
    return hdr + payload


def test_tls_cert_not_trusted():
    import struct
    p = struct.pack("<BBIiIH", 1, 0, 0x8008, -0x2700, 0x08, 3)
    e = decode_frame(_tls_frame(p))
    d = e["data"]
    assert e["event"] == "tls_error" and e["time_synced"] is True
    assert d["category"] == "cert_verify" and d["cert_problems"] == ["not_trusted"]
    assert d["stack_err_name"] == "x509_cert_verify_failed" and d["esp_err"] == "0x8008"
    assert d["failures"] == 3 and d["mqtt_rc"] is None


def test_tls_handshake_and_refused():
    import struct
    h = decode_frame(_tls_frame(struct.pack("<BBIiIH", 2, 0, 0x8008, -0x7200, 0, 1)))["data"]
    assert h["category"] == "handshake" and h["cert_problems"] == []
    r = decode_frame(_tls_frame(struct.pack("<BBIiIH", 3, 5, 0, 0, 0, 1)))["data"]
    assert r["category"] == "mqtt_refused" and r["mqtt_rc"] == "not_authorized"
    assert r["stack_err_name"] is None


def test_tls_positive_stack_code_normalized():
    import struct
    d = decode_frame(_tls_frame(struct.pack("<BBIiIH", 1, 0, 0x801a, 0x2700, 0, 4)))["data"]
    assert d["stack_err"] == -0x2700 and d["stack_err_name"] == "x509_cert_verify_failed"
    assert d["cert_problems"] == [] and d["failures"] == 4


def _ota_frame(payload: bytes) -> bytes:
    import struct
    hdr = struct.pack("<2sBBHBHIII", b"ST", 2, 5, len(payload), 1, 9, 11, 5000, 1793338000)
    return hdr + payload


def test_ota_rejected_downgrade():
    import struct
    v = b"0.3.0"
    p = struct.pack("<BBI8sB", 3, 2, 0, bytes.fromhex("1122334455667788"), len(v)) + v
    e = decode_frame(_ota_frame(p))
    d = e["data"]
    assert e["event"] == "ota"
    assert (d["stage"], d["reason"], d["target_version"]) == ("rejected", "downgrade", "0.3.0")
    assert d["target_elf_sha256_prefix"] == "1122334455667788"


def test_ota_start_without_target():
    import struct
    d = decode_frame(_ota_frame(struct.pack("<BBI8sB", 1, 0, 0, bytes(8), 0)))["data"]
    assert d["stage"] == "start" and d["target_version"] is None
    assert d["target_elf_sha256_prefix"] is None