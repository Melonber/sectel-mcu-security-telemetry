"""Decoder for sectel wire format v2. Mirrors firmware sectel_wire.h."""
from __future__ import annotations

import json
import struct
import sys
from typing import Any

MAGIC = b"ST"
SCHEMA_VERSION = 2
HEADER = struct.Struct("<2sBBHBHIII")   # 21 bytes, little-endian
FLAG_TIME_SYNCED = 0x01
FLAG_BUF_OVERFLOW = 0x02

EVENT_TYPES = {1: "boot", 2: "heartbeat", 3: "wifi", 4: "tls_error", 5: "ota"}

# esp_reset_reason_t
RESET_REASONS = {
    0: "unknown", 1: "poweron", 2: "ext", 3: "sw", 4: "panic", 5: "int_wdt",
    6: "task_wdt", 7: "wdt", 8: "deepsleep", 9: "brownout", 10: "sdio",
    11: "usb", 12: "jtag", 13: "efuse", 14: "pwr_glitch", 15: "cpu_lockup",
}
FLASH_ENC = {0: "off", 1: "development", 2: "release", 3: "unknown"}

BOOT_FIXED = struct.Struct("<BBBI8sB")      # 16 bytes before fw_version
HEARTBEAT = struct.Struct("<HBIII")         # 15 bytes
WIFI = struct.Struct("<BH6sbBBH")           # 14 bytes

TLS = struct.Struct("<BBIiIH")             # 16 bytes
OTA_FIXED = struct.Struct("<BBI8sB")        # 15 bytes before version

OTA_STAGES = {1: "start", 2: "applied", 3: "rejected", 4: "failed",
              5: "rollback", 6: "confirmed"}
OTA_REASONS = {0: "none", 1: "validation_failed", 2: "downgrade", 3: "same_version",
               4: "download_failed", 5: "image_invalid", 6: "version_unparsable",
               7: "wrong_project", 8: "insecure_url"}

TLS_CATEGORIES = {1: "cert_verify", 2: "handshake", 3: "mqtt_refused"}
# mbedTLS X.509 verification flags (MBEDTLS_X509_BADCERT_*)
X509_FLAGS = {
    0x01: "expired", 0x02: "revoked", 0x04: "cn_mismatch", 0x08: "not_trusted",
    0x10: "crl_not_trusted", 0x20: "crl_expired", 0x40: "missing",
    0x80: "skip_verify", 0x100: "other", 0x200: "future", 0x400: "crl_future",
    0x800: "key_usage", 0x1000: "ext_key_usage", 0x2000: "ns_cert_type",
    0x4000: "bad_md", 0x8000: "bad_pk", 0x10000: "bad_key",
}
MBEDTLS_ERRORS = {
    -0x2700: "x509_cert_verify_failed", -0x7780: "ssl_fatal_alert_message",
    -0x7280: "ssl_conn_eof", -0x7200: "ssl_invalid_record",
    -0x6C00: "ssl_internal_error",
}
MQTT_RC = {0: "accepted", 1: "bad_protocol", 2: "id_rejected",
           3: "server_unavailable", 4: "bad_username_or_password", 5: "not_authorized"}

WIFI_ACTIONS = {1: "connected", 2: "disconnected"}
# wifi_err_reason_t (most common values)
WIFI_REASONS = {
    0: "none", 1: "unspecified", 2: "auth_expire", 3: "auth_leave",
    4: "assoc_expire", 5: "assoc_toomany", 6: "not_authed", 7: "not_assoced",
    8: "assoc_leave", 15: "4way_handshake_timeout", 200: "beacon_timeout",
    201: "no_ap_found", 202: "auth_fail", 203: "assoc_fail",
    204: "handshake_timeout", 205: "connection_fail",
}
# wifi_auth_mode_t
WIFI_AUTH = {
    0: "open", 1: "wep", 2: "wpa_psk", 3: "wpa2_psk", 4: "wpa_wpa2_psk",
    5: "enterprise", 6: "wpa3_psk", 7: "wpa2_wpa3_psk", 8: "wapi_psk", 9: "owe",
}


class DecodeError(ValueError):
    pass


def _decode_boot(p: bytes) -> dict[str, Any]:
    if len(p) < BOOT_FIXED.size:
        raise DecodeError(f"boot payload too short: {len(p)}")
    reason, sb, fe, last_up, sha, fw_len = BOOT_FIXED.unpack_from(p)
    fw = p[BOOT_FIXED.size:]
    if len(fw) != fw_len:
        raise DecodeError(f"fw_len {fw_len} != remaining {len(fw)}")
    return {
        "reset_reason": RESET_REASONS.get(reason, f"raw_{reason}"),
        "reset_reason_raw": reason,
        "secure_boot": bool(sb),
        "flash_encryption": FLASH_ENC.get(fe, f"raw_{fe}"),
        "last_uptime_s": last_up,
        "elf_sha256_prefix": sha.hex(),
        "fw_version": fw.decode("utf-8", errors="replace"),
    }


def _decode_heartbeat(p: bytes) -> dict[str, Any]:
    if len(p) != HEARTBEAT.size:
        raise DecodeError(f"heartbeat payload must be {HEARTBEAT.size}, got {len(p)}")
    interval, depth, dropped, heap, min_heap = HEARTBEAT.unpack(p)
    return {
        "interval_s": interval,
        "queue_depth": depth,
        "dropped_total": dropped,
        "free_heap": heap,
        "min_free_heap": min_heap,
    }


def _decode_wifi(p: bytes) -> dict[str, Any]:
    if len(p) != WIFI.size:
        raise DecodeError(f"wifi payload must be {WIFI.size}, got {len(p)}")
    action, reason, bssid, rssi, channel, auth, disconnects = WIFI.unpack(p)
    connected = action == 1
    return {
        "action": WIFI_ACTIONS.get(action, f"raw_{action}"),
        "reason": WIFI_REASONS.get(reason, f"raw_{reason}"),
        "reason_raw": reason,
        # all-zero BSSID / rssi -128 = "no AP" (e.g. no_ap_found)
        "bssid": ":".join(f"{b:02x}" for b in bssid) if any(bssid) else None,
        "rssi_dbm": rssi if rssi != -128 else None,
        "channel": channel if channel else None,
        "authmode": WIFI_AUTH.get(auth, f"raw_{auth}") if connected else None,
        "disconnects": disconnects,
    }


def _decode_tls(p: bytes) -> dict[str, Any]:
    if len(p) != TLS.size:
        raise DecodeError(f"tls_error payload must be {TLS.size}, got {len(p)}")
    cat, rc, esp_err, stack_err, flags, failures = TLS.unpack(p)
    if stack_err > 0:          # tolerate positive codes (esp-tls convention)
        stack_err = -stack_err
    return {
        "category": TLS_CATEGORIES.get(cat, f"raw_{cat}"),
        "mqtt_rc": MQTT_RC.get(rc, f"raw_{rc}") if cat == 3 else None,
        "esp_err": f"0x{esp_err:04x}",
        "stack_err": stack_err,
        "stack_err_name": MBEDTLS_ERRORS.get(stack_err, f"-0x{-stack_err:04x}" if stack_err else None),
        "cert_flags": flags,
        # empty if the TLS stack did not propagate the X.509 flags (seen on ESP-IDF v6)
        "cert_problems": [n for bit, n in X509_FLAGS.items() if flags & bit],
        "failures": failures,
    }


def _decode_ota(p: bytes) -> dict[str, Any]:
    if len(p) < OTA_FIXED.size:
        raise DecodeError(f"ota payload too short: {len(p)}")
    stage, reason, esp_err, sha, vlen = OTA_FIXED.unpack_from(p)
    ver = p[OTA_FIXED.size:]
    if len(ver) != vlen:
        raise DecodeError(f"version_len {vlen} != remaining {len(ver)}")
    return {
        "stage": OTA_STAGES.get(stage, f"raw_{stage}"),
        "reason": OTA_REASONS.get(reason, f"raw_{reason}"),
        "esp_err": f"0x{esp_err:04x}",
        "target_elf_sha256_prefix": sha.hex() if any(sha) else None,
        "target_version": ver.decode("utf-8", errors="replace") if vlen else None,
    }


PAYLOAD_DECODERS = {1: _decode_boot, 2: _decode_heartbeat, 3: _decode_wifi,
                    4: _decode_tls, 5: _decode_ota}


def decode_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) < HEADER.size:
        raise DecodeError(f"frame too short: {len(frame)}")
    magic, ver, etype, plen, flags, boot_cnt, seq, uptime_ms, ts = HEADER.unpack_from(frame)
    if magic != MAGIC:
        raise DecodeError(f"bad magic: {magic!r}")
    if ver != SCHEMA_VERSION:
        raise DecodeError(f"unsupported schema version: {ver}")
    payload = frame[HEADER.size:]
    if len(payload) != plen:
        raise DecodeError(f"payload_len {plen} != actual {len(payload)}")

    synced = bool(flags & FLAG_TIME_SYNCED)
    event: dict[str, Any] = {
        "schema_version": ver,
        "event": EVENT_TYPES.get(etype, f"unknown_{etype}"),
        "event_type_raw": etype,
        "boot_count": boot_cnt,
        "seq": seq,
        "uptime_ms": uptime_ms,
        "device_ts": ts if synced else None,
        "time_synced": synced,
        "buffer_overflow": bool(flags & FLAG_BUF_OVERFLOW),
    }
    decoder = PAYLOAD_DECODERS.get(etype)
    event["data"] = decoder(payload) if decoder else {"raw": payload.hex()}
    return event


def parse_hex(text: str) -> bytes:
    return bytes.fromhex("".join(text.split()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python decoder.py '<hex bytes>'")
    try:
        print(json.dumps(decode_frame(parse_hex(" ".join(sys.argv[1:]))), indent=2))
    except (DecodeError, ValueError) as e:
        sys.exit(f"decode error: {e}")