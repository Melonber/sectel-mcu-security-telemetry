#!/usr/bin/env python3
"""Append SYNTHETIC boot events to backend/events.jsonl to test the posture rules.

There is only one real board and it cannot be made secure without burning eFuses,
so the negative case (secure device) and the posture change are simulated.
Every synthetic line carries "synthetic": true and device_id_source "synthetic_test".

Usage (from this folder):  python3 inject_synthetic.py
"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "backend" / "events.jsonl"


def boot(device: str, secure: bool, flash_enc: str, when: datetime, boot_count: int) -> dict:
    return {
        "received_at": when.isoformat(timespec="milliseconds"),
        "device_id": device, "device_id_source": "synthetic_test", "synthetic": True,
        "schema_version": 2, "event": "boot", "event_type_raw": 1,
        "boot_count": boot_count, "seq": 0, "uptime_ms": 60,
        "device_ts": None, "time_synced": False, "buffer_overflow": False,
        "data": {"reset_reason": "poweron", "reset_reason_raw": 1,
                 "secure_boot": secure, "flash_encryption": flash_enc,
                 "last_uptime_s": 0, "elf_sha256_prefix": "0000000000000000",
                 "fw_version": "synthetic"},
        "duplicate": False, "seq_gap": 0,
    }


now = datetime.now(timezone.utc)
events = [
    # negative case: properly secured device, must NOT be flagged
    boot("esp32-synthetic-secure", True, "release", now - timedelta(minutes=10), 1),
    # posture change: secure first, then insecure (clone / reflash / downgrade)
    boot("esp32-synthetic-flip", True, "release", now - timedelta(minutes=9), 1),
    boot("esp32-synthetic-flip", False, "off", now - timedelta(minutes=1), 2),
]

with OUT.open("a", encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"Appended {len(events)} synthetic boot events to {OUT}")
