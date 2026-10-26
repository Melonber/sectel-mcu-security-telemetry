import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from collector import track_sequence  # noqa: E402


def ev(boot, seq):
    return {"boot_count": boot, "seq": seq}


def test_sequence_gap_duplicate_and_new_boot():
    st = {}
    a = ev(1, 0); track_sequence(st, "d", a); assert a["seq_gap"] == 0
    b = ev(1, 3); track_sequence(st, "d", b); assert b["seq_gap"] == 2
    c = ev(1, 3); track_sequence(st, "d", c); assert c["duplicate"] is True
    d = ev(2, 0); track_sequence(st, "d", d); assert d["seq_gap"] == 0 and not d["duplicate"]


def test_first_frame_not_zero_reports_gap():
    st = {}
    a = ev(5, 4); track_sequence(st, "d", a); assert a["seq_gap"] == 4


def test_time_fields():
    from datetime import datetime, timezone
    from collector import add_time_fields
    recv = datetime(2026, 10, 16, 0, 0, 5, tzinfo=timezone.utc)
    ev = {"device_ts": int(datetime(2026, 10, 16, 0, 0, 2, tzinfo=timezone.utc).timestamp())}
    add_time_fields(ev, recv)
    assert ev["lag_ms"] == 3000 and ev["device_time"].startswith("2026-10-16T00:00:02")
    ev2 = {"device_ts": None}
    add_time_fields(ev2, recv)
    assert "lag_ms" not in ev2