"""MQTT collector: subscribe -> decode -> enrich -> JSON lines (stdout + file)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

import paho.mqtt.client as mqtt

from decoder import DecodeError, decode_frame

TOPIC = "sectel/+/ev"


def track_sequence(state: dict, device_id: str, ev: dict[str, Any]) -> None:
    """Mark duplicates and gaps using (boot_count, seq) per device."""
    boot, seq = ev["boot_count"], ev["seq"]
    prev = state.get(device_id)
    ev["duplicate"] = False
    ev["seq_gap"] = 0
    if prev and prev[0] == boot:
        if seq <= prev[1]:
            ev["duplicate"] = True          # QoS 1 redelivery or replay
            return
        ev["seq_gap"] = seq - prev[1] - 1   # frames lost in between
    elif seq > 0:
        ev["seq_gap"] = seq                 # first frames of this boot missing
    state[device_id] = (boot, seq)


def add_time_fields(ev: dict[str, Any], received: datetime) -> None:
    """device_time from device clock; lag = server receive time - device time.

    Lag includes queueing/transport delay AND device clock error; device_ts has
    1 s resolution, so small values (+-1 s) are noise."""
    ts = ev.get("device_ts")
    if ts:
        device_dt = datetime.fromtimestamp(ts, timezone.utc)
        ev["device_time"] = device_dt.isoformat()
        ev["lag_ms"] = int((received - device_dt).total_seconds() * 1000)


def handle(topic: str, payload: bytes, state: dict,
           id_source: str = "mqtt_topic") -> dict[str, Any]:
    received = datetime.now(timezone.utc)
    received_at = received.isoformat(timespec="milliseconds")
    device_id = topic.split("/")[1]
    try:
        ev = decode_frame(payload)
        track_sequence(state, device_id, ev)
        add_time_fields(ev, received)
    except DecodeError as e:
        ev = {"event": "decode_error", "error": str(e), "raw": payload.hex()}
    # mqtt_topic: device-claimed. mtls_acl: broker enforced that the topic
    # matches the CN of the client certificate that published it.
    return {"received_at": received_at, "device_id": device_id,
            "device_id_source": id_source, **ev}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--pki", default="../pki", help="dir with ca.crt, collector.crt/.key")
    ap.add_argument("--plain", action="store_true", help="plain MQTT on 1883 (test only)")
    ap.add_argument("--out", default="events.jsonl")
    args = ap.parse_args()

    state: dict = {}
    out = open(args.out, "a", encoding="utf-8")

    def on_connect(client, userdata, flags, reason_code, properties):
        print(f"[collector] connected: {reason_code}, subscribing {TOPIC}", file=sys.stderr)
        client.subscribe(TOPIC, qos=1)

    def on_message(client, userdata, msg):
        line = json.dumps(handle(msg.topic, msg.payload, state, id_source))
        print(line, flush=True)
        out.write(line + "\n")
        out.flush()

    # Persistent session: broker keeps QoS 1 messages while the collector is
    # offline and delivers them on reconnect (requires a fixed client_id).
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id="sectel-collector", clean_session=False)
    client.reconnect_delay_set(min_delay=1, max_delay=5)
    id_source = "mqtt_topic"
    if args.plain:
        if args.port == 8883:
            args.port = 1883
    else:
        client.tls_set(ca_certs=f"{args.pki}/ca.crt",
                       certfile=f"{args.pki}/collector.crt",
                       keyfile=f"{args.pki}/collector.key")
        id_source = "mtls_acl"
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.host, args.port, keepalive=30)
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        pass
    finally:
        out.close()


if __name__ == "__main__":
    main()