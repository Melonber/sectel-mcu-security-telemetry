# Scenario 03: mTLS and topic ACL (identity and provenance baseline)

**Status:** executed on the ESP32 bench (19 Oct 2026). Checks 1, 2, 4 confirmed on the bench; 3 and 5 confirmed in the lab test.

**Goal:** show that, after mTLS + ACL, `device_id` is no longer device-claimed: the broker
only accepts a frame on `sectel/<id>/ev` from a client whose certificate CN is `<id>`.

**Setup:** `pki/make_pki.sh <broker_ip> <device_id>`, Mosquitto on 8883 with
`require_certificate`, `use_identity_as_username`, `acl.conf`.

## Checks (pre-validated with Mosquitto 2.0.18 + mosquitto_pub)
| # | Action | Expected | Result (lab) | Result (ESP32 bench) |
|---|---|---|---|---|
| 1 | Device cert publishes to its own topic | Delivered, `device_id_source = mtls_acl` | Delivered | Delivered; broker username = CN `esp32-dcda0c81a1e4`; TLS 1.2 ECDHE-ECDSA-AES256-GCM-SHA384 |
| 2 | Device cert publishes to another device's topic | Denied by ACL, not delivered | Denied (broker log) | `Denied PUBLISH ... sectel/esp32-victim/ev`, PUBACK rc 135 internally; nothing reached the collector |
| 3 | Other valid cert publishes to this device's topic | Denied by ACL | Denied | Not repeated (lab result) |
| 4 | Client without certificate | TLS handshake fails | "peer did not return a certificate" | Same: rejected during TLS handshake, before MQTT |
| 5 | Device cert subscribes to all device topics | Receives nothing | Nothing received | Not repeated (lab result) |
| 6 | ESP32 with wrong CA (broker not trusted) | Device refuses to connect | | Pending |

## Commands (from backend/, broker running)
```
mosquitto_pub -h localhost -p 8883 --cafile ../pki/ca.crt \
  --cert ../pki/device.crt --key ../pki/device.key \
  -t sectel/esp32-victim/ev -q 1 -m test            # check 2: expect "Denied PUBLISH" in broker log
mosquitto_pub -h localhost -p 8883 --cafile ../pki/ca.crt -t sectel/x/ev -m hi   # check 4
```

## Observations
- With MQTT 3.1.1 (`p4` in the broker log) a denied QoS 1 publish is still acknowledged to the
  client and silently dropped: the broker computes reason code 135 (Not authorized) but 3.1.1
  cannot carry it, so the publisher cannot tell it was rejected. Evidence of the attempt exists
  only in the broker log (forward it to the SIEM as a second, independent source). With MQTT 5
  the client would receive 0x87 and could report the rejection itself.
- The ESP32 negotiated TLS 1.2 (TLS 1.3 is disabled by default in ESP-IDF); desktop clients
  negotiated TLS 1.3. Enabling TLS 1.3 on the device is a possible improvement.
- QoS 1 redelivery observed: heartbeat seq 4 arrived twice (~1.4 s late, PUBACK delay);
  the second copy was flagged `duplicate: true` and kept.
- The device private key is stored in flash in plaintext. Without flash encryption it can be
  extracted from a stolen device, so a cloned device could impersonate it. Mitigations to
  evaluate: flash encryption, NVS encryption, ESP32 Digital Signature (DS) peripheral.

## Measured cost of mTLS on the device (ESP32-C3)
| Metric | Plain MQTT | mTLS | Delta |
|---|---|---|---|
| First delivery after boot | ~4.5 s | ~6.3 s (MQTT connected 5.33 s) | +1.8 s (ECDSA handshake) |
| Free heap (steady) | ~210 KB | ~182.7 KB | -27.5 KB |
| Min free heap (peak) | ~204.5 KB | ~173.6 KB | -31 KB |
| Flash image | 939,016 B (16 Oct, before SNTP) | ~945 KB | ~+6 KB incl. SNTP and embedded certs |
| Static DRAM | 108,928 B | 108,992 B | +64 B |

Flash cost is small because mbedTLS/esp-tls were already linked (MQTT transport and WPA2
crypto). The real cost of TLS is runtime RAM and handshake time.
