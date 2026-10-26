# Scenario 02: Wi-Fi attacks (disconnect flood, evil twin)

**Status:** variant A executed (16 Oct 2026); B-D pending.
**Event:** `wifi` (type 3): action, reason, bssid, rssi_dbm, channel, authmode, disconnects.
**Rules:** `detections/native/wifi_disconnect_flood.esql`, `wifi_bssid_change.esql`, `wifi_open_network.esql`

## Variants
| Variant | How | Expected evidence | Rule |
|---|---|---|---|
| A. AP outage / disconnect flood | Power off the router for 1-2 min, then on | disconnected (beacon_timeout, no_ap_found), then connected with disconnects > 1 | disconnect_flood |
| B. Evil twin | Phone hotspot with the same SSID and password (2.4 GHz), router off; then phone off, router on | connected with a different BSSID | bssid_change |
| C. Open rogue AP | Phone hotspot with the same SSID, no password; router off | connected, authmode = open | open_network (only if device is configured to accept open networks) |
| D. Real deauth (optional) | Deauth tool against **your own** AP/device only | disconnected with reason auth/assoc codes (2-8), repeated | disconnect_flood |

## Device behaviour to note
- Disconnect events are rate limited (1 per 10 s); extra disconnects are counted in `disconnects` of the next wifi event.
- While disconnected, events stay in the RAM queue (32 frames) and arrive after reconnect. Detection is therefore delayed until the device is back on a network that reaches the broker.
- On the evil-twin network the broker is unreachable, so heartbeats queue up; after ~5 min the queue overflows and the oldest frames (including the wifi event of the rogue connection) are evicted. Keep variant B under ~4 min, and record `dropped_total` in the next heartbeat.

## Results
| Variant | Duration | Disconnects (device) | Events received | Detected | Time to detect (after reconnect) | Notes |
|---|---|---|---|---|---|---|
| A (Wi-Fi router unplugged) | ~2 min (start time TODO) | ~64 attempts (12 x 5 + 4) | 13 wifi events (12 disconnected, 1 connected) | Y | 51 s (delivered 00:14:54, alert 00:15:45) | Burst delivery after reconnect; reason no_ap_found; bssid 00:00:00:00:00:00 and rssi -128 mean "no AP"; router came back on channel 8 (was 5), same BSSID; alert recovered 00:18:45 |
| B | | | | | | |
| C | | | | | | |
| D | | | | | | |

## Observations (variant A)
- Rate limiting worked: ~64 reconnect attempts were reported in 13 frames, so the queue did not overflow and older evidence was not evicted.
- All events arrived within ~1 s after the device reconnected (store-and-forward). Detection cannot happen while the device is offline.
- Total time from outage start to alert = outage duration + router boot time + up to one rule interval (1 min).
- Channel change (5 -> 8) with the same BSSID was legitimate (router auto channel), but a channel change for the same SSID is also a weak evil-twin indicator.
- The alert recovered ~3 min after the events; the rule's own time window setting limits the effective window (document the actual value).

## Limitations (expected)
- The device reports attacks on its own network through that same network: evidence arrives only after recovery.
- Wi-Fi reason codes are reported by the device and can be spoofed by an attacker (forged deauth frames).
- The log shows `pmf:0`: Protected Management Frames are not in use, so forged deauth frames are accepted. Enabling PMF (WPA3 or PMF-required on AP and device) is the mitigation to test.

## Legal note
Run deauth and rogue-AP tests only against your own equipment. Transmitting deauth frames or jamming third-party networks is illegal in most jurisdictions.
