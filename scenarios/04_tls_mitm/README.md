# Scenario 04: Rogue broker / TLS MITM (S4)

**Status:** variant A executed on the ESP32 bench (26–27 Oct 2026) and detected; variants B and C prepared and pre-validated, device runs pending.

**Goal:** when something other than the real broker answers on the broker address, the device must refuse to send telemetry to it and report why, once it reaches the real broker again.

**Event:** `tls_error` (type 4): category, esp-tls and mbedTLS error codes, X.509 flags, aggregated failure count. Plain TCP failures (broker down, connection refused or reset) are deliberately not reported: they are not TLS evidence and would flood the queue during ordinary outages.

**Rules:**
- Native (executed): `detections/native/tls_error.esql`, Kibana rule *Sectel - TLS error*, every 1 min, 15-min window.
- Sigma (portable): `detections/sigma/sectel_tls_cert_failure.yml` (category `cert_verify`, level high), `detections/sigma/sectel_tls_downgrade.yml` (category `handshake`, level medium). Conversion path not yet tested.
- MITRE ATT&CK for ICS: T0830 (Adversary-in-the-Middle).

This scenario also closes check 6 of scenario 03 (device refuses a broker certificate from an untrusted CA).

---

## Variants

| Variant | Fake broker | Expected on device | Pre-validation (standard TLS client trusting the real CA) |
|---|---|---|---|
| A. Rogue CA | Same IP, CA with the **same name** but a different key | `cert_verify`, mbedTLS `-0x2700` | Rejected: certificate verify failed (untrusted chain) |
| B. Wrong address | Certificate from the **real** CA, issued for 10.99.99.99 | `cert_verify`, mbedTLS `-0x2700` (indistinguishable from A, see findings) | Rejected: IP address mismatch |
| C. Downgrade | Plaintext MQTT on port 8883 | `handshake` | Rejected: connection reset during handshake |

## Files

| File | Purpose |
|---|---|
| `make_rogue_certs.sh` | Generates the rogue CA and broker certificates into `certs/` (variant B uses the real CA from `../../pki/`) |
| `mosquitto-rogue-ca.conf` | Variant A |
| `mosquitto-wrong-ip.conf` | Variant B |
| `mosquitto-no-tls.conf` | Variant C |

Run everything from this folder. No `sudo` is needed; if you get `Permission denied`, fix ownership with `chown -R $(whoami) .` instead.

## Procedure (per variant)

1. Normal stack running (real broker, collector, ELK), device connected.
2. Once: `bash make_rogue_certs.sh <broker_ip>`.
3. Stop the real broker (Ctrl+C). The collector keeps its persistent session.
4. Start the fake broker, e.g. `mosquitto -c mosquitto-rogue-ca.conf -v`.
5. Watch the device monitor for `tls_error cat=... mbedtls=...`; there must be no `connected`. The fake broker log shows TLS failures from the device IP; no MQTT packet reaches it.
6. After 1–2 minutes stop the fake broker and start the real one (`cd ../../backend && mosquitto -c mosquitto.conf -v`).
7. The device connects, delivers its queue and flushes the aggregated `tls_error`.
8. Check the collector / Kibana (`event.action : "tls_error"`) and the rule *Sectel - TLS error*. Record the time the real broker came back and the alert start time.

---

## Results

| Variant | Attack window | Device behaviour | tls_error delivered | Category / error | Detected | Time to alert after reconnect | Notes |
|---|---|---|---|---|---|---|---|
| A | 01:27–01:29 (first run), short rerun before 01:52 | Every connection attempt (~every 4 s) rejected during the TLS handshake; no connection established | Yes, via the real broker after it returned | `cert_verify`, `x509_cert_verify_failed` (-0x2700), `cert_problems: []` | **Yes**, alert started 01:52:20 | TODO (delivery time of first `tls_error`) | Total `failures` TODO; time not synced in the rerun boot (`time_synced: false`) |
| B | | | | | | | Pending |
| C | | | | | | | Pending |

Times are local (UTC+8).

---

## Findings

1. **The rogue broker learns nothing.** Both the ESP32 and the collector rejected the fake broker during the TLS handshake (`tlsv1 alert unknown ca` in the fake broker log). It could neither receive telemetry nor feed fake events to the collector.

2. **Two ESP-IDF v6 quirks broke the first classification.**
   - esp-tls stores the mbedTLS error as a positive value (`0x2700` instead of `-0x2700`).
   - The X.509 verification flags were not propagated (`cert_flags = 0`) even though verification failed.

   The first run was therefore reported as `handshake` instead of `cert_verify`. The fix classifies `cert_verify` when the flags are non-zero **or** the mbedTLS code is `0x2700`, and normalizes the code to the negative mbedTLS convention. After the fix the event is reported correctly.

3. **The device sees *that* the broker certificate was rejected, but not *why*.** Because the flags are not propagated, an untrusted CA (A) and a wrong address (B) produce the same evidence (`cert_verify`, empty `cert_problems`). The reason can only be established from another source, such as the fake broker log or network observations, which is an argument for independent evidence sources (planned: Zeek).

4. **Ordinary outages are not mistaken for attacks.** While no broker was listening, and when the fake broker was stopped (`Connection reset by peer`), no `tls_error` was created.

5. **Rate limiting works.** A `tls_error` log line is printed on every attempt, but an event is emitted at most once per 30 s; further attempts are counted in `failures` and flushed on reconnect.

6. **Repeated handshakes did not exhaust memory.** Minimum free heap during the attack was ~171.5 KB (normal operation with mTLS: ~173 KB). The queue grew without loss (`dropped = 0`).

7. **Time sync is independent of the attack, but matters for evidence.** In the rerun boot SNTP did not sync, so the events carry `time_synced: false` and no device time. The server receive time remains the primary timeline.

## Limitations

- As with Wi-Fi attacks, evidence arrives only after the device reaches the real broker again.
- A rogue broker cannot read telemetry, but it can **block** it: during the attack the SIEM sees silence. Absence of heartbeats is itself a signal (planned: "device silent" rule).
- If the attacker holds the real CA private key, mTLS gives no protection. Keep the CA key offline.
- Before time sync the device clock can make a valid certificate look "not yet valid"; this is a possible false positive.

## Legal note

Run only on your own network and devices.
