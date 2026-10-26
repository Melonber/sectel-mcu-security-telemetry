# Scenario 01: Boot loop

**Status:** variants A and B executed (15 Oct 2026); variant C pending.
**Goal:** verify that repeated restarts of an embedded device are visible in the SIEM and detected by a rule.
**Device:** ESP32-C3, ESP-IDF v6.0.1, sectel wire format v2, plain MQTT (no TLS).
**Rule:** `detections/sigma/sectel_boot_loop.yml` (portable), executed as `detections/native/boot_loop.esql` (Kibana Elasticsearch query rule, ES|QL, every 1 min).
**Detection logic:** 3 or more `boot` events from one `device_id` within 5 minutes.

## Threat context
A device that keeps restarting may indicate fault injection (brownout/voltage glitch), a crash triggered by malformed input, forced restarts by an attacker, or a broken firmware update. Mapped to MITRE ATT&CK for ICS **T0816 (Device Restart/Shutdown)**. A boot loop alone does not prove an attack; see false positives.

## How the scenario is triggered
Test-only Kconfig options in `main/Kconfig.projbuild` (never enabled in production):

| Variant | Kconfig | Restart method | Expected `reset_reason` |
|---|---|---|---|
| A. Software restart loop | `SECTEL_TEST_BOOTLOOP=y` | `esp_restart()` every 20 s | `sw` (3) |
| B. Crash loop | + `SECTEL_TEST_BOOTLOOP_PANIC=y` | `abort()` every 20 s | `panic` (4) |
| C. Physical reset | none | RST button x3 | `poweron` (1) |

## Evidence used
- `boot` event: `reset_reason`, `last_uptime_s` (previous session length), `elf_sha256_prefix`, `fw_version`
- Envelope: `boot_count` (persisted in NVS, increments even when the event is never delivered)
- Collector: `received_at` (server time, used as `@timestamp`)

## Results
Times are local (UTC+8) as shown in Kibana.

| Variant | Boots (boot_count range) | Received | Lost | Detected | Time to detect | reasons | last_uptime_s |
|---|---|---|---|---|---|---|---|
| A | TODO | TODO | TODO | Y (alert started 18:53:46) | ~1 min after 3rd boot | sw | ~15-20 |
| B | 343-347 (sample window) | 5 of 5 in window | 0 in window | TODO | TODO | panic | 20 |
| C | | | | | | | |

### Observations
1. **Rule fired** within about one rule interval (1 min) after the third boot in variant A.
2. **Alert flapping (A).** The alert switched between active and recovered and was marked *Flapping* by Kibana. Likely cause: some boot events were not delivered before the next restart, so the count in the 5-minute window hovered around the threshold.
3. **Time to first delivery after boot was ~11 s** (Wi-Fi IP at ~1.8 s, MQTT connected at ~10.7 s, first frame sent at ~11.4 s). The MQTT client tried to connect before Wi-Fi was up and then waited the default 10 s reconnect timeout.
4. **Crash loop is distinguishable from a software restart** by `reset_reason` (`panic` vs `sw`); one rule covers both, and `reasons` in the alert gives the analyst context.
5. **Firmware identification.** `elf_sha256_prefix` changed between the normal and the test build, so an investigation can tie crashes to a specific image.
6. **Side effect.** About 330 restarts during testing (boot_count 17 to 347), each writing NVS. On a real device a sustained boot loop also wears flash.

## Limitations found
- **Restart faster than first delivery = invisible.** If the device restarts in less than ~11 s (default config), no boot event leaves the device; the loop is invisible to the SIEM. Events queued in RAM are lost on every restart.
- **Loss at the end of a boot cannot be seen as `seq_gap`**, because `seq` restarts at 0 after each boot. Loss is measurable only via gaps in `boot_count`.
- **Physical reset is indistinguishable from power-on** (`reset_reason = poweron`, RTC memory cleared).
- Test bench has no TLS or device authentication; `device_id` is device-claimed (MQTT topic).

## Mitigation tested / planned
- Set `network.reconnect_timeout_ms = 2000` in the MQTT client to reduce time to first delivery (~11 s to ~3 s expected). Re-run variant A and compare loss and flapping. **TODO**
- Planned: persist a small summary of undelivered events (count, last seq) in RTC/NVS and report it in the next `boot` event.

## False positives
Unstable power supply, firmware bugs unrelated to an attack, development and flashing sessions.

## How to reproduce
1. Start the stack (Docker ELK, Mosquitto, collector), create the rule from `boot_loop.esql`.
2. Enable the variant in `idf.py menuconfig` → *Sectel demo config*, then `idf.py build flash`.
3. Run 5+ minutes, check Rules → *Sectel - boot loop* and Discover (`event.action : "boot"`).
4. Disable test options and flash normal firmware.
