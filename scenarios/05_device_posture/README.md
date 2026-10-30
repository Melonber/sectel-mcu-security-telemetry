# Scenario 05: Insecure device posture (S6)

**Status:** executed 30 Oct 2026. Both rules behave as expected on real and synthetic data.

**Goal:** show which devices in the field run without firmware protection (secure boot,
flash encryption), and detect when a device's reported posture changes.

**Why it matters:** without secure boot an attacker with physical access can install any
firmware; without flash encryption the firmware and the device TLS private key can be read
out of flash and the device cloned (see limitation 7 in the root README). Sectel does not
implement these protections; it reports whether they are enabled.

**Evidence:** `boot` event fields `data.secure_boot` and `data.flash_encryption`
(`off`, `development`, `release`, `unknown`), plus firmware hash and version.

**Rules**
| Rule | ES&#124;QL (executed) | Sigma (portable) | Logic |
|---|---|---|---|
| Insecure device posture | `detections/native/device_posture.esql` | `detections/sigma/sectel_device_posture.yml` | Boot with `secure_boot = false` or flash encryption not `release`, last 24 h |
| Device posture change | `detections/native/posture_change.esql` | `detections/sigma/sectel_posture_change.yml` (value_count correlation) | Same device reported more than one posture in 30 days |

Sigma files pass pySigma syntax validation; conversion to ES&#124;QL is not yet tested.

## Test cases
| # | Case | Source | Expected |
|---|---|---|---|
| A | Real ESP32-C3 (no secure boot, flash encryption off) | Real boot event | Flagged by *Insecure device posture* |
| B | Secure device (`secure_boot = true`, `release`) | Synthetic event | **Not** flagged |
| C | Same device: secure, then insecure | Synthetic events | Flagged by both rules |

Cases B and C are synthetic because enabling secure boot and flash encryption burns eFuses
permanently; there is only one board. Synthetic events are marked `synthetic: true` and
`device_id_source: synthetic_test`, and are removed after the test.

## Procedure
1. Stack running (broker, collector, ELK). Press RST on the board to produce a fresh `boot` event.
2. Discover → Try ES|QL: run `device_posture.esql` (without `//` lines). Expect one row for the real device.
3. Kibana → Stack Management → Rules → Create rule → Elasticsearch query → ES|QL:
   - `Sectel - insecure device posture` from `device_posture.esql`
   - `Sectel - device posture change` from `posture_change.esql`
   - Time field `@timestamp`, check every **1 minute** for the test (set to 1 hour afterwards).
4. From this folder: `python3 inject_synthetic.py`. Wait ~10 s; in Discover search `synthetic : true` (3 events).
5. Within 1–2 minutes check both rules (Alerts tab) and run the queries in Discover to see the rows.
6. Clean up (from the repository root):
   ```
   curl -s -X POST "localhost:9200/sectel-events-*/_delete_by_query" \
     -H 'Content-Type: application/json' -d '{"query":{"term":{"synthetic":true}}}'
   grep -v '"synthetic": true' backend/events.jsonl > /tmp/ev && mv /tmp/ev backend/events.jsonl
   ```
   Rewriting the file may make Logstash re-read it from the start; thanks to idempotent document
   IDs this does not create duplicates.

## Results
| Case | Rule: insecure posture | Rule: posture change | Notes |
|---|---|---|---|
| A. Real ESP32-C3 | Flagged (5 boots in 24 h, `secure_boot=false`, `flash_encryption=off`) | Not flagged (posture unchanged) | Firmware versions seen: `3bc74a2-dirty`, `edb757e-dirty` |
| B. Synthetic secure device | **Not flagged** (correct negative) | Not flagged | `secure_boot=true`, `release` |
| C. Synthetic flip device | Flagged (latest boot insecure) | **Flagged**: 2 postures (`secure_boot=true flash_enc=release`, `secure_boot=false flash_enc=off`) | Order of states visible in Discover |

Alerts confirmed in Kibana: *insecure device posture* active from 13:42:40, *device posture change* active from 13:42:14 (30 Oct 2026, UTC+8), after the rule time windows were set to 24 h and 30 days.

## Observations
- **Firmware identity from git.** Once the project became a git repository, ESP-IDF set the
  firmware version from `git describe` (e.g. `3bc74a2-dirty`); `-dirty` means the build had
  uncommitted changes. Each boot event therefore ties the device to the exact source commit,
  which is useful in an investigation. Commit before building release images.
- The posture query is evaluated over boot events only; the real device appeared with 5 boots
  in 24 h because of reflashing during development.

- **Rule time window must match the query window.** The Elasticsearch query rule applies its
  own *Time window* (default 5 minutes) on top of the ES|QL condition. With the default the
  posture rules silently found nothing, because posture is reported only at boot. Setting the
  rule window to 24 h and 30 days fixed it. The same applies to every rule in this project:
  document the actual rule window, not only the query.
- **One alert per rule run, not per device.** Two devices matched the posture rule, but Kibana
  showed a single alert; the rows (which devices) are visible only by running the query. The
  Elastic Security detection engine creates an alert per result row, which is one more reason
  to move the rules there.

## Limitations
- **Posture is device-claimed.** A compromised device can report `secure_boot = true`. The
  report is trustworthy only on a device that is actually protected, so the rule finds
  honest misconfiguration, not a determined attacker.
- **Reported only at boot.** A device that never restarts drops out of the 24 h window. Fleet
  inventory should use a longer window or a periodic posture report (future work).
- **Order of states is not checked by the rule.** Insecure → secure (provisioning) and
  secure → insecure (suspicious) both trigger *posture change*; the analyst checks the order.
- **No real secure device tested.** A second board with secure boot and flash encryption
  enabled is planned.
