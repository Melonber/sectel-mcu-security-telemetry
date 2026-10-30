# Scenario 06: Firmware update tampering (S5)

**Status:** variants A–D executed on the ESP32-C3 bench (30 Oct 2026); E (insecure URL) and B2 (foreign signing key) pending.

**Goal:** a device must accept only authentic, newer firmware, and report every refused,
failed or rolled-back update so the SOC sees attempts to install modified or vulnerable code.

**Protection layers (all without burning eFuses):**
| Layer | Mechanism | Stops |
|---|---|---|
| Who may trigger an update | OTA command via MQTT topic `sectel/<id>/ota`, mTLS + ACL (only the operator identity can write it) | Arbitrary clients sending update commands |
| Where the image comes from | HTTPS only, server certificate must chain to the project CA | Plain HTTP, fake update servers |
| Is the image authentic | Signed app images (RSA, Secure Boot V2 scheme) verified by the running app before switching | Modified / unsigned / foreign-signed firmware |
| Is it newer | Software anti-rollback: `MAJOR.MINOR.PATCH` must be strictly greater; same project name | Downgrade to a vulnerable version, wrong product image |
| Does it work | Bootloader rollback: a new image must reach the broker and run 30 s before it is confirmed | Bricking / broken releases |

**Event:** `ota` (type 5): `stage` (start, applied, rejected, failed, rollback, confirmed),
`reason` (validation_failed, downgrade, same_version, download_failed, image_invalid,
version_unparsable, wrong_project, insecure_url), `esp_err`, target version and ELF hash prefix.

**Rules:** `detections/native/ota_security.esql` (rejected / failed / rollback, 15 min);
Sigma: `sectel_ota_rejected.yml` (high, ATT&CK for ICS T0857 System Firmware),
`sectel_ota_rollback.yml` (medium). Sigma syntax validated with pySigma; conversion not yet tested.

---

## One-time setup

1. **Firmware options** (`idf.py menuconfig`; an existing `sdkconfig` ignores `sdkconfig.defaults`):
   - *Bootloader config* → **Enable app rollback support**
   - *Security features* → **Require signed app images** → App signing scheme **RSA**
     → **Verify app signature on update** (on) → **Sign binaries during build** (on)
     → Secure boot private signing key: `ota_signing_key.pem`
   - Do **not** enable "Enable hardware Secure Boot in bootloader" or flash encryption
     (they burn eFuses permanently).
2. **Signing key** (in the firmware project folder, git-ignored by `*.pem`):
   ```
   espsecure generate-signing-key --version 2 --scheme rsa3072 ota_signing_key.pem
   ```
   (older esptool: `espsecure.py generate_signing_key --version 2 --scheme rsa3072 ota_signing_key.pem`)
3. **Broker ACL:** use the new `backend/acl.conf` (operator may write `sectel/+/ota`, each device
   may read only its own) and restart Mosquitto.
4. **Version:** the root `CMakeLists.txt` sets `PROJECT_VER`; the OTA check compares it.

## Build the test images

Run in `firmware/esp32-security-telemetry`; copy each image into `scenarios/06_ota/images/`.

| Image | How | Purpose |
|---|---|---|
| `sectel-0.3.0.bin` | `PROJECT_VER "0.3.0"`, `idf.py fullclean build flash monitor` (USB; also flashes the rollback-enabled bootloader), then copy `build/esp32_sectel.bin` | Baseline on the device; later the downgrade image |
| `sectel-0.3.1.bin` | `PROJECT_VER "0.3.1"`, `idf.py build` (no flash), copy | Legitimate update |
| `sectel-0.3.1-tampered.bin` | `python3 tamper_image.py images/sectel-0.3.1.bin` | Modified firmware |
| `sectel-0.3.2-crash.bin` | `PROJECT_VER "0.3.2"`, enable *TEST: boot loop* + *abort()* (20 s < 30 s confirm), build, copy; then disable the test options again | Broken release, triggers rollback |

## Run

Terminal A (this folder): `python3 ota_server.py` (HTTPS on 8443).
Send an update command (from `backend/`, adjust the device ID and Mac IP):
```
mosquitto_pub -h localhost -p 8883 --cafile ../pki/ca.crt \
  --cert ../pki/collector.crt --key ../pki/collector.key \
  -t sectel/esp32-dcda0c81a1e4/ota -q 1 \
  -m "https://192.168.18.207:8443/sectel-0.3.1-tampered.bin"
```

| Order | Variant | Image / payload | Running before | Expected events | Expected device state |
|---|---|---|---|---|---|
| 1 | B. Tampered image | `sectel-0.3.1-tampered.bin` | 0.3.0 | start → **rejected / validation_failed** | stays on 0.3.0 |
| 2 | A. Legitimate update | `sectel-0.3.1.bin` | 0.3.0 | start → applied → reboot → boot `fw 0.3.1` → **confirmed** after ~30 s | 0.3.1 |
| 3 | C. Downgrade | `sectel-0.3.0.bin` | 0.3.1 | start → **rejected / downgrade** (before download) | stays on 0.3.1 |
| 4 | D. Broken release | `sectel-0.3.2-crash.bin` | 0.3.1 | start → applied → boot 0.3.2 → crash → boot 0.3.1 → **rollback** (target 0.3.2) | back on 0.3.1 |
| 5 | E. Insecure source (optional) | `http://192.168.18.207:8443/...` | any | **rejected / insecure_url** | unchanged |

Rule: create *Sectel - OTA security* from `ota_security.esql`, check every 1 minute,
**rule time window 15 minutes** (lesson from scenario 05).

## Results
| Variant | Events observed | Detected | Time to alert | Notes |
|---|---|---|---|---|
| B. Tampered image (0.3.0 running) | start → download ~30 s → `Checksum failed` → **rejected / validation_failed** (`esp_err 0x1503`), target 0.3.1 | **Yes** (*OTA security* alert) | rule created after the event; next run fired | Device stayed on 0.3.0. Caught by the image checksum, **before** the signature check (see findings) |
| A. Legitimate update 0.3.0 → 0.3.1 | start → applied → reboot (`reset=sw`, boot 412, `fw 0.3.1`, pending verification) → **confirmed** at 30.5 s uptime | n/a (benign, not flagged) | — | Signature verified; MQTT reconnected at 13.9 s, confirm at the 30 s threshold |
| C. Downgrade to 0.3.0 (0.3.1 running) | start → **rejected / downgrade** 40 ms after the header was read | **Yes** | — | No image segments downloaded; whole attempt ~1.6 s (mostly TLS) |
| D. Broken release 0.3.2 (crash at 20 s) | start → download ~133 s → **signature verified (RSA-PSS)** → applied → boot 413 `fw 0.3.2` pending → `abort()` at 20.7 s → bootloader rollback → boot 414 `reset=panic`, `last_uptime 20 s`, `fw 0.3.1` → **rollback** event (target 0.3.2) | **Yes** | — | Full chain reconstructable from events alone (see findings) |
| E. Insecure URL | | | | Pending |
| B2. Image signed with a foreign key | | | | Pending: proves the signature layer against an attacker who fixes checksums |

## Findings
1. **The signature layer works and is visible.** On every accepted image the device logged
   `Verifying image signature... #0 app key digest == #0 trusted key digest ... Verifying with
   RSA-PSS... Signature verified successfully!` (~70 ms per check).
2. **Variant B was stopped by integrity, not by the signature.** Flipping one byte broke the image
   checksum, so verification failed before the signature step. An attacker who recomputes
   checksums and hashes is stopped only by the signature; variant B2 is planned to show that.
3. **The target hash in the `ota` event is declared, not computed.** The tampered image reported
   `target_elf_sha256_prefix = 94e40f13ae65b54b`, identical to the genuine 0.3.1, because the
   modification did not touch the header. Useful for investigation ("someone modified release
   0.3.1"), but not proof of authenticity.
4. **Version check before download is a cheap first line.** A downgrade costs ~1.6 s and almost no
   traffic; a signature rejection costs a full download (~30–133 s, ~950 KB).
5. **A broken release is reconstructable from telemetry alone:** boot 413 `fw 0.3.2` (`reset=sw`)
   → boot 414 `reset=panic`, `last_uptime_s=20`, `fw 0.3.1` → `ota rollback` with target 0.3.2.
6. **Memory during OTA.** HTTPS download in parallel with MQTT over mTLS lowered the minimum free
   heap to ~114–133 KB (normal operation ~170 KB). This is the worst case observed so far.
7. **Download time varied widely** (~30 s vs ~133 s for images of the same size), so OTA duration
   on Wi-Fi is not a stable metric.
8. **A false positive in `tls_error` was found here.** When Wi-Fi stopped for the planned restart,
   the open MQTT session failed with mbedTLS `-0x4C` (network read error) and was classified as a
   TLS handshake failure. Any Wi-Fi drop mid-session would have raised a false TLS alert. Fixed:
   only `ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED` counts as `handshake`.

## Limitations
- **Signature is verified on update only, not at boot.** Without hardware secure boot anyone
  with USB access can flash unsigned firmware directly. This scenario covers remote updates.
- **Anti-rollback is in software.** It relies on the running firmware and is not backed by
  eFuse security versions, so a USB reflash bypasses it.
- **Validation failure is not split further:** a bad signature and a corrupted image both
  return `ESP_ERR_OTA_VALIDATE_FAILED` and are reported as `validation_failed`.
- **Operator identity reuses the collector certificate** (lab shortcut). Production needs a
  separate operator identity and ideally signed update commands.
- **Commands are not queued:** a device that is offline when the command is sent misses it.
- **The rollback event is sent by the old image** after the new one failed.
