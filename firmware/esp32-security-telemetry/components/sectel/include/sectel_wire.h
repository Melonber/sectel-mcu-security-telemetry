#pragma once
#include <stdint.h>
#include <stddef.h>

/* ===== sectel wire format v2 (little-endian) =====
 * Header, 21 bytes:
 *   0..1   magic        'S','T'
 *   2      schema_ver   SECTEL_SCHEMA_VERSION
 *   3      event_type   sectel_event_type_t
 *   4..5   payload_len  u16, header not included
 *   6      flags        SECTEL_FLAG_*
 *   7..8   boot_count   u16 (wraps)
 *   9..12  seq          u32, per boot, starts at 0
 *   13..16 uptime_ms    u32
 *   17..20 ts           u32 unix seconds, 0 if not synced
 * Device ID is NOT in the frame: bound by transport identity (mTLS/MQTT).
 */
#define SECTEL_MAGIC_0          0x53
#define SECTEL_MAGIC_1          0x54
#define SECTEL_SCHEMA_VERSION   0x02
#define SECTEL_HEADER_SIZE      21
#define SECTEL_MAX_PAYLOAD      128
#define SECTEL_MAX_FRAME        (SECTEL_HEADER_SIZE + SECTEL_MAX_PAYLOAD)

#define SECTEL_FLAG_TIME_SYNCED   0x01
#define SECTEL_FLAG_BUF_OVERFLOW  0x02

/* Never reuse or renumber; append only. */
typedef enum {
    SECTEL_EVT_BOOT      = 1,
    SECTEL_EVT_HEARTBEAT = 2,
    SECTEL_EVT_WIFI      = 3,
    SECTEL_EVT_TLS_ERROR = 4,
    SECTEL_EVT_OTA       = 5,
} sectel_event_type_t;

/* Boot payload:
 *   0      reset_reason   raw esp_reset_reason_t
 *   1      secure_boot    0/1
 *   2      flash_enc      0 off,1 dev,2 release,3 unknown
 *   3..6   last_uptime_s  u32, previous session (0 = unknown/power-on)
 *   7..14  elf_sha256     first 8 bytes of app ELF SHA-256
 *   15     fw_len         u8
 *   16..   fw_version     fw_len bytes, no NUL
 */
#define SECTEL_BOOT_FW_MAX  32

/* Heartbeat payload (15 bytes):
 *   0..1   interval_s     u16
 *   2      queue_depth    u8, frames waiting to be sent
 *   3..6   dropped_total  u32, frames lost to overflow since boot
 *   7..10  free_heap      u32 bytes
 *   11..14 min_free_heap  u32 bytes, low-water mark since boot
 */

/* WiFi payload (14 bytes):
 *   0      action        1 = connected, 2 = disconnected
 *   1..2   reason        u16 wifi_err_reason_t (0 on connect)
 *   3..8   bssid         6 bytes, MAC of the access point
 *   9      rssi          int8, dBm
 *   10     channel       u8 (0 = unknown, on disconnect)
 *   11     authmode      u8 wifi_auth_mode_t (connect only, else 0)
 *   12..13 disconnects   u16, disconnects represented by this event,
 *                        incl. ones suppressed by rate limiting
 */
#define SECTEL_WIFI_PAYLOAD_SIZE  14
#define SECTEL_WIFI_CONNECTED     1
#define SECTEL_WIFI_DISCONNECTED  2

/* TLS error payload (16 bytes):
 *   0      category      1 = cert_verify, 2 = handshake, 3 = mqtt_refused
 *   1      mqtt_rc       u8 MQTT CONNACK return code (category 3), else 0
 *   2..5   esp_err       u32 esp-tls error code (e.g. 0x8008)
 *   6..9   stack_err     i32 mbedTLS error code (negative), 0 if none
 *   10..13 cert_flags    u32 mbedTLS X.509 verification flags
 *   14..15 failures      u16 failures represented by this event,
 *                        incl. ones suppressed by rate limiting
 * Plain TCP failures (broker down, connection refused) are NOT reported:
 * they are not TLS evidence and would flood the queue during outages.
 */
#define SECTEL_TLS_PAYLOAD_SIZE   16
#define SECTEL_TLS_CERT_VERIFY    1
#define SECTEL_TLS_HANDSHAKE      2
#define SECTEL_TLS_MQTT_REFUSED   3

typedef struct {
    uint8_t  flags;
    uint16_t boot_count;
    uint32_t seq;
    uint32_t uptime_ms;
    uint32_t ts;
} sectel_envelope_t;

static inline void sectel_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}

static inline void sectel_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)(v >> 24);
}

static inline size_t sectel_write_header(uint8_t *buf, size_t buf_len,
                                         sectel_event_type_t type,
                                         uint16_t payload_len,
                                         const sectel_envelope_t *env)
{
    if (buf == NULL || env == NULL || buf_len < SECTEL_HEADER_SIZE) return 0;
    buf[0] = SECTEL_MAGIC_0;
    buf[1] = SECTEL_MAGIC_1;
    buf[2] = SECTEL_SCHEMA_VERSION;
    buf[3] = (uint8_t)type;
    sectel_put_u16(&buf[4], payload_len);
    buf[6] = env->flags;
    sectel_put_u16(&buf[7], env->boot_count);
    sectel_put_u32(&buf[9], env->seq);
    sectel_put_u32(&buf[13], env->uptime_ms);
    sectel_put_u32(&buf[17], env->ts);
    return SECTEL_HEADER_SIZE;
}