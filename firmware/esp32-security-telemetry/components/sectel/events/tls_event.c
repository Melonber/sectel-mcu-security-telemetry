#include "tls_event.h"
#include "sectel.h"

#include <stdint.h>

#include "esp_timer.h"

/* At most one tls_error event per 30 s; further failures are counted and
 * reported in the next event (or on the next successful connect). */
#define TLS_MIN_INTERVAL_US  (30 * 1000000LL)

static struct {
    uint8_t  category, mqtt_rc;
    uint32_t esp_err, cert_flags;
    int32_t  stack_err;
} s_last;
static uint16_t s_pending;
static int64_t  s_last_emit_us = -TLS_MIN_INTERVAL_US;

static void emit(void)
{
    uint8_t p[SECTEL_TLS_PAYLOAD_SIZE];
    p[0] = s_last.category;
    p[1] = s_last.mqtt_rc;
    sectel_put_u32(&p[2],  s_last.esp_err);
    sectel_put_u32(&p[6],  (uint32_t)s_last.stack_err);
    sectel_put_u32(&p[10], s_last.cert_flags);
    sectel_put_u16(&p[14], s_pending);
    s_pending = 0;
    sectel_emit(SECTEL_EVT_TLS_ERROR, p, sizeof(p));
}

void sectel_tls_error_report(uint8_t category, uint8_t mqtt_rc, uint32_t esp_err,
                             int32_t stack_err, uint32_t cert_flags)
{
    s_last.category   = category;
    s_last.mqtt_rc    = mqtt_rc;
    s_last.esp_err    = esp_err;
    s_last.stack_err  = stack_err;
    s_last.cert_flags = cert_flags;
    if (s_pending < UINT16_MAX) s_pending++;

    int64_t now = esp_timer_get_time();
    if (now - s_last_emit_us >= TLS_MIN_INTERVAL_US) {
        s_last_emit_us = now;
        emit();
    }
}

void sectel_tls_error_flush(void)
{
    if (s_pending > 0) emit();
}