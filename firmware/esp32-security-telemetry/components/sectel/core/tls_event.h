#pragma once
#include <stdint.h>

/* Called from the MQTT event handler (single task context). */
void sectel_tls_error_report(uint8_t category, uint8_t mqtt_rc, uint32_t esp_err,
                             int32_t stack_err, uint32_t cert_flags);

/* Emit pending (rate-limited) failures, e.g. right after a successful connect. */
void sectel_tls_error_flush(void);