#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "sectel_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Init NVS + envelope (boot counter). Call once, first. */
esp_err_t sectel_init(void);

/* Wrap payload in envelope header and send. */
esp_err_t sectel_emit(sectel_event_type_t type, const uint8_t *payload, uint16_t len);

/* Wi-Fi monitor: call BEFORE wifi_start() so the first connect is captured. */
esp_err_t sectel_wifi_monitor_start(void);

/* TLS material (PEM, NUL-terminated). Pass NULL to sectel_transport_start
 * for plain MQTT (test only). Certificate CN must equal the MQTT client_id. */
typedef struct {
    const char *ca_pem;      /* CA that signed the broker certificate */
    const char *cert_pem;    /* device certificate (mTLS) */
    const char *key_pem;     /* device private key */
} sectel_tls_t;

/* Start MQTT transport (call after Wi-Fi start). Frames queue until connected. */
esp_err_t sectel_transport_start(const char *broker_uri, const sectel_tls_t *tls);

/* SNTP: call after wifi_start(). Sets time_synced flag on each sync. */
esp_err_t sectel_time_sync_start(const char *server);

/* Set by SNTP module later; until then ts=0, flag cleared. */
void sectel_set_time_synced(bool synced);

/* Boot event */
esp_err_t sectel_boot_event_emit(void);
esp_err_t sectel_boot_tracker_start(void);

/* Heartbeat: periodic liveness + queue/heap stats */
esp_err_t sectel_heartbeat_start(uint16_t interval_s);

/* True while the MQTT transport is connected to the broker. */
bool sectel_is_connected(void);

/* Wait until the event queue is empty (all frames acknowledged), e.g. before a
 * planned restart. Returns true if empty within timeout. */
bool sectel_wait_idle(uint32_t timeout_ms);

/* OTA command channel: the agent subscribes to sectel/<client_id>/ota and passes
 * the payload (an image URL) to this handler. Keep the handler short. */
typedef void (*sectel_ota_request_cb_t)(const char *payload, size_t len);
void sectel_set_ota_request_handler(sectel_ota_request_cb_t cb);

/* OTA event. version / sha_prefix (8 bytes) describe the TARGET image; NULL if unknown. */
esp_err_t sectel_ota_event_emit(uint8_t stage, uint8_t reason, uint32_t esp_err,
                                const char *version, const uint8_t *sha_prefix);

#ifdef __cplusplus
}
#endif