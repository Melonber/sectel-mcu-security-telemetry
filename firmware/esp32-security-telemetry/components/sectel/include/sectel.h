#pragma once
#include <stdbool.h>
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

#ifdef __cplusplus
}
#endif