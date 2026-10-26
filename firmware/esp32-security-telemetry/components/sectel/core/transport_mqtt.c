#include "transport.h"
#include "tls_event.h"
#include "sectel.h"

#include <stdbool.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_tls_errors.h"
#include "mqtt_client.h"

static const char *TAG = "sectel_mqtt";

#define PUBACK_WAIT_STEPS  5      /* x 1 s */

static esp_mqtt_client_handle_t s_client;
static volatile bool            s_connected;
static volatile int             s_acked_id = -1;
static SemaphoreHandle_t        s_ack;
static char                     s_client_id[24];
static char                     s_topic[48];

/* Classify an MQTT/transport error; only TLS-level failures become evidence.
 * Observed on ESP-IDF v6: esp-tls stores the mbedTLS error as a POSITIVE value
 * (0x2700 for MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) and the X.509 verify flags
 * are not always propagated (0), so the error code is checked as well. */
#define MBEDTLS_X509_VERIFY_FAILED_ABS  0x2700

static void report_error(const esp_mqtt_error_codes_t *er)
{
    uint8_t cat = 0;
    int32_t stack = er->esp_tls_stack_err;
    int32_t stack_abs = stack < 0 ? -stack : stack;

    if (er->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
        cat = SECTEL_TLS_MQTT_REFUSED;              /* broker rejected CONNECT */
    } else if (er->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
        esp_err_t ee = er->esp_tls_last_esp_err;
        bool tcp_only = ee == ESP_ERR_ESP_TLS_CANNOT_RESOLVE_HOSTNAME ||
                        ee == ESP_ERR_ESP_TLS_CANNOT_CREATE_SOCKET ||
                        ee == ESP_ERR_ESP_TLS_UNSUPPORTED_PROTOCOL_FAMILY ||
                        ee == ESP_ERR_ESP_TLS_FAILED_CONNECT_TO_HOST ||
                        ee == ESP_ERR_ESP_TLS_SOCKET_SETOPT_FAILED ||
                        ee == ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT;
        if (er->esp_tls_cert_verify_flags != 0 ||
            stack_abs == MBEDTLS_X509_VERIFY_FAILED_ABS) {
            cat = SECTEL_TLS_CERT_VERIFY;           /* broker cert rejected */
        } else if (!tcp_only && (ee == ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED ||
                                 stack_abs != 0)) {
            cat = SECTEL_TLS_HANDSHAKE;             /* e.g. not a TLS server */
        }
    }
    if (cat == 0) return;   /* plain TCP failure: not TLS evidence */

    ESP_LOGW(TAG, "tls_error cat=%u esp_err=0x%x mbedtls=-0x%x cert_flags=0x%x rc=%d",
             cat, (unsigned)er->esp_tls_last_esp_err, (unsigned)stack_abs,
             (unsigned)er->esp_tls_cert_verify_flags, (int)er->connect_return_code);
    /* send in mbedTLS convention (negative) */
    sectel_tls_error_report(cat, (uint8_t)er->connect_return_code,
                            (uint32_t)er->esp_tls_last_esp_err, -stack_abs,
                            (uint32_t)er->esp_tls_cert_verify_flags);
}

static void on_mqtt(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;
    esp_mqtt_event_handle_t e = data;
    switch ((esp_mqtt_event_id_t)id) {
        case MQTT_EVENT_CONNECTED:
            s_connected = true;
            ESP_LOGI(TAG, "connected, topic %s", s_topic);
            sectel_tls_error_flush();   /* report failures suppressed by rate limit */
            break;
        case MQTT_EVENT_DISCONNECTED:
            s_connected = false;
            ESP_LOGW(TAG, "disconnected");
            break;
        case MQTT_EVENT_PUBLISHED:          /* PUBACK received */
            s_acked_id = e->msg_id;
            xSemaphoreGive(s_ack);
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGW(TAG, "mqtt error");
            if (e->error_handle) report_error(e->error_handle);
            break;
        default:
            break;
    }
}

esp_err_t sectel_transport_start(const char *broker_uri, const sectel_tls_t *tls)
{
    if (s_client) return ESP_ERR_INVALID_STATE;
    if (broker_uri == NULL) return ESP_ERR_INVALID_ARG;

    uint8_t mac[6];
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (err != ESP_OK) return err;
    snprintf(s_client_id, sizeof(s_client_id), "esp32-%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    snprintf(s_topic, sizeof(s_topic), "sectel/%s/ev", s_client_id);

    s_ack = xSemaphoreCreateBinary();
    if (!s_ack) return ESP_ERR_NO_MEM;

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = broker_uri,
        .credentials.client_id = s_client_id,
        .session.keepalive = 30,
        .network.reconnect_timeout_ms = 2000,   /* default 10 s delays first delivery */
    };
    if (tls) {
        cfg.broker.verification.certificate = tls->ca_pem;          /* verify broker */
        cfg.credentials.authentication.certificate = tls->cert_pem; /* prove identity */
        cfg.credentials.authentication.key = tls->key_pem;
    } else {
        ESP_LOGW(TAG, "TLS disabled: plain MQTT (test only)");
    }
    s_client = esp_mqtt_client_init(&cfg);
    if (!s_client) return ESP_FAIL;

    err = esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, on_mqtt, NULL);
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "client_id=%s broker=%s tls=%s", s_client_id, broker_uri, tls ? "mTLS" : "off");
    return esp_mqtt_client_start(s_client);
}

esp_err_t sectel_transport_send(const uint8_t *frame, size_t len)
{
    if (!s_client || !s_connected) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_ack, 0);   /* clear stale signal */
    int msg_id = esp_mqtt_client_publish(s_client, s_topic, (const char *)frame,
                                         (int)len, 1, 0);
    if (msg_id < 0) return ESP_FAIL;

    for (int i = 0; i < PUBACK_WAIT_STEPS; i++) {
        if (xSemaphoreTake(s_ack, pdMS_TO_TICKS(1000)) == pdTRUE && s_acked_id == msg_id) {
            return ESP_OK;
        }
    }
    return ESP_ERR_TIMEOUT;     /* frame stays queued; may arrive twice */
}