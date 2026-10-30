#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "sectel.h"
#include "wifi.h"

static const char *TAG = "main";

/* Embedded via EMBED_TXTFILES in main/CMakeLists.txt (NUL-terminated) */
extern const char ca_crt_start[]     asm("_binary_ca_crt_start");
extern const char device_crt_start[] asm("_binary_device_crt_start");
extern const char device_key_start[] asm("_binary_device_key_start");

#define HEARTBEAT_INTERVAL_S 10   /* 10 s for testing, 60 s later */

void app_main(void)
{
    /* Fail-open: telemetry errors must never stop the application. */
    esp_err_t err = sectel_init();          /* also initialises NVS */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sectel_init failed: %s", esp_err_to_name(err));
        return;
    }

    if ((err = sectel_boot_event_emit()) != ESP_OK)   /* before tracker */
        ESP_LOGW(TAG, "boot event: %s", esp_err_to_name(err));
    if ((err = sectel_boot_tracker_start()) != ESP_OK)
        ESP_LOGW(TAG, "uptime tracker: %s", esp_err_to_name(err));
    if ((err = sectel_heartbeat_start(HEARTBEAT_INTERVAL_S)) != ESP_OK)
        ESP_LOGW(TAG, "heartbeat: %s", esp_err_to_name(err));

    if ((err = sectel_wifi_monitor_start()) != ESP_OK)   /* before wifi_start */
        ESP_LOGW(TAG, "wifi monitor: %s", esp_err_to_name(err));

    if ((err = wifi_start(CONFIG_SECTEL_WIFI_SSID, CONFIG_SECTEL_WIFI_PASSWORD)) != ESP_OK) {
        ESP_LOGE(TAG, "wifi: %s", esp_err_to_name(err));
        return;   /* events stay queued */
    }
    if ((err = sectel_time_sync_start(CONFIG_SECTEL_NTP_SERVER)) != ESP_OK)
        ESP_LOGW(TAG, "time sync: %s", esp_err_to_name(err));
    const sectel_tls_t tls = {
        .ca_pem = ca_crt_start, .cert_pem = device_crt_start, .key_pem = device_key_start,
    };
    if ((err = sectel_transport_start(CONFIG_SECTEL_BROKER_URI, &tls)) != ESP_OK)
        ESP_LOGE(TAG, "transport: %s", esp_err_to_name(err));

#if CONFIG_SECTEL_TEST_BOOTLOOP
    /* Test scenario 01: boot loop. Never enable in production. */
    ESP_LOGW(TAG, "TEST boot loop: restart in %d s", CONFIG_SECTEL_TEST_BOOTLOOP_DELAY_S);
    vTaskDelay(pdMS_TO_TICKS(CONFIG_SECTEL_TEST_BOOTLOOP_DELAY_S * 1000));
#if CONFIG_SECTEL_TEST_BOOTLOOP_PANIC
    abort();
#else
    esp_restart();
#endif
#endif
}