#include "sectel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_mac.h"
static const char *TAG = "sectel_wifi";

/* Rate limit: at most one disconnect event per 10 s. Extra disconnects are
 * counted and reported in the next wifi event, so a flood cannot fill the
 * queue and evict older evidence (e.g. the boot event). */
#define DISC_MIN_INTERVAL_US  (10 * 1000000LL)

static uint16_t s_disc_pending;                      /* not yet reported */
static int64_t  s_last_disc_emit_us = -DISC_MIN_INTERVAL_US;
static bool     s_registered;

static void emit(uint8_t action, uint16_t reason, const uint8_t bssid[6],
                 int8_t rssi, uint8_t channel, uint8_t authmode)
{
    uint8_t p[SECTEL_WIFI_PAYLOAD_SIZE];
    uint16_t disconnects = s_disc_pending;
    s_disc_pending = 0;

    p[0] = action;
    sectel_put_u16(&p[1], reason);
    memcpy(&p[3], bssid, 6);
    p[9]  = (uint8_t)rssi;
    p[10] = channel;
    p[11] = authmode;
    sectel_put_u16(&p[12], disconnects);

    sectel_emit(SECTEL_EVT_WIFI, p, sizeof(p));
}

static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base;

    if (id == WIFI_EVENT_STA_CONNECTED) {
        const wifi_event_sta_connected_t *e = data;
        wifi_ap_record_t ap;
        int8_t rssi = (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) ? ap.rssi : 0;
        ESP_LOGI(TAG, "connected bssid=" MACSTR " ch=%u auth=%d pending_disc=%u",
                 MAC2STR(e->bssid), e->channel, (int)e->authmode, s_disc_pending);
        emit(SECTEL_WIFI_CONNECTED, 0, e->bssid, rssi, e->channel, (uint8_t)e->authmode);

    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *e = data;
        if (s_disc_pending < UINT16_MAX) s_disc_pending++;

        int64_t now = esp_timer_get_time();
        if (now - s_last_disc_emit_us >= DISC_MIN_INTERVAL_US) {
            s_last_disc_emit_us = now;
            emit(SECTEL_WIFI_DISCONNECTED, e->reason, e->bssid, e->rssi, 0, 0);
        }
    }
}

esp_err_t sectel_wifi_monitor_start(void)
{
    if (s_registered) return ESP_OK;

    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;

    err = esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, on_wifi, NULL);
    if (err != ESP_OK) return err;
    err = esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_wifi, NULL);
    if (err == ESP_OK) s_registered = true;
    return err;
}