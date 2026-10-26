#include "sectel.h"

#include <sys/time.h>
#include <time.h>

#include "esp_log.h"
#include "esp_netif_sntp.h"

static const char *TAG = "sectel_time";

/* Called by the SNTP client after each successful sync (default: hourly). */
static void on_sync(struct timeval *tv)
{
    sectel_set_time_synced(true);
    ESP_LOGI(TAG, "time synced, unix=%lld", (long long)tv->tv_sec);
}

esp_err_t sectel_time_sync_start(const char *server)
{
    if (server == NULL) return ESP_ERR_INVALID_ARG;

    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(server);
    cfg.sync_cb = on_sync;
    ESP_LOGI(TAG, "SNTP server %s", server);
    return esp_netif_sntp_init(&cfg);
}