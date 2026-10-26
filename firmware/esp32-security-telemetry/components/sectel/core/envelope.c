#include "envelope.h"
#include "sectel.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"

static const char *TAG = "sectel_env";

#define NVS_NS        "sectel"
#define NVS_KEY_BOOT  "boot_cnt"

static uint32_t          s_boot_count;
static _Atomic uint32_t  s_seq;
static volatile bool     s_time_synced;

esp_err_t sectel_envelope_init(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    uint32_t cnt = 0;
    err = nvs_get_u32(h, NVS_KEY_BOOT, &cnt);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(h);
        return err;
    }

    s_boot_count = cnt + 1;
    err = nvs_set_u32(h, NVS_KEY_BOOT, s_boot_count);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);

    atomic_store(&s_seq, 0);
    ESP_LOGI(TAG, "boot_count=%lu", (unsigned long)s_boot_count);
    return err;
}

void sectel_set_time_synced(bool synced)
{
    s_time_synced = synced;
}

void sectel_envelope_fill(sectel_envelope_t *env)
{
    bool synced = s_time_synced;

    env->flags      = synced ? SECTEL_FLAG_TIME_SYNCED : 0;
    env->boot_count = (uint16_t)s_boot_count;
    env->seq        = atomic_fetch_add(&s_seq, 1);
    env->uptime_ms  = (uint32_t)(esp_timer_get_time() / 1000);
    env->ts         = synced ? (uint32_t)time(NULL) : 0;
}