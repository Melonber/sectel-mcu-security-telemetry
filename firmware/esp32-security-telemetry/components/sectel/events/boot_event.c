#include "sectel.h"

#include <string.h>

#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_secure_boot.h"
#include "esp_system.h"
#include "esp_timer.h"

static const char *TAG = "sectel_boot";

#define RTC_MAGIC          0x53544C31u   /* 'STL1' */
#define TRACKER_PERIOD_US  (5 * 1000000ULL)

/* Survives SW reset, panic, WDT; garbage after power-on (magic check). */
RTC_NOINIT_ATTR static uint32_t s_rtc_magic;
RTC_NOINIT_ATTR static uint32_t s_rtc_uptime_s;

static esp_timer_handle_t s_tracker;

static uint8_t flash_enc_mode(void)
{
    if (!esp_flash_encryption_enabled()) return 0; 
    switch (esp_get_flash_encryption_mode()) {
        case ESP_FLASH_ENC_MODE_DEVELOPMENT: return 1;
        case ESP_FLASH_ENC_MODE_RELEASE:     return 2;
        default:                             return 3;
    }
}

esp_err_t sectel_boot_event_emit(void)
{
    uint8_t p[16 + SECTEL_BOOT_FW_MAX];
    size_t o = 0;

    esp_reset_reason_t reason = esp_reset_reason();
    p[o++] = (uint8_t)reason;
    p[o++] = esp_secure_boot_enabled() ? 1 : 0;
    p[o++] = flash_enc_mode();

    uint32_t last_uptime = (s_rtc_magic == RTC_MAGIC) ? s_rtc_uptime_s : 0;
    s_rtc_magic = RTC_MAGIC;   /* reset so a crash before first tick */
    s_rtc_uptime_s = 0;        /* doesn't report a stale value */
    sectel_put_u32(&p[o], last_uptime);
    o += 4;

    const esp_app_desc_t *d = esp_app_get_description();
    memcpy(&p[o], d->app_elf_sha256, 8);
    o += 8;

    size_t fw_len = strnlen(d->version, SECTEL_BOOT_FW_MAX);
    p[o++] = (uint8_t)fw_len;
    memcpy(&p[o], d->version, fw_len);
    o += fw_len;

    ESP_LOGI(TAG, "reset=%d last_uptime=%lus fw=%.*s",
             (int)reason, (unsigned long)last_uptime, (int)fw_len, d->version);

    return sectel_emit(SECTEL_EVT_BOOT, p, (uint16_t)o);
}

static void tracker_cb(void *arg)
{
    (void)arg;
    s_rtc_uptime_s = (uint32_t)(esp_timer_get_time() / 1000000LL);
}

esp_err_t sectel_boot_tracker_start(void)
{
    const esp_timer_create_args_t args = {
        .callback = &tracker_cb,
        .name = "sectel_uptime",
    };
    esp_err_t err = esp_timer_create(&args, &s_tracker);
    if (err != ESP_OK) return err;
    return esp_timer_start_periodic(s_tracker, TRACKER_PERIOD_US);
}