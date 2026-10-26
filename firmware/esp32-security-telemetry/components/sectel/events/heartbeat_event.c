#include "sectel.h"
#include "event_queue.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

static const char *TAG = "sectel_hb";

static esp_timer_handle_t s_timer;
static uint16_t           s_interval_s;

static void hb_cb(void *arg)
{
    (void)arg;
    uint8_t  p[15];
    uint8_t  depth   = sectel_eq_depth();
    uint32_t dropped = sectel_eq_dropped();
    uint32_t heap    = esp_get_free_heap_size();
    uint32_t minheap = esp_get_minimum_free_heap_size();

    sectel_put_u16(&p[0], s_interval_s);
    p[2] = depth;
    sectel_put_u32(&p[3], dropped);
    sectel_put_u32(&p[7], heap);
    sectel_put_u32(&p[11], minheap);

    ESP_LOGI(TAG, "depth=%u dropped=%lu heap=%lu min=%lu", depth,
             (unsigned long)dropped, (unsigned long)heap, (unsigned long)minheap);
    sectel_emit(SECTEL_EVT_HEARTBEAT, p, sizeof(p));
}

esp_err_t sectel_heartbeat_start(uint16_t interval_s)
{
    if (interval_s == 0) return ESP_ERR_INVALID_ARG;
    if (s_timer) return ESP_ERR_INVALID_STATE;

    s_interval_s = interval_s;
    const esp_timer_create_args_t args = {
        .callback = &hb_cb,
        .name = "sectel_hb",
    };
    esp_err_t err = esp_timer_create(&args, &s_timer);
    if (err != ESP_OK) return err;
    return esp_timer_start_periodic(s_timer, (uint64_t)interval_s * 1000000ULL);
}