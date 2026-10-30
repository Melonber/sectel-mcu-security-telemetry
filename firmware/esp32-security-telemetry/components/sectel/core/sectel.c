#include "sectel.h"
#include "envelope.h"
#include "event_queue.h"
#include "transport.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char *TAG = "sectel";

static TaskHandle_t s_sender;

static void sender_task(void *arg)
{
    (void)arg;
    uint8_t  frame[SECTEL_MAX_FRAME];
    size_t   len;
    uint32_t token;

    for (;;) {
        if (sectel_eq_peek(frame, sizeof(frame), &len, &token)) {
            if (sectel_transport_send(frame, len) == ESP_OK) {
                ESP_LOGI(TAG, "sent type=%u len=%u", frame[3], (unsigned)len);
                sectel_eq_pop(token);
            } else {
                vTaskDelay(pdMS_TO_TICKS(1000));   /* backoff, keep frame */
            }
        } else {
            ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        }
    }
}

esp_err_t sectel_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS reinit (erase)");
        err = nvs_flash_erase();
        if (err == ESP_OK) err = nvs_flash_init();
    }
    if (err != ESP_OK) return err;

    if ((err = sectel_envelope_init()) != ESP_OK) return err;
    if ((err = sectel_eq_init()) != ESP_OK) return err;

    if (xTaskCreate(sender_task, "sectel_tx", 3072, NULL, 4, &s_sender) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t sectel_emit(sectel_event_type_t type, const uint8_t *payload, uint16_t len)
{
    if (len > SECTEL_MAX_PAYLOAD || (len > 0 && payload == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t frame[SECTEL_MAX_FRAME];
    sectel_envelope_t env;
    sectel_envelope_fill(&env);
    if (sectel_eq_take_overflow()) env.flags |= SECTEL_FLAG_BUF_OVERFLOW;

    size_t off = sectel_write_header(frame, sizeof(frame), type, len, &env);
    if (off == 0) return ESP_FAIL;
    if (len > 0) memcpy(&frame[off], payload, len);

    esp_err_t err = sectel_eq_push(frame, off + len);
    if (err == ESP_OK && s_sender) xTaskNotifyGive(s_sender);
    return err;
}

bool sectel_wait_idle(uint32_t timeout_ms)
{
    uint32_t waited = 0;
    while (sectel_eq_depth() > 0 && waited < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(100));
        waited += 100;
    }
    return sectel_eq_depth() == 0;
}