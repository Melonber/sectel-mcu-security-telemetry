#include "event_queue.h"
#include "sectel_wire.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef struct {
    uint16_t len;
    uint8_t  data[SECTEL_MAX_FRAME];
} slot_t;

static slot_t            s_slots[SECTEL_QUEUE_SLOTS];
static uint8_t           s_head, s_tail, s_count;
static uint32_t          s_tail_id;    /* increments on every removal */
static uint32_t          s_dropped;
static bool              s_overflow;
static SemaphoreHandle_t s_lock;

esp_err_t sectel_eq_init(void)
{
    if (s_lock) return ESP_OK;
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

static void advance_tail(void)
{
    s_tail = (s_tail + 1) % SECTEL_QUEUE_SLOTS;
    s_count--;
    s_tail_id++;
}

esp_err_t sectel_eq_push(const uint8_t *frame, size_t len)
{
    if (!s_lock) return ESP_ERR_INVALID_STATE;
    if (frame == NULL || len == 0 || len > SECTEL_MAX_FRAME) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_count == SECTEL_QUEUE_SLOTS) {
        advance_tail();
        s_dropped++;
        s_overflow = true;
    }
    s_slots[s_head].len = (uint16_t)len;
    memcpy(s_slots[s_head].data, frame, len);
    s_head = (s_head + 1) % SECTEL_QUEUE_SLOTS;
    s_count++;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

bool sectel_eq_peek(uint8_t *out, size_t cap, size_t *len, uint32_t *token)
{
    if (!s_lock) return false;
    bool ok = false;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_count > 0 && s_slots[s_tail].len <= cap) {
        *len = s_slots[s_tail].len;
        memcpy(out, s_slots[s_tail].data, *len);
        *token = s_tail_id;
        ok = true;
    }
    xSemaphoreGive(s_lock);
    return ok;
}

void sectel_eq_pop(uint32_t token)
{
    if (!s_lock) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_count > 0 && token == s_tail_id) advance_tail();
    xSemaphoreGive(s_lock);
}

uint8_t sectel_eq_depth(void)    { return s_count; }
uint32_t sectel_eq_dropped(void) { return s_dropped; }

bool sectel_eq_take_overflow(void)
{
    if (!s_lock) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool v = s_overflow;
    s_overflow = false;
    xSemaphoreGive(s_lock);
    return v;
}