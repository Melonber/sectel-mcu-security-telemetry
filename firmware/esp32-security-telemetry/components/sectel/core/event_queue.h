#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define SECTEL_QUEUE_SLOTS 32

esp_err_t sectel_eq_init(void);

/* Copies frame in. If full, drops the OLDEST frame and counts it. */
esp_err_t sectel_eq_push(const uint8_t *frame, size_t len);

/* Copies oldest frame out without removing it. token identifies it. */
bool sectel_eq_peek(uint8_t *out, size_t cap, size_t *len, uint32_t *token);

/* Removes oldest frame only if it is still the one peeked (token). */
void sectel_eq_pop(uint32_t token);

uint8_t  sectel_eq_depth(void);
uint32_t sectel_eq_dropped(void);

/* True once after any drop; used to set SECTEL_FLAG_BUF_OVERFLOW. */
bool sectel_eq_take_overflow(void);