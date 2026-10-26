#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

/* Blocks until broker PUBACK (QoS 1) or timeout. ESP_OK = delivered. */
esp_err_t sectel_transport_send(const uint8_t *frame, size_t len);