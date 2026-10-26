#pragma once
#include "esp_err.h"

/* Station mode, auto-reconnect. Requires NVS initialised (sectel_init). */
esp_err_t wifi_start(const char *ssid, const char *password);