#pragma once
#include "esp_err.h"
#include "sectel_wire.h"

esp_err_t sectel_envelope_init(void);   /* loads + increments boot counter */
void sectel_envelope_fill(sectel_envelope_t *env);