#include "sectel.h"

#include <string.h>

esp_err_t sectel_ota_event_emit(uint8_t stage, uint8_t reason, uint32_t esp_err,
                                const char *version, const uint8_t *sha_prefix)
{
    uint8_t p[15 + SECTEL_OTA_VERSION_MAX];
    size_t o = 0;

    p[o++] = stage;
    p[o++] = reason;
    sectel_put_u32(&p[o], esp_err);
    o += 4;
    if (sha_prefix) memcpy(&p[o], sha_prefix, 8);
    else            memset(&p[o], 0, 8);
    o += 8;

    size_t vl = version ? strnlen(version, SECTEL_OTA_VERSION_MAX) : 0;
    p[o++] = (uint8_t)vl;
    if (vl) {
        memcpy(&p[o], version, vl);
        o += vl;
    }
    return sectel_emit(SECTEL_EVT_OTA, p, (uint16_t)o);
}