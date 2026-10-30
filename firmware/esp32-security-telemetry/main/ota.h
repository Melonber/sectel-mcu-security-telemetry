#pragma once
#include <stddef.h>

/* Called at boot: detects a pending-verify image and a previous rollback. */
void app_ota_boot_check(void);

/* Handler for the sectel OTA command channel (payload = https:// image URL). */
void app_ota_request(const char *url, size_t len);

/* If the running image is pending verification, confirm it once the device
 * has been up for 30 s AND connected to the broker; otherwise the bootloader
 * rolls back on the next restart. */
void app_ota_start_confirm_if_pending(void);