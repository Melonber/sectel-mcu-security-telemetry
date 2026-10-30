#include "ota.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "sectel.h"

static const char *TAG = "app_ota";

/* Same CA as the broker: the OTA server uses a certificate from the project PKI. */
extern const char ca_crt_start[] asm("_binary_ca_crt_start");

#define CONFIRM_MIN_UPTIME_S  30
#define CONFIRM_TIMEOUT_S     180

static char         s_url[256];
static TaskHandle_t s_task;
static bool         s_pending_verify;

static void emit(uint8_t stage, uint8_t reason, esp_err_t err, const esp_app_desc_t *d)
{
    ESP_LOGI(TAG, "ota stage=%u reason=%u err=0x%x version=%s",
             stage, reason, (unsigned)err, d ? d->version : "-");
    sectel_ota_event_emit(stage, reason, (uint32_t)err,
                          d ? d->version : NULL, d ? d->app_elf_sha256 : NULL);
}

/* Compare "MAJOR.MINOR.PATCH". Returns -1, 0, 1, or -2 if either is unparsable. */
static int semver_cmp(const char *a, const char *b)
{
    unsigned a1, a2, a3, b1, b2, b3;
    if (sscanf(a, "%u.%u.%u", &a1, &a2, &a3) != 3 ||
        sscanf(b, "%u.%u.%u", &b1, &b2, &b3) != 3) return -2;
    if (a1 != b1) return a1 > b1 ? 1 : -1;
    if (a2 != b2) return a2 > b2 ? 1 : -1;
    if (a3 != b3) return a3 > b3 ? 1 : -1;
    return 0;
}

static void ota_task(void *arg)
{
    (void)arg;
    const esp_app_desc_t *cur = esp_app_get_description();
    esp_https_ota_handle_t h = NULL;
    esp_app_desc_t nd;
    esp_err_t err;
    int cmp;

    emit(SECTEL_OTA_START, SECTEL_OTA_R_NONE, ESP_OK, NULL);

    esp_http_client_config_t http = {
        .url = s_url,
        .cert_pem = ca_crt_start,        /* server must present a project-PKI cert */
        .timeout_ms = 15000,
        .keep_alive_enable = true,
    };
    esp_https_ota_config_t cfg = { .http_config = &http };

    err = esp_https_ota_begin(&cfg, &h);
    if (err != ESP_OK) {
        emit(SECTEL_OTA_FAILED, SECTEL_OTA_R_DOWNLOAD, err, NULL);
        goto done;
    }

    /* Header checks BEFORE downloading the whole image */
    err = esp_https_ota_get_img_desc(h, &nd);
    if (err != ESP_OK) {
        emit(SECTEL_OTA_FAILED, SECTEL_OTA_R_IMAGE_INVALID, err, NULL);
        esp_https_ota_abort(h);
        goto done;
    }
    if (strncmp(nd.project_name, cur->project_name, sizeof(nd.project_name)) != 0) {
        emit(SECTEL_OTA_REJECTED, SECTEL_OTA_R_WRONG_PROJECT, ESP_OK, &nd);
        esp_https_ota_abort(h);
        goto done;
    }
    cmp = semver_cmp(nd.version, cur->version);
    if (cmp != 1) {        /* software anti-rollback: only strictly newer versions */
        uint8_t reason = cmp == -2 ? SECTEL_OTA_R_VERSION_UNPARSABLE
                       : cmp == 0  ? SECTEL_OTA_R_SAME_VERSION
                                   : SECTEL_OTA_R_DOWNGRADE;
        emit(SECTEL_OTA_REJECTED, reason, ESP_OK, &nd);
        esp_https_ota_abort(h);
        goto done;
    }

    while ((err = esp_https_ota_perform(h)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
    }
    if (err != ESP_OK || !esp_https_ota_is_complete_data_received(h)) {
        emit(SECTEL_OTA_FAILED, SECTEL_OTA_R_DOWNLOAD, err != ESP_OK ? err : ESP_FAIL, &nd);
        esp_https_ota_abort(h);
        goto done;
    }

    /* Verifies image integrity and (with signed apps enabled) the signature,
     * then sets the boot partition. Frees the handle in all cases. */
    err = esp_https_ota_finish(h);
    if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
        emit(SECTEL_OTA_REJECTED, SECTEL_OTA_R_VALIDATION, err, &nd);
        goto done;
    }
    if (err != ESP_OK) {
        emit(SECTEL_OTA_FAILED, SECTEL_OTA_R_IMAGE_INVALID, err, &nd);
        goto done;
    }

    emit(SECTEL_OTA_APPLIED, SECTEL_OTA_R_NONE, ESP_OK, &nd);
    sectel_wait_idle(10000);           /* deliver the 'applied' event first */
    esp_restart();

done:
    s_task = NULL;
    vTaskDelete(NULL);
}

void app_ota_request(const char *url, size_t len)
{
    if (s_task) {
        ESP_LOGW(TAG, "OTA already running, request ignored");
        return;
    }
    if (len < 8 || len >= sizeof(s_url)) {
        ESP_LOGW(TAG, "invalid OTA request (len=%u)", (unsigned)len);
        return;
    }
    if (strncmp(url, "https://", 8) != 0) {
        emit(SECTEL_OTA_REJECTED, SECTEL_OTA_R_INSECURE_URL, ESP_OK, NULL);
        return;
    }
    memcpy(s_url, url, len);
    s_url[len] = '\0';
    ESP_LOGI(TAG, "OTA requested: %s", s_url);
    if (xTaskCreate(ota_task, "app_ota", 8192, NULL, 5, &s_task) != pdPASS) {
        s_task = NULL;
        ESP_LOGE(TAG, "cannot start OTA task");
    }
}

void app_ota_boot_check(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    if (run && esp_ota_get_state_partition(run, &st) == ESP_OK &&
        st == ESP_OTA_IMG_PENDING_VERIFY) {
        s_pending_verify = true;
        ESP_LOGW(TAG, "running image is pending verification");
    }

    /* Report a rollback once: remember which invalid image was already reported */
    const esp_partition_t *inv = esp_ota_get_last_invalid_partition();
    esp_app_desc_t d;
    if (inv && esp_ota_get_partition_description(inv, &d) == ESP_OK) {
        uint32_t tag, seen = 0;
        memcpy(&tag, d.app_elf_sha256, sizeof(tag));
        nvs_handle_t nh;
        if (nvs_open("sectel_ota", NVS_READWRITE, &nh) == ESP_OK) {
            nvs_get_u32(nh, "rb_seen", &seen);
            if (seen != tag) {
                emit(SECTEL_OTA_ROLLBACK, SECTEL_OTA_R_NONE, ESP_OK, &d);
                nvs_set_u32(nh, "rb_seen", tag);
                nvs_commit(nh);
            }
            nvs_close(nh);
        }
    }
}

static void confirm_task(void *arg)
{
    (void)arg;
    for (int i = 0; i < CONFIRM_TIMEOUT_S; i++) {
        bool up = esp_timer_get_time() / 1000000 >= CONFIRM_MIN_UPTIME_S;
        if (up && sectel_is_connected()) {
            if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
                s_pending_verify = false;
                emit(SECTEL_OTA_CONFIRMED, SECTEL_OTA_R_NONE, ESP_OK, esp_app_get_description());
            }
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    vTaskDelete(NULL);   /* not confirmed: next restart rolls back */
}

void app_ota_start_confirm_if_pending(void)
{
    if (s_pending_verify) {
        xTaskCreate(confirm_task, "ota_confirm", 3072, NULL, 4, NULL);
    }
}