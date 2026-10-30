idf_component_register(SRCS "main.c" "wifi.c" "ota.c"
                       INCLUDE_DIRS "."
                       REQUIRES sectel esp_wifi esp_netif esp_event
                                app_update esp_https_ota esp_http_client
                                esp_app_format esp_timer nvs_flash
                       EMBED_TXTFILES "certs/ca.crt" "certs/device.crt" "certs/device.key")