idf_component_register(SRCS "main.c" "wifi.c"
                       INCLUDE_DIRS "."
                       REQUIRES sectel esp_wifi esp_netif esp_event
                       EMBED_TXTFILES "certs/ca.crt" "certs/device.crt" "certs/device.key")