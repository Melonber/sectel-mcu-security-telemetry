idf_component_register(SRCS "core/sectel.c"
                            "core/envelope.c"
                            "core/event_queue.c"
                            "core/transport_mqtt.c"
                            "core/time_sync.c"
                            "events/boot_event.c"
                            "events/heartbeat_event.c"
                            "events/wifi_event.c"
                            "events/tls_event.c"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "core"
                       PRIV_REQUIRES nvs_flash esp_timer esp_app_format
                                     bootloader_support esp_event esp_wifi esp_netif lwip esp-tls log)