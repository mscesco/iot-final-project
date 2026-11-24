# Análise do firmware (gerado por scripts/analyze_firmware.py)

- Imagem analisada: `firmware_work.bin` (871040 bytes)
- SHA-256: `d9d935b49b5c4b5dc60f130c52756a9062c65cde15e81bc2b0705047cd00a7fa`
- Tipo de imagem: aplicação isolada
- Total de strings imprimíveis (>= 6 chars): 4240
- Segredos exibidos: não, valores mascarados

## Escopo da imagem

O arquivo contém só a aplicação. Bootloader, tabela de partições e NVS não estão nele; a estrutura de partições usada pelo build é a `default.csv` do Arduino-ESP32 (nvs, otadata, app0, app1, spiffs, coredump) e está descrita em architecture/architecture.md.

## Aplicação

| Label | Tipo | Subtipo | Offset | Tamanho | Vazia | Entropia | SHA-256 (16 primeiros) |
|---|---|---|---|---|---|---|---|
| app (arquivo inteiro) | app | app | 0x000000 | 871040 | False | 7.053 | `d9d935b49b5c4b5d` |

Entropia próxima de 8 em toda a partição de app indicaria dados cifrados (Flash Encryption). Valores típicos de código não cifrado ficam entre 5 e 6,5.

## Aplicação `app (arquivo inteiro)`

- Cabeçalho válido: True  | segmentos: 5  | entry: 0x40082c90
- Hash SHA-256 anexado à imagem: True
- **Bloco de assinatura Secure Boot V2: False**
- Projeto: `arduino-lib-builder`  | versão: `esp-idf: v4.4.7 38eeba213a`  | secure_version (anti-rollback): 0
- Compilado em: Mar  5 2024 12:36:24  | IDF: `v4.4.7-dirty`

## Segredos (da NVS ou informados com --known-secret) que aparecem literalmente no binário

| Chave NVS | Valor (mascarado) | Offsets no binário |
|---|---|---|
| informado:mqtt_pass | ne************* (15 caracteres) | 0x000013c5 |

Isso indica credencial **embutida no firmware**: igual em todas as unidades que recebem a mesma imagem.

## Strings por categoria

### URLs / endpoints (0 ocorrências)


### Endereços IP (0 ocorrências)


### Tópicos MQTT / caminhos de API (33 ocorrências)

- `0x00001333` /telemetry
- `0x0000133e` /status
- `0x00001773` application/json
- `0x00003c5d` text/html
- `0x00003c8d` text/html
- `0x00003cbd` text/css
- `0x00003ced` text/plain
- `0x00003d1d` application/javascript
- `0x00003d4d` application/json
- `0x00003d7d` image/png
- `0x00003dad` image/gif
- `0x00003ddd` image/jpeg
- `0x00003e0d` image/x-icon
- `0x00003e3d` image/svg+xml
- `0x00003e6d` application/x-font-ttf
- `0x00003e9d` application/x-font-opentype
- `0x00003ecd` application/font-woff
- `0x00003efd` application/font-woff2
- `0x00003f5d` application/font-sfnt
- `0x00003f8d` text/xml
- `0x00003fbd` application/pdf
- `0x00003fed` application/zip
- `0x0000401d` application/x-gzip
- `0x0000404d` text/cache-manifest
- `0x0000407d` application/octet-stream

### Caminhos de build (vazam ambiente do desenvolvedor) (17 ocorrências)

- `0x00001a6f` @C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiClient.cpp
- `0x00001ea6` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiGeneric.cpp
- `0x00002cb1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiSTA.cpp
- `0x00003082` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/HTTPUpdate/src/HTTPUpdate.cpp
- `0x00003440` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/Preferences/src/Preferences.cpp
- `0x00003a86` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/WebServer.cpp
- `0x000040a2` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/Parsing.cpp
- `0x000043dc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/Esp.cpp
- `0x000044ae` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/HardwareSerial.cpp
- `0x000048cc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/WString.cpp
- `0x000049c1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-cpu.c
- `0x00004be5` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-gpio.c
- `0x00004ca7` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-misc.c
- `0x00004e82` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-uart.c
- `0x00004f8a` /C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/tools/sdk/esp32/include/hal/esp32/include/hal/gpio_ll.h
- `0x000160eb` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/HTTPClient/src/HTTPClient.cpp
- `0x0001654d` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/Update/src/Updater.cpp

### Credenciais / segredos (palavras-chave) (40 ocorrências)

- `0x0000135d` wifi_pass
- `0x0000137b` mqtt_user
- `0x00001385` mqtt_pass
- `0x000014d8` [boot] mqtt=%s:%u user=%s
- `0x00001682` chaves:   wifi_ssid wifi_pass mqtt_host mqtt_port mqtt_user mqtt_pass interval
- `0x00001851` wifi_pass=%s
- `0x00001879` mqtt_user=%s
- `0x00001886` mqtt_pass=%s
- `0x00001a6f` @C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiClient.cpp
- `0x00001ea6` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiGeneric.cpp
- `0x00002cb1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiSTA.cpp
- `0x00002da8` [%6u][E][%s:%u] %s(): passphrase too long!
- `0x00003082` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/HTTPUpdate/src/HTTPUpdate.cpp
- `0x00003440` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/Preferences/src/Preferences.cpp
- `0x00003a86` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/WebServer.cpp
- `0x000040a2` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/Parsing.cpp
- `0x000043dc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/Esp.cpp
- `0x000044ae` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/HardwareSerial.cpp
- `0x000048cc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/WString.cpp
- `0x000049c1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-cpu.c
- `0x00004be5` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-gpio.c
- `0x00004ca7` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-misc.c
- `0x00004e82` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-uart.c
- `0x00004f8a` /C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/tools/sdk/esp32/include/hal/esp32/include/hal/gpio_ll.h
- `0x000086b5` E (%u) %s: dhcps cb: failed to post IP_EVENT_AP_STAIPASSIGNED (%x)

### Mensagens de debug / console (33 ocorrências)

- `0x000013d5` [nexa] factory reset concluido, reiniciando...
- `0x00001460` [boot] build: %s %s
- `0x00001475` [boot] chip: %s rev %d, %d cores, flash %u bytes
- `0x000014a7` [boot] device_id=%s mac=%s
- `0x000014c3` [boot] wifi_ssid=%s
- `0x000014d8` [boot] mqtt=%s:%u user=%s
- `0x000014f3` [boot] topics: %s ¦ %s
- `0x0000150b` [boot] ota: http (sem assinatura), console de diagnostico: ATIVO
- `0x0000154c` [boot] digite 'help' para comandos de manutencao
- `0x0000157d` [wifi] conectando em %s
- `0x00001595` [wifi] ok ip=%s rssi=%d
- `0x000015ae` [wifi] falha
- `0x000015bb` [mqtt] conectando %s:%u como %s
- `0x000015eb` [mqtt] conectado
- `0x000015fc` [mqtt] falha rc=%d
- `0x00001610` comandos: help ¦ status ¦ config ¦ set <chave> <valor> ¦ save ¦ led on¦off
- `0x0000165b`           ota <url> ¦ reboot ¦ factory
- `0x00001755` [tele] %s
- `0x00001784` [ota] baixando %s
- `0x000017a0` [ota] falhou: %s
- `0x000017b2` [ota] sem atualizacao
- `0x000017c8` [ota] ok
- `0x00001814` [mqtt] rx %s %s
- `0x00001825` [mqtt] json invalido
- `0x00001925` [http] servidor de status na porta 80 (/status)

### Atualização / OTA (32 ocorrências)

- `0x00001132` update default trc: invalid ifx
- `0x0000150b` [boot] ota: http (sem assinatura), console de diagnostico: ATIVO
- `0x0000165b`           ota <url> ¦ reboot ¦ factory
- `0x00001784` [ota] baixando %s
- `0x000017a0` [ota] falhou: %s
- `0x000017b2` [ota] sem atualizacao
- `0x000017c8` [ota] ok
- `0x000023fa` GROUP_KEY_UPDATE_TIMEOUT
- `0x00002fa2` Update error: 
- `0x00003082` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/HTTPUpdate/src/HTTPUpdate.cpp
- `0x000030ed` [%6u][E][%s:%u] %s(): Update.begin failed! (%s)
- `0x00003120` [%6u][E][%s:%u] %s(): Update.setMD5 failed! (%s)
- `0x00003154` [%6u][E][%s:%u] %s(): Update.writeStream failed! (%s)
- `0x0000318d` [%6u][E][%s:%u] %s(): Update.end failed! (%s)
- `0x000031be` ESP32-http-Update
- `0x0000338f` [%6u][E][%s:%u] %s(): Update failed
- `0x00003429` runUpdate
- `0x00003433` handleUpdate
- `0x00004d3e` [%6u][E][%s:%u] %s(): OTA verification failed! Start rollback to the previous version ...
- `0x00006485` /IDF/components/app_update/esp_ota_ops.c
- `0x00006512` E (%u) %s: Rollback is not possible, do not have any suitable apps in slots
- `0x0000655f` E (%u) %s: Running firmware is factory
- `0x00006587` esp_ota_get_next_update_partition
- `0x0000a3f7` tcp_update_rcv_ann_wnd: invalid pcb
- `0x0000a8f5` tcp_update_rcv_ann_wnd

### TLS / certificados / chaves (15 ocorrências)

- `0x0000fab6` ESP_ERR_MBEDTLS_CERT_PARTLY_OK
- `0x0000fad5` ESP_ERR_MBEDTLS_CTR_DRBG_SEED_FAILED
- `0x0000fafa` ESP_ERR_MBEDTLS_SSL_SET_HOSTNAME_FAILED
- `0x0000fb22` ESP_ERR_MBEDTLS_SSL_CONFIG_DEFAULTS_FAILED
- `0x0000fb4d` ESP_ERR_MBEDTLS_SSL_CONF_ALPN_PROTOCOLS_FAILED
- `0x0000fb7c` ESP_ERR_MBEDTLS_X509_CRT_PARSE_FAILED
- `0x0000fba2` ESP_ERR_MBEDTLS_SSL_CONF_OWN_CERT_FAILED
- `0x0000fbcb` ESP_ERR_MBEDTLS_SSL_SETUP_FAILED
- `0x0000fbec` ESP_ERR_MBEDTLS_SSL_WRITE_FAILED
- `0x0000fc0d` ESP_ERR_MBEDTLS_PK_PARSE_KEY_FAILED
- `0x0000fc31` ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED
- `0x0000fc56` ESP_ERR_MBEDTLS_SSL_CONF_PSK_FAILED
- `0x0000fc7a` ESP_ERR_MBEDTLS_SSL_TICKET_SETUP_FAILED
- `0x00014402` /IDF/components/mbedtls/port/esp32/bignum.c
- `0x000148d3` /IDF/components/mbedtls/port/sha/parallel_engine/sha.c

### Versões e bibliotecas (110 ocorrências)

- `0x00000030` esp-idf: v4.4.7 38eeba213a
- `0x00000050` arduino-lib-builder
- `0x00000090` v4.4.7-dirty
- `0x00001a6f` @C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiClient.cpp
- `0x00001ea6` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiGeneric.cpp
- `0x00001f99` [%6u][E][%s:%u] %s(): Arduino Event Malloc Failed!
- `0x00001fce` [%6u][E][%s:%u] %s(): Arduino Event Send Failed!
- `0x00002111` arduino_events
- `0x00002c55` _arduino_event_cb
- `0x00002c8b` postArduinoEvent
- `0x00002cb1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WiFi/src/WiFiSTA.cpp
- `0x00003082` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/HTTPUpdate/src/HTTPUpdate.cpp
- `0x00003440` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/Preferences/src/Preferences.cpp
- `0x00003a86` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/WebServer.cpp
- `0x000040a2` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/libraries/WebServer/src/Parsing.cpp
- `0x000043dc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/Esp.cpp
- `0x000044ae` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/HardwareSerial.cpp
- `0x000048cc` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/WString.cpp
- `0x000049c1` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-cpu.c
- `0x00004be5` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-gpio.c
- `0x00004ca7` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-misc.c
- `0x00004e4e` initArduino
- `0x00004e82` C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/cores/esp32/esp32-hal-uart.c
- `0x00004f8a` /C:/Users/Usuario/.platformio/packages/framework-arduinoespressif32/tools/sdk/esp32/include/hal/esp32/include/hal/gpio_ll.h
- `0x000075be` v4.4.7-dirty
