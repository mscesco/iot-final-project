# Notas de análise do firmware (Etapas 2 e 3)

## 1. Preservação

| Campo | Valor |
|---|---|
| Arquivo | `firmware_original.bin` (não publicado) — nome na origem `firmware.bin` |
| Tamanho | 871040 bytes |
| Formato | imagem de aplicação ESP32 (magic 0xE9 no offset 0; sem bootloader/tabela de partições/NVS no arquivo) |
| Origem | PlatformIO `pio run -e lab` (NexaSense 0.9.3-lab), equivalente a pacote de firmware do fabricante |
| Data | 2026-11-24 (UTC) |
| SHA-256 | `d9d935b49b5c4b5dc60f130c52756a9062c65cde15e81bc2b0705047cd00a7fa` |
| Cópia de trabalho | `firmware/work/firmware_work.bin`, mesmo SHA-256 |

Fluxo: original → somente leitura + SHA-256 → cópia de trabalho → análise.
Limitação: sem aquisição física via ROM bootloader; a NVS não está no arquivo (ver `docs/limitacoes-ambiente-virtual.md`).

## 2. Formato e estrutura

Comando: `py scripts\analyze_firmware.py firmware\work\firmware_work.bin --known-secret mqtt_pass=<valor da UART>`

- Cabeçalho ESP32 válido: sim; segmentos: 5; entry point `0x40082c90`; hash SHA-256 anexado: sim.
- `esp_app_desc_t`: projeto `arduino-lib-builder`, versão `esp-idf: v4.4.7`, compilação `Mar 5 2024 12:36:24`, IDF `v4.4.7-dirty`, **secure_version = 0** (sem anti-rollback). Obs.: esses campos vêm do framework Arduino-ESP32 pré-compilado; a versão do NexaSense (`0.9.3-lab`) aparece no banner/strings, não no app_desc.
- Bloco de assinatura Secure Boot V2: **ausente**. Entropia: 7.05 bits/byte → **não cifrada** (dados cifrados ficariam ~8; milhares de strings legíveis).
- Bibliotecas por strings: Arduino-ESP32/ESP-IDF, PubSubClient, ArduinoJson, DHT, mbedTLS.

## 3. Informações relevantes

| # | Informação | Offset | Relevância |
|---|---|---|---|
| 1 | valor de `mqtt_pass` lido na UART aparece literal no binário | `0x000013c5` | credencial **embutida e compartilhada** pela frota (F04) |
| 2 | host `host.wokwi.internal` (porta 1883, tópicos `nexahome/...`) | `0x000013a7` | revela arquitetura e tópico de comando |
| 3 | lista de comandos do console (`help | status | config | set ...`) | `0x00001610` | interface de manutenção presente no build de produção (F01/F02) |
| 4 | `[boot] ota: http (sem assinatura), console ... ATIVO` | `0x0000150b` | atualização sem autenticidade (F07) |
| 5 | `[http] servidor de status na porta 80 (/status)` | `0x00001925` | endpoint de diagnóstico sem autenticação (F08) |
| 6 | caminhos de build `C:/Users/Usuario/.platformio/...` | `0x00001a6f` | vazamento do ambiente de build (expõe o usuário Windows) |

Cuidado com falso positivo: `mqtt_pass=%s` prova que existe código que **imprime** a senha, não que a senha está no binário.
O que prova o item 1 é o valor observado na UART coincidir com um literal no binário.

## 4. Mecanismo de atualização (análise estática)

- Tabela A/B (`app0`/`app1` + `otadata`): arquitetura que permite recuperação.
- Disparo: console `ota <url>` ou MQTT `{"ota":"<url>"}` no tópico de comando.
- Transporte HTTP sem TLS, sem assinatura, `secure_version` 0 e sem checagem de versão.
- Não exercitado nesta sessão (Etapa 7 opcional): no laboratório local o servidor OTA (`127.0.0.1:8000`) é alcançável pelo ESP32 via `host.wokwi.internal`, então o teste dinâmico é possível.

## 5. Ghidra (opcional)

No PlatformIO, o `.pio/build/lab/firmware.elf` tem símbolos (Xtensa:LE:32). Em Defined Strings, procure
`mqtt_pass=%s` e siga a referência até `handleSerialCommand`: a senha é impressa sem verificação de acesso.
