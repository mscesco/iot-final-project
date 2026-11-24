# Procedimento equivalente em placa física (fora do escopo da avaliação simulada)

Os testes que dependem de hardware real não foram executados; este anexo documenta como seriam
conduzidos em uma placa ESP32 DevKit física, para rastreabilidade da metodologia.

| Item | Especificação |
|---|---|
| ESP32 DevKit V1 | ESP32-WROOM-32 (de preferência -32E / chip V3), 4 MB Flash, ponte CP2102 ou CH340 |
| Sensor | módulo DHT22/AM2302 (3,3–5,5 V) no GPIO4 |
| Analisador lógico | USB 8 canais 24 MHz (compatível PulseView) |
| Outros | cabo USB de dados, jumpers, multímetro |

Passos adicionais que o hardware permite:

```
py scripts\opcional_dump_placa_fisica.py --port COM5      # chip-id, flash-id, espefuse summary, read-flash 0 ALL x2
py scripts\analyze_firmware.py firmware\work\firmware_work.bin   # agora com NVS e tabela de partições
py scripts\serial_capture.py --port COM5 --send help --send config
```

Nunca rode `espefuse burn-*`, nem habilite Secure Boot/Flash Encryption: é irreversível.
Para restaurar a placa: `py -m esptool --port COM5 write-flash 0 firmware\original\firmware_original.bin`.
A configuração de broker local (Mosquitto + ACL) e o servidor OTA ficam em `lab/`.
