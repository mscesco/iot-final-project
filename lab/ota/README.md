# Servidor OTA do laboratório (local)

Serve um `.bin` por HTTP simples no `127.0.0.1` do notebook, só para observar o mecanismo
de atualização inseguro do perfil `lab`. O ESP32 simulado alcança o servidor por
`host.wokwi.internal` (gateway do Wokwi for VS Code).

```powershell
# 1. compile uma versão diferente (ex.: troque NEXA_FW_VERSION para "0.9.4-lab" no platformio.ini)
cd firmware-src ; pio run -e lab
# 2. copie o binário da aplicação para esta pasta
copy .pio\build\lab\firmware.bin ..\lab\ota\nexasense-0.9.4-lab.bin
# 3. sirva a pasta (porta 8000) no notebook
cd ..\lab\ota ; py -m http.server 8000
```

Na UART da placa (ou por MQTT no tópico `cmd`):

```
ota http://host.wokwi.internal:8000/nexasense-0.9.4-lab.bin
```

O que observar e registrar em `network/protocol-analysis.md`:

- a requisição é `GET` em HTTP puro (Wireshark no loopback: filtro `http`), sem autenticação;
- o dispositivo aceita qualquer imagem válida para ESP32, sem assinatura;
- não há checagem de versão: gravar de novo a `0.9.3-lab` (mais antiga) também é aceito (rollback);
- o comando também chega por MQTT: `{"ota":"http://host.wokwi.internal:8000/..."}` no tópico `cmd`.

Faça o teste de rollback **só com imagens que você mesma compilou**. Como é tudo simulado,
reiniciar a simulação já restaura o estado; em placa física, preserve o dump original (Etapa 2)
antes de qualquer OTA.
