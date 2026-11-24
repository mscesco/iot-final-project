# lab/ — broker e servidor OTA locais do laboratório

O laboratório usa o **Wokwi for VS Code**: o ESP32 simulado alcança o notebook pelo gateway
embutido (`host.wokwi.internal`). Assim o broker MQTT e o servidor OTA rodam em `127.0.0.1`,
sem nenhum serviço externo.

- `mosquitto/` — broker local com senha e ACL.
  - `mosquitto.conf` — listener 1883 (lab, sem TLS) e, comentado, 8883 (reteste, TLS).
  - `acl` — ACL do protótipo (credencial `nexasense` com `readwrite nexahome/#`) e, comentada,
    a ACL hardened por dispositivo (`pattern ... %u`), recomendada para o backend da NexaHome.
  - `passwd` — arquivo de senhas (gitignored). Crie com `mosquitto_passwd` (ver `mosquitto.conf`).
  - `gen-certs.sh` — gera CA e certificado de servidor (CN/SAN `host.wokwi.internal`) para o TLS.
- `ota/` — servidor OTA HTTP local (porta 8000) para demonstrar a atualização insegura do perfil `lab`.
