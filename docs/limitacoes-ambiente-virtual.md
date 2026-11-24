# Limitações do ambiente virtual e como foram tratadas

O enunciado permite “outro microcontrolador ou dispositivo equivalente, desde que possibilite a análise
dos conceitos”, e o próprio material da disciplina usa prática simulada em software. Ainda assim, um
simulador não é a placa. Esta tabela deixa explícito o que foi **validado dinamicamente**, o que foi
**analisado estaticamente** e o que ficou **só documental**. Essa separação faz parte da metodologia
(fato observado × interpretação × validação necessária).

| Teste | No laboratório virtual | Tipo de validação | Como seria na placa física |
|---|---|---|---|
| Log de boot e console na UART0 | Serial Monitor + sinal no analisador lógico (VCD decodificado) | **Dinâmica** | igual, com adaptador USB-UART/analisador real |
| Nível elétrico, GND, multímetro | não existe no simulador | Documental | medir 3,3 V no TX ocioso, continuidade de GND |
| Aquisição da Flash (`esptool read-flash`) | indisponível; firmware obtido do build (equivalente a pacote do fabricante) | Estática | `read-flash 0 ALL` via ROM bootloader |
| NVS em texto claro | indisponível no binário baixado; comprovado pelo código (`Preferences` sem criptografia) | Estática | partição `nvs` lida no dump |
| Credencial embutida no firmware | valor lido na UART localizado no binário (`--known-secret`) | **Dinâmica + estática** | idem |
| Estado de eFuses (Secure Boot, Flash Encryption, JTAG) | sem `espefuse` | Documental (padrão de fábrica = desligados) | `espefuse summary` (somente leitura) |
| MQTT sem TLS | PCAP do Wi-Fi simulado | **Dinâmica** | Wireshark na rede local |
| Uso indevido da credencial / comando | demonstração com o LED | **Dinâmica** | idem |
| OTA por HTTP | servidor OTA local (`127.0.0.1:8000`) alcançado pelo ESP32 via `host.wokwi.internal`; GET do `.bin` capturado | **Dinâmica + estática** (`secure_version=0`, sem bloco de assinatura) | OTA a partir de servidor local + captura |
| Endpoint `/status` | exposto ao PC pelo `[[net.forward]]` do `wokwi.toml` (`curl http://localhost:8180/status`) | **Dinâmica** | `curl http://<ip>/status` |
| JTAG | não simulado | Documental | adaptador JTAG |

## Efeito na classificação de risco

A probabilidade e o impacto foram estimados para o **produto físico** (o objeto da avaliação),
não para o simulador. Achados com validação só estática ou documental estão marcados assim na tabela
de `findings/findings.md`, e o reteste recomendado inclui repetir esses testes em hardware antes do piloto.

## Broker e serviços locais (nenhum serviço externo)

Todo o backend do laboratório roda no próprio notebook, em `127.0.0.1`: o broker **Mosquitto**
(porta 1883 sem TLS no perfil lab; 8883 TLS no reteste) e o **servidor OTA HTTP** (porta 8000).
O ESP32 simulado no Wokwi for VS Code os alcança pelo gateway embutido, que resolve
`host.wokwi.internal` para o PC; o `[[net.forward]]` do `wokwi.toml` expõe o `/status` do dispositivo
ao PC. Assim não há qualquer tráfego para serviços de terceiros, e as fragilidades de rede
(MQTT sem TLS, OTA por HTTP, `/status`) passam a ser **validadas dinamicamente**, não só pelo código.
A configuração de broker recomendada para produção (ACL por dispositivo, TLS) está em
`lab/mosquitto/` e é exercitada no reteste.
