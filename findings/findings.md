# Achados (Etapa 7)

Cada achado segue: **evidência → fragilidade → ameaça → impacto → risco → mitigação**. A probabilidade e o
impacto são estimados para o produto físico; achados não confirmados dinamicamente estão marcados como tais.

## Critério de risco

Probabilidade considera as pré-condições (acesso físico rápido ≠ desmontagem destrutiva ≠ remoto).

| Probabilidade \ Impacto | Baixo | Médio | Alto | Crítico |
|---|---|---|---|---|
| **Alta** | Médio | Alto | Alto | Crítico |
| **Média** | Baixo | Médio | Alto | Alto |
| **Baixa** | Baixo | Baixo | Médio | Alto |

Modelo de atacante (para o produto físico): (A1) alguém com acesso físico breve a uma unidade (técnico, inquilino, unidade
comprada e devolvida); (A2) alguém na mesma rede Wi-Fi do cliente; (A3) laboratório com tempo e
equipamento (fora do escopo prático, só conceitual).

## Resumo

Validação: **D** = dinâmica no laboratório virtual; **E** = estática (binário/código); **Doc** = documental.
Probabilidade e impacto se referem ao produto físico.

| Achado | Evidência | Valid. | Impacto | Probab. | Risco | Recomendação |
|---|---|---|---|---|---|---|
| F01 Log de boot expõe configuração interna | `vcd_uart_D0.txt`, `uart_*.log` | D | Médio | Alta | **Alto** | Log mínimo em produção; ROM log silenciado |
| F02 Console de manutenção sem autenticação na UART | `vcd_uart_D1.txt` (comando) + resposta no D0 (senha mascarada) | D | Alto | Média | **Alto** | Remover console no build de produção |
| F03 Flash legível via ROM e sem criptografia | `firmware_analysis.md` (entropia, sem assinatura) | E/Doc | Alto | Média | **Alto** | Flash Encryption (release) + Secure Download Mode |
| F04 Credencial da frota embutida no firmware | `firmware_analysis.md` (valor da UART achado no binário, offset `0x13c5`) | D+E | Alto | Média | **Alto** | Credencial única por dispositivo + NVS Encryption |
| F05 MQTT sem TLS expõe senha e telemetria | `mqtt_observer_*.log` (telemetria em claro) + `f05_connect_*.log` (CONNECT com credencial legível) | D | Alto | Média | **Alto** | MQTT sobre TLS com verificação do servidor |
| F06 Uma credencial comanda qualquer unidade | `findings/evidence/demo_*.log` + vídeo do LED | D | Alto | Média | **Alto** | Identidade por dispositivo e ACL por device id |
| F07 OTA por HTTP sem assinatura e sem anti-rollback | código + strings + `secure_version=0` (teste OTA dinâmico disponível, não executado) | E | Crítico | Baixa | **Alto** | Secure Boot V2 + HTTPS + secure_version |
| F08 `/status` HTTP sem autenticação | `curl localhost:8180/status` (net.forward) + strings | D | Baixo | Alta | **Médio** | Remover endpoint ou exigir autenticação |
| F09 JTAG não desabilitado | datasheet + estado padrão de eFuses | Doc | Alto | Baixa | **Médio** | JTAG desabilitado por eFuse em produção |
| F10 Secure Boot desligado | sem bloco de assinatura no app | E | Alto | Baixa | **Médio** | Secure Boot V2 com chave da NexaHome |

---

## F01 — Log de boot expõe configuração interna

- **Ativo**: confidencialidade da configuração; arquitetura do sistema.
- **Pré-condições**: acesso físico à UART0 (no DevKit basta o cabo USB; no produto, pads/conector).
- **Fato observado** (monitor serial do simulador; decodificação elétrica do canal D0 pendente do VCD): `[boot] wifi_ssid=Wokwi-GUEST`, `[boot] mqtt=host.wokwi.internal:1883 user=nexasense`, `[boot] topics: nexahome/nexa-000110/telemetry | nexahome/nexa-000110/cmd`, `[boot] ota: http (sem assinatura), console de diagnostico: ATIVO`. Device `nexa-000110`, MAC `24:0A:C4:00:01:10`.
- **Interpretação**: o atacante aprende SSID, endereço do broker, usuário, tópicos e que há um console de manutenção, sem abrir nada além do conector.
- **Impacto**: Médio (não entrega a senha sozinho, mas guia os próximos passos). **Probabilidade**: Alta. **Risco**: Alto.
- **Referências**: ETSI EN 303 645 5.6-4 (interface de debug fisicamente acessível deve ser desabilitada em software); OWASP ISTG-INT[UART]; MITRE EMB3D TID-116 (Latent Privileged Access Port).
- **Recomendação**: build de produção com `CORE_DEBUG_LEVEL=0`, sem banner de configuração; avaliar silenciar o log da ROM (GPIO15 em nível baixo no boot ou opção de eFuse correspondente).
- **Reteste**: capturar o boot com a versão hardened e mostrar que só sai o device id.

## F02 — Console de manutenção sem autenticação

- **Pré-condições**: igual a F01.
- **Fato observado** (`serial_capture.py` injetando comandos na UART simulada via RFC2217; log mascarado `hardware/evidence/uart_20261123_222317.log`): o comando `config` foi aceito **sem qualquer autenticação** e devolveu a configuração completa — `wifi_ssid=Wokwi-GUEST`, `mqtt_host=host.wokwi.internal`, `mqtt_port=1883`, `mqtt_user=nexasense`, `mqtt_pass=ne*************` (mascarado), `interval=10`. Os comandos `set`, `ota` e `factory` existem no mesmo console sem senha (código/strings), não exercitados nesta captura.
- **Interpretação**: em poucos minutos de acesso físico obtém-se a credencial de rede da frota e é possível reconfigurar a unidade (trocar broker → redirecionar telemetria; disparar `ota`).
- **Impacto**: Alto. **Probabilidade**: Média (exige acesso físico, mas sem ferramenta especial). **Risco**: Alto.
- **Referências**: ETSI 5.6-4; NIST IR 8259A — Logical Access to Interfaces; OWASP ISTG-INT[UART]-AUTHZ; EMB3D TID-116.
- **Recomendação**: remover o console no build de produção; se for necessário em manutenção, exigir desbloqueio por desafio-resposta assinado pela NexaHome, por unidade e com registro.

## F03 — Download mode aberto e Flash sem criptografia

- **Fato observado (estático)**: o binário da aplicação tem entropia 7.05 bits/byte (abaixo de 8 → **não cifrada**; dados cifrados ficariam ~8), milhares de strings legíveis e nenhum bloco de assinatura Secure Boot V2; o firmware não habilita Flash Encryption. **Não validado dinamicamente** (sem esptool no simulador); em placa física, `read-flash 0 ALL` e `espefuse summary` confirmariam.
- **Interpretação**: qualquer pessoa com a placa e um cabo copia firmware e dados persistentes; também consegue **gravar** outro firmware.
- **Impacto**: Alto (propriedade intelectual + segredos + integridade). **Probabilidade**: Média. **Risco**: Alto.
- **Referências**: EMB3D TID-115 (Firmware/Data Extraction via Hardware Interface) e TID-108; ETSI 5.4-1; OWASP ISTG-MEM; Espressif — Flash Encryption.
- **Recomendação**: Flash Encryption em modo release + Secure Download Mode (ou download desabilitado) na linha de produção. **Não** programar eFuses durante a atividade (irreversível).

## F04 — Credenciais em texto claro e embutidas no firmware

- **Fato observado**: o valor de `mqtt_pass` lido na UART (F02) foi localizado como literal no binário no offset `0x000013c5` (`analyze_firmware.py --known-secret`, relatório `firmware/evidence/firmware_analysis.md`; imagem SHA-256 `d9d935b4…a7fa`). O código grava a configuração na NVS com `Preferences` sem criptografia (estático).
- **Interpretação**: a senha não é um segredo de dispositivo, é um segredo **da frota**. Vazou uma unidade, vazaram todas.
- **Impacto**: Alto (escala). **Probabilidade**: Média. **Risco**: Alto.
- **Referências**: ETSI 5.4-3 (parâmetros críticos hard-coded não devem ser usados) e 5.1 (sem senhas padrão universais); EMB3D TID-328 (Hardcoded Credentials); NIST IR 8259A — Data Protection.
- **Recomendação**: provisionamento em fábrica com credencial/certificado único por dispositivo; NVS Encryption; rotação e revogação no broker.

## F05 — MQTT sem TLS

- **Fato observado**: (1) o `mqtt_observer.py` (conta `analyst`, somente leitura) capturou a telemetria em **texto claro**, com MAC `24:0A:C4:00:01:10` e IP `10.13.37.2` legíveis no payload (`network/evidence/mqtt_observer_*.log`); (2) como o Npcap/Wireshark não pôde ser instalado, a credencial no fio foi evidenciada na camada de aplicação com `scripts/mqtt_connect_evidence.py`: um CONNECT MQTT 3.1.1 enviado por TCP ao broker `127.0.0.1:1883` (sem TLS) carrega `username='nexasense'` e a senha (15 bytes) em ASCII legível dentro do pacote; o broker respondeu CONNACK `20 02 00 00` (Connection Accepted). Evidência: `network/evidence/f05_connect_20261123_223749.log` (senha mascarada).
- **Impacto**: Alto. **Probabilidade**: Média (atacante A2 na mesma rede). **Risco**: Alto.
- **Referências**: EMB3D TID-408 (Unencrypted Sensitive Data Communication); ETSI 5.5-1; OWASP ISTG-DES.
- **Recomendação**: MQTT sobre TLS 1.2+ (porta 8883) com verificação do certificado do broker (CA fixada no firmware).

## F06 — Comando para qualquer unidade com a credencial compartilhada (demonstração controlada)

- **Cadeia**: F02/F04 (credencial obtida por acesso físico a uma unidade) → F05/F06 (broker aceita a credencial e a ACL libera `nexahome/#`).
- **Fato observado**: `demo_controlled.py`, usando a credencial obtida na UART, publicou `{"led":"on"}` em `<raiz>/<id>/cmd`; o LED acendeu no simulador e a telemetria refletiu `led=on`; depois restaurou `off`. Resultado: **CONFIRMADO** em 2026-11-23 22:21:17 (led off→on→off), log `findings/evidence/demo_20261123_222117.log` + vídeo `findings/evidence/demo.mp4`.
- **Impacto**: Alto (num produto real o atuador pode ser relé de climatização, alarme etc., e o mesmo canal aceita `ota`). **Probabilidade**: Média. **Risco**: Alto.
- **Referências**: ETSI 5.5-5 (mudanças de configuração via rede só após autenticação); NIST IR 8259A — Logical Access to Interfaces; OWASP ISTG-DES-AUTHZ.
- **Recomendação**: identidade única por dispositivo; ACL por padrão `%u`; comandos aceitos só de um tópico/cliente do backend; opcionalmente comandos assinados com nonce/contador contra replay.

## F07 — OTA sem autenticidade

- **Fato observado (estático)**: o código aceita `ota <url>` no console e `{"ota":...}` via MQTT, usa `httpUpdate` sobre `WiFiClient` (HTTP puro), não passa versão atual nem verifica assinatura; `secure_version = 0` e sem bloco de assinatura (`firmware/evidence/firmware_analysis.md`). O teste dinâmico é possível neste laboratório (servir um `.bin` em `http://host.wokwi.internal:8000/...` pelo servidor OTA local e capturar o `GET`), mas **não foi executado nesta avaliação**; o achado é sustentado pela análise estática (código, strings e `secure_version=0`).
- **Impacto**: Crítico (execução de código arbitrário persistente). **Probabilidade**: Baixa (precisa de console/credencial e um servidor na rede). **Risco**: Alto.
- **Referências**: EMB3D TID-211 (Unauthenticated Firmware Installation), TID-215, TID-216 (Rollbacks Allowed); ETSI 5.3 e 5.7-1; NIST IR 8259A — Software Update; OWASP ISTG-FW[UPDT].
- **Recomendação**: Secure Boot V2 (assinatura RSA-PSS verificada também no OTA), download por HTTPS, `secure_version` com anti-rollback, OTA disparado só pelo backend, slots A/B com rollback automático em falha.

## F08 — Endpoint `/status` sem autenticação

- **Fato observado (dinâmico)**: com o `[[net.forward]]` do `wokwi.toml` (`localhost:8180 -> target:80`), `curl http://localhost:8180/status` retornou, sem qualquer autenticação, JSON (salvo em `network/evidence/status_http.json`): `{"device":"nexa-000110","fw":"0.9.3-lab","mac":"24:0A:C4:00:01:10","ip":"10.13.37.2","mqtt_host":"host.wokwi.internal","mqtt_port":1883,"mqtt_user":"nexasense","uptime":723,"free_heap":241788,"chip_rev":3}`.
- **Impacto**: Baixo. **Probabilidade**: Alta. **Risco**: Médio.
- **Referências**: ETSI 5.6-1/5.6-2 (interfaces não usadas desabilitadas; mínima exposição sem autenticação).
- **Recomendação**: remover em produção (o backend já recebe status via MQTT).

## F09 — JTAG habilitado (não testado ativamente)

- **Fato observado (documental)**: o ESP32 sai de fábrica com JTAG habilitado; o protótipo não habilita Secure Boot/Flash Encryption em release, que é o que desabilitaria o JTAG por padrão. Sem teste com adaptador.
- **Impacto**: Alto. **Probabilidade**: Baixa (adaptador + conhecimento; pinos multiplexados com GPIO). **Risco**: Médio.
- **Referências**: EMB3D TID-119 (Latent Hardware Debug Port); ETSI 5.6-4.
- **Recomendação**: JTAG desabilitado por eFuse em produção (habilitar Secure Boot/Flash Encryption em release já o faz por padrão no ESP-IDF).

## F10 — Secure Boot desligado

- **Fato observado (estático)**: sem bloco de assinatura Secure Boot V2 no app (`firmware_analysis.md`).
- **Impacto**: Alto. **Probabilidade**: Baixa isoladamente (é a causa-raiz que torna F03 e F07 exploráveis). **Risco**: Médio.
- **Referências**: EMB3D TID-201 (Inadequate Bootloader Protection and Verification); ETSI 5.7-1; Espressif Secure Boot V2.
- **Recomendação**: ver plano de hardening, fase de produção.
