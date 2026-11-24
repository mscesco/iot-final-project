# Plano de hardening — NexaSense versão comercial (Etapa 8)

Princípio: cada medida responde ao mecanismo que gerou o risco, e cada uma tem um reteste.
Nada aqui exige programar eFuses na atividade; as medidas irreversíveis são propostas para a linha de produção.

## Fase 1 — Software (implementado no perfil `hardened` e retestado)

| Medida | Achados | Implementação | Reteste no laboratório virtual |
|---|---|---|---|
| Sem banner de configuração; log mínimo | F01 | perfil hardened | boot mostra só o device id (Serial Monitor + VCD) |
| Console reduzido a `status`; `provision` só em estado de fábrica | F02 | `main.cpp` | `config` → “comando desconhecido” |
| Nenhum segredo no binário; credencial entra no provisionamento | F04 | `provision <ssid> <pass> <user> <pass>` | `analyze_firmware --known-secret` não encontra a senha |
| MQTT sobre TLS (8883) com CA fixada | F05 | `WiFiClientSecure.setCACert` | captura de loopback só com registros TLS |
| Validação de parâmetros de comando (interval 5..3600) | robustez | `handleCommand` | `{"interval":0}` recusado |
| `/status` removido; OTA só HTTPS e não mais via MQTT | F07, F08 | `main.cpp` | strings do `/status` ausentes; `ota` via MQTT ignorado |
| ACL por dispositivo (`pattern ... %u`) | F06 | `lab/mosquitto/acl` | retestável: credencial de um device não publica em tópico de outro (ACL nega) |

Limitação honesta: o perfil hardened ainda roda **sem** Secure Boot e Flash Encryption.
Um dump da Flash ainda revelaria a NVS. Com credencial única por unidade (Fase 3), o impacto cai de
“frota” para “unidade”; com Flash/NVS Encryption (Fase 2), o dump deixa de ser legível. Por isso as
Fases 2 e 3 são obrigatórias antes do piloto, e o reteste deve ser repetido em placa física.

## Fase 2 — Plataforma ESP32 (proposta para produção; irreversível)

Usar chip ESP32 **revisão v3 ou superior** (ESP32-D0WD-V3, módulos -E), que tem verificações
contra fault injection na ROM e suporta Secure Boot V2 (lição do CVE-2019-17391, ver `docs/caso-real.md`).

1. **Secure Boot V2** (RSA-3072, RSA-PSS): ROM verifica o bootloader, o bootloader verifica o app,
   e o app verifica a assinatura de cada imagem OTA antes de trocar de slot. Chave privada em HSM da
   NexaHome, nunca no repositório ou na máquina de build comum. → F07, F10
2. **Flash Encryption em modo release** + **NVS Encryption**: dump físico passa a devolver dados cifrados
   com chave única por chip. → F03, F04
3. **Secure Download Mode** (ou download desabilitado): a UART da ROM deixa de permitir leitura da Flash. → F03
4. **JTAG desabilitado** por eFuse (padrão do ESP-IDF quando 1–2 estão em release). → F09
5. **Anti-rollback**: `secure_version` no app_desc, incrementado em toda correção de segurança. → F07

## Fase 3 — Processo e backend

- **Provisionamento seguro em fábrica**: certificado X.509 de cliente por dispositivo (mTLS) em vez de senha;
  registro do device id no backend; revogação individual.
- **Atualização**: OTA só iniciado pelo backend; servidor HTTPS; rollout escalonado; slot A/B com
  confirmação de boot (`esp_ota_mark_app_valid_cancel_rollback`) e retorno automático em falha.
- **Recuperação**: imagem de fábrica assinada; procedimento documentado para unidades que falharem no OTA.
- **Manufatura**: o conector UART da placa final sem header montado; pads cobertos; teste de linha que
  verifica estado dos eFuses de cada unidade antes de embalar (falha = unidade não sai).
- **Política de divulgação de vulnerabilidades** e prazo de suporte de atualizações publicados (ETSI 5.2 e 5.3).
- **Pentest de reteste** antes do piloto, repetindo os testes deste repositório.

## Matriz achado × referência

| Achado | OWASP ISTG | NIST IR 8259A | ETSI EN 303 645 | MITRE EMB3D |
|---|---|---|---|---|
| F01, F02 | ISTG-INT[UART] | Logical Access to Interfaces | 5.6-4 | TID-116 |
| F03 | ISTG-MEM | Data Protection | 5.4-1 | TID-115, TID-108 |
| F04 | ISTG-FW[INST] | Data Protection; Device Identification | 5.1, 5.4-3 | TID-328 |
| F05 | ISTG-DES | Data Protection | 5.5-1 | TID-408 |
| F06 | ISTG-DES-AUTHZ | Logical Access to Interfaces | 5.5-5 | TID-328 |
| F07 | ISTG-FW[UPDT] | Software Update | 5.3, 5.7-1 | TID-211, TID-215, TID-216 |
| F08 | ISTG-DES | Logical Access to Interfaces | 5.6-1, 5.6-2 | — |
| F09 | ISTG-PHY | Logical Access to Interfaces | 5.6-4 | TID-119 |
| F10 | ISTG-FW[INST] | Device Configuration | 5.7-1 | TID-201 |
