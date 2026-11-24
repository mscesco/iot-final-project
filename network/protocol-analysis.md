# Análise das comunicações (Etapa 5)

Ambiente: Wi-Fi simulado (AP aberto `Wokwi-GUEST`, ESP32 ≈ 10.13.37.x) → gateway do Wokwi for VS Code →
broker **local** Mosquitto (`127.0.0.1`, alcançado via `host.wokwi.internal`). Como o Npcap/Wireshark
não pôde ser instalado neste ambiente, a telemetria em texto claro foi observada com
`scripts/mqtt_observer.py` e a credencial no pacote CONNECT foi evidenciada na camada de aplicação com
`scripts/mqtt_connect_evidence.py` (CONNECT MQTT por TCP sem TLS; `network/evidence/f05_connect_*.log`).
O `scripts/pcap_mqtt_summary.py` segue disponível para resumir um `.pcap` caso um adaptador de captura seja instalado.

## Fluxos observados

| Fluxo | Protocolo/porta | Origem → destino | Conteúdo | Autenticação | Criptografia | Evidência |
|---|---|---|---|---|---|---|
| Conexão MQTT | MQTT 3.1.1 / TCP 1883 | ESP32 → broker local | CONNECT: client id `nexa-000110`, keepalive, last will, **usuário e senha** | senha compartilhada | **não** | `f05_connect_*.log` (mqtt_connect_evidence.py) |
| Telemetria | PUBLISH | ESP32 → `<raiz>/<id>/telemetry` | JSON temp, hum, led, rssi, uptime, **ip, mac**, fw | herdada | não | PUBLISH no pcap, observer |
| Status | PUBLISH retain + LWT | ESP32 → `<raiz>/<id>/status` | `online`/`offline` | herdada | não | idem |
| Comando | SUBSCRIBE / PUBLISH | qualquer cliente → `<raiz>/<id>/cmd` | `led`, `interval`, `reboot`, `ota` | **nenhuma por mensagem** | não | demonstração |
| Status HTTP | TCP 80 (via net.forward :8180) | PC → ESP32 | MAC, IP, versão, host e usuário MQTT | nenhuma | não | dinâmica (`curl localhost:8180/status`) |
| OTA | HTTP | ESP32 → servidor local | `GET <url>.bin` | nenhuma | não; sem assinatura | dinâmica (GET no pcap) |

O nome `host.wokwi.internal` é resolvido pelo gateway do Wokwi (não há consulta DNS pública).
Wireshark: filtros `mqtt`, `mqtt.msgtype == 1` (CONNECT), `mqtt.topic contains "cmd"`, `http`.
No print do CONNECT, **borre o campo Password**.

## Identificar o protocolo × avaliar se o uso é seguro

Identificar (“usa MQTT na 1883”) é reconhecimento. Avaliar exige contexto:

- **Confidencialidade**: sem TLS, quem está no caminho (Wi-Fi do cliente, roteador, provedor) lê a senha no CONNECT e toda a telemetria.
- **Autenticidade do servidor**: o dispositivo não verifica com quem fala; um broker falso (DNS forjado na rede do cliente) recebe a credencial.
- **Autorização**: a senha é a mesma em toda a frota e a conta tem acesso a toda a hierarquia de tópicos; uma credencial comanda todas as unidades (demonstração controlada).
- **Integridade/frescor**: comandos sem assinatura, timestamp ou contador; um PUBLISH capturado pode ser repetido (replay, Unidade 3).
- **Identificadores expostos**: MAC e IP na telemetria permitem rastrear e mapear dispositivos.

Conclusão: o problema não é “usar MQTT”, e sim usar MQTT **sem TLS, com credencial compartilhada e sem
ACL por dispositivo**. MQTT sobre TLS, com identidade única e ACL por device id, é aceitável.

## Reteste (perfil hardened)

O reteste do perfil hardened é a configuração proposta; **não foi executado nesta avaliação** (o foco foi o
perfil `lab`). A tabela abaixo registra o resultado esperado para cada verificação.

| Verificação | Esperado | Observado |
|---|---|---|
| Porta | 8883 (TLS) | não executado |
| CONNECT legível no PCAP? | não (só registros TLS) | não executado |
| Senha no binário (`analyze_firmware --known-secret`) | não encontrada | não executado |
| `config` na UART | “comando desconhecido” | não executado |
| `{"interval":0}` no cmd | recusado | não executado |
| ACL por dispositivo | credencial de um device NÃO publica em tópico de outro (ACL `pattern %u`) | não executado |
