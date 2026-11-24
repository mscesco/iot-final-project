# Mapa de interfaces físicas (Etapa 4)

Ambiente: ESP32 DevKit simulado no Wokwi (`wokwi/diagram.json`). Analisador lógico virtual:
D0 = TX0 (GPIO1), D1 = RX0 (GPIO3), D2 = GPIO4 (DHT22), GND comum.

## Tabela de interfaces

| Interface | Pinos | Observação | Evidência | O que permite | Proteção existente | Validação |
|---|---|---|---|---|---|---|
| UART0 | GPIO1 TX0, GPIO3 RX0 | baud ~115200 (leitura RFC2217 a 115200 OK; decodificação do VCD pendente) | `vcd_uart_D0.txt`, `vcd_uart_D1.txt`, `uart_20261123_222317.log`, print PulseView | ler log de boot; console sem senha (`config`, `set`, `ota`, `factory`) | nenhuma | dinâmica |
| Download mode (ROM) | GPIO0 + EN | — | documentação Espressif | ler/escrever a Flash inteira com esptool | nenhuma no protótipo (sem Secure Download Mode) | documental |
| JTAG | GPIO12 TDI, 13 TCK, 14 TMS, 15 TDO | — | datasheet ESP32 | depuração, leitura de memória, controle de execução | eFuse JTAG_DISABLE não programado no protótipo | documental |
| Flash SPI | interna ao módulo | — | `firmware_analysis.md` | leitura direta do firmware e da NVS | sem Flash Encryption (entropia normal, sem bloco de assinatura) | estática |
| Barramento do sensor | GPIO4 | pulsos do DHT22 no canal D2 `[opcional]` | print | observar/forjar leituras | nenhuma | conceitual |

## Pergunta-chave: o que a interface permite e qual o risco em produção?

**UART0.** Fato observado (monitor serial / RFC2217; decodificação elétrica do canal D0 pendente do VCD): `[boot] wifi_ssid=Wokwi-GUEST`, `[boot] mqtt=host.wokwi.internal:1883 user=nexasense`, `[boot] ota: http (sem assinatura), console de diagnostico: ATIVO`.
No canal D1 aparecem os comandos digitados (`help`, `config`), e a resposta de `config` no D0 inclui `mqtt_pass=re*******` (mascarado).
Interpretação: num produto com pads ou conector UART acessíveis, quem tiver a unidade nas mãos por poucos minutos
obtém a credencial MQTT. Como ela é a mesma em todas as unidades (F04), o impacto vai além da placa (F06).
Validação adicional necessária: repetir em hardware para confirmar acessibilidade física dos pads no gabinete final.

Por que o analisador lógico importa mesmo no simulador: o Serial Monitor mostra o que o software escreveu;
o VCD mostra o **sinal no pino**, decodificado de forma independente (baud estimado pela largura do bit).
É a mesma lógica da Unidade 1: confirmar a interface pelo comportamento elétrico, não pela suposição.

**Download mode / Flash.** O ESP32 entra no bootloader serial da ROM com GPIO0 em nível baixo no reset.
Sem Flash Encryption e sem Secure Download Mode, `esptool read-flash` copia a Flash inteira em claro.
Não exercitado no simulador; a análise do binário mostra que nada estaria cifrado (F03).

**JTAG.** Presença dos pinos não é achado por si só. O risco depende do eFuse JTAG_DISABLE e de um
adaptador; probabilidade baixa, impacto alto (F09). Registrado como documental.
