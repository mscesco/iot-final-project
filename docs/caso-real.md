# Fonte de pesquisa — caso real: fault injection no ESP32 (CVE-2019-17391)

**Dispositivo analisado.** Os SoCs ESP32 das primeiras revisões (ESP32-D0WD, D2WD, S0WD e PICO-D4),
a mesma família da placa do NexaSense. A pesquisa foi feita pelo pesquisador independente
LimitedResults e divulgada de forma coordenada com a Espressif em novembro de 2019.

**Superfície de ataque.** Física: a alimentação do chip logo após o reset. Com a placa modificada,
um pulso de tensão (*voltage glitch*) cuidadosamente temporizado corrompe a leitura dos eFuses pela ROM.

**Problema.** A ROM das revisões afetadas não tinha verificações contra glitch nesse ponto.
Repetindo o ataque, era possível ler eFuses protegidos contra leitura, incluindo as chaves de
Flash Encryption e de Secure Boot (V1). Com a chave de Flash Encryption, o atacante lê e altera o
conteúdo cifrado da Flash daquela unidade; com a chave de Secure Boot, consegue gerar um bootloader
modificado aceito pelo chip. Antes disso, um ataque relacionado (CVE-2019-15894) já mostrava que
um glitch podia pular a verificação de Secure Boot. O CVSS 3.1 publicado é 4.6 (vetor físico).

**Mitigação.** Não havia correção por software para chips já fabricados, porque o defeito está na
ROM. A Espressif lançou a revisão ESP32-D0WD-V3 (e módulos “-E”) com checagens na ROM e passou a
recomendar esse chip para quem usa Flash Encryption/Secure Boot, junto com Secure Boot V2
(assinatura RSA em vez de digest com chave simétrica). O impacto foi limitado por desenho: as chaves
são únicas por chip, então o ataque compromete a unidade atacada, não a frota.

**O que o caso ensina para a NexaHome.**

1. Secure Boot e Flash Encryption são necessários, mas não absolutos contra um atacante com
   laboratório. A escolha da revisão do chip é decisão de segurança, não só de custo: exigir V3+ na compra.
2. A defesa mais valiosa foi a **chave única por dispositivo**: limitou o dano a uma placa. O NexaSense
   hoje faz o oposto (credencial MQTT igual na frota, F04/F06) — um ataque físico barato a uma unidade
   compromete todas. Corrigir isso vem antes de qualquer contramedida sofisticada.
3. Modelo de ameaça honesto: fault injection exige equipamento, tempo e destruição parcial; no
   NexaSense atual um cabo USB basta (F02, F03). A prioridade é fechar o que é barato de explorar.

**Referências.**
- Espressif, *Security Advisory Concerning Fault Injection and eFuse Protections (CVE-2019-17391)*, 01/11/2019.
- NIST NVD, CVE-2019-17391.
- Espressif, *Security Advisory Concerning Fault Injection and Secure Boot (CVE-2019-15894)*, 03/09/2019.
- Espressif, *ESP32 Fault Injection Vulnerability — Impact Analysis*, 02/01/2020.
