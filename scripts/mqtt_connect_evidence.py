#!/usr/bin/env python3
"""
Etapa 5 (alternativa ao Wireshark) - prova que o MQTT sem TLS leva a credencial em TEXTO CLARO.

Em vez de capturar o tráfego com Npcap/Wireshark, este script abre uma conexão TCP real com o
broker local (porta 1883, sem TLS), monta e envia um pacote MQTT 3.1.1 CONNECT e mostra os bytes
EXATOS que foram para o fio: o username e a password aparecem como ASCII legível dentro do pacote.
O broker responde com CONNACK (0x20 0x02 0x00 0x00 = Connection Accepted), confirmando que foram
essas credenciais em claro que autenticaram. É a mesma evidência do F05, obtida na camada de aplicação.

A senha NÃO fica no código: venha por variável de ambiente.
  Windows (PowerShell):  $env:MQTT_PASS="<senha da frota>"
Uso:
  $env:MQTT_PASS="..."; py scripts\\mqtt_connect_evidence.py --user nexasense
"""
import argparse
import datetime as dt
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "network" / "evidence"
RAW = EVID / "raw"


def mqtt_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return len(b).to_bytes(2, "big") + b


def varlen(n: int) -> bytes:
    out = b""
    while True:
        d = n % 128
        n //= 128
        if n:
            d |= 0x80
        out += bytes([d])
        if not n:
            return out


def hexdump(data: bytes, mask_span=None) -> str:
    """hexdump clássico; mask_span=(ini,fim) troca esses bytes por '**' no hex e '·' no ASCII."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs, asc = [], []
        for i, b in enumerate(chunk):
            pos = off + i
            masked = mask_span and mask_span[0] <= pos < mask_span[1]
            hexs.append("**" if masked else f"{b:02x}")
            asc.append("·" if masked else (chr(b) if 32 <= b < 127 else "."))
        lines.append(f"  {off:04x}  {' '.join(hexs):<47}  {''.join(asc)}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--user", default="nexasense")
    ap.add_argument("--client-id", default="f05-evidence")
    args = ap.parse_args()

    password = os.environ.get("MQTT_PASS")
    if not password:
        sys.exit("Defina MQTT_PASS no ambiente (não coloque a senha no código).")

    payload = mqtt_str(args.client_id) + mqtt_str(args.user) + mqtt_str(password)
    var_header = mqtt_str("MQTT") + bytes([0x04, 0xC2]) + (30).to_bytes(2, "big")  # nível 4; flags user+pass+clean; keepalive 30
    rem = var_header + payload
    packet = bytes([0x10]) + varlen(len(rem)) + rem

    # posição da senha dentro do pacote (para mascarar na versão publicável)
    pw_bytes = password.encode()
    pw_start = packet.find(pw_bytes)
    pw_span = (pw_start, pw_start + len(pw_bytes)) if pw_start >= 0 else None

    s = socket.create_connection((args.host, args.port), timeout=5)
    s.sendall(packet)
    connack = s.recv(4)
    s.close()

    accepted = len(connack) >= 4 and connack[0] == 0x20 and connack[3] == 0x00
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    RAW.mkdir(parents=True, exist_ok=True)
    EVID.mkdir(parents=True, exist_ok=True)

    cabec = (
        f"# Evidência F05 - credencial MQTT em texto claro (sem TLS)\n"
        f"# Método: CONNECT MQTT 3.1.1 enviado por TCP ao broker {args.host}:{args.port} (sem TLS).\n"
        f"# Data: {dt.datetime.now().isoformat(timespec='seconds')}\n"
        f"# Tamanho do pacote CONNECT: {len(packet)} bytes | username='{args.user}' | password: {len(pw_bytes)} bytes\n"
        f"# Resposta do broker (CONNACK): {connack.hex(' ')}  -> {'Connection Accepted (0x00)' if accepted else 'ver código rc'}\n"
        f"# Conclusão: o broker autenticou com usuário e senha trafegando LEGÍVEIS no pacote (nenhuma cifra).\n\n"
    )

    # bruto (NÃO publicar): senha visível
    (RAW / f"f05_connect_{stamp}.txt").write_text(
        cabec + "Pacote CONNECT (bytes reais no fio):\n" + hexdump(packet) + "\n", encoding="utf-8")
    # publicável: senha mascarada no hex e no ASCII
    (EVID / f"f05_connect_{stamp}.log").write_text(
        cabec + "Pacote CONNECT (senha mascarada com **):\n" + hexdump(packet, pw_span) + "\n", encoding="utf-8")

    print(cabec)
    print("Pacote CONNECT (senha mascarada):")
    print(hexdump(packet, pw_span))
    print(f"\nBruto (não publicar): {(RAW / f'f05_connect_{stamp}.txt').relative_to(ROOT)}")
    print(f"Evidência (mascarada): {(EVID / f'f05_connect_{stamp}.log').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
