#!/usr/bin/env python3
"""
Etapa 4 - Decodifica UART a partir do arquivo VCD do analisador lógico do Wokwi.

O Wokwi baixa "wokwi-logic.vcd" ao parar a simulação (analisador com D0 = TX0, D1 = RX0, D2 = GPIO4).
Este script faz o papel do decoder UART do PulseView, de forma reproduzível:
  - mede a menor largura de bit observada e estima o baud rate (deve dar ~115200)
  - amostra cada bit no meio do período, 8N1, LSB primeiro
  - grava o texto decodificado (com senhas mascaradas) e as estatísticas do sinal

Uso:
  py scripts\\vcd_uart_decode.py wokwi-logic.vcd                 (canal D0 = TX0)
  py scripts\\vcd_uart_decode.py wokwi-logic.vcd --channel D1    (RX0: comandos digitados)
  py scripts\\vcd_uart_decode.py wokwi-logic.vcd --list          (mostra os canais do arquivo)

Saída: hardware/evidence/vcd_uart_<canal>.txt
"""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "hardware" / "evidence"
STD_BAUDS = [9600, 19200, 38400, 57600, 74880, 115200, 230400, 460800, 921600]
MASK_RX = re.compile(r"((?:wifi_pass|mqtt_pass|password|passwd|pwd|token|secret)\s*[=:]\s*)(\S+)", re.I)


def parse_vcd(path):
    timescale_s = 1e-9
    signals = {}   # id -> nome
    changes = {}   # id -> [(t, v)]
    t = 0
    in_defs = True
    scale_units = {"s": 1, "ms": 1e-3, "us": 1e-6, "ns": 1e-9, "ps": 1e-12, "fs": 1e-15}
    with open(path, "r", encoding="ascii", errors="replace") as f:
        text_iter = iter(f.read().split())
    for tok in text_iter:
        if in_defs:
            if tok == "$timescale":
                spec = ""
                for x in text_iter:
                    if x == "$end":
                        break
                    spec += x
                m = re.match(r"(\d+)\s*(\w+)", spec)
                if m:
                    timescale_s = int(m.group(1)) * scale_units.get(m.group(2), 1e-9)
            elif tok == "$var":
                parts = []
                for x in text_iter:
                    if x == "$end":
                        break
                    parts.append(x)
                # $var wire 1 <id> <nome> $end
                if len(parts) >= 4:
                    signals[parts[2]] = parts[3]
                    changes[parts[2]] = []
            elif tok == "$enddefinitions":
                in_defs = False
            continue
        if tok.startswith("#"):
            t = int(tok[1:])
        elif tok[0] in "01xXzZ" and tok[1:] in changes:
            v = 1 if tok[0] == "1" else 0
            lst = changes[tok[1:]]
            if not lst or lst[-1][1] != v:
                lst.append((t, v))
    return timescale_s, signals, changes


def decode(edges, ts, baud=None):
    """edges: lista de (t, nível). Retorna (baud_usado, bytes, largura_min_s)."""
    if len(edges) < 4:
        return baud, b"", None
    # ignora o primeiro trecho (do início da captura até a 1ª borda), que não é um bit
    widths = [(edges[i + 1][0] - edges[i][0]) * ts for i in range(1, len(edges) - 1)]
    widths = sorted(w for w in widths if w > 0)
    shortest = widths[0]
    # média das larguras de "1 bit" (até 1,5x a menor) reduz o efeito de jitter
    singles = [w for w in widths if w < shortest * 1.5]
    min_w = sum(singles) / len(singles)
    if baud is None:
        est = 1 / min_w
        baud = min(STD_BAUDS, key=lambda b: abs(b - est))
    bit = 1 / baud / ts                     # duração do bit em unidades do VCD

    def level_at(tq):
        lo, hi = 0, len(edges) - 1
        if tq < edges[0][0]:
            return 1
        while lo < hi:                      # último evento com t <= tq
            mid = (lo + hi + 1) // 2
            if edges[mid][0] <= tq:
                lo = mid
            else:
                hi = mid - 1
        return edges[lo][1]

    out = bytearray()
    i = 0
    end_t = edges[-1][0]
    while i < len(edges):
        t, v = edges[i]
        if v == 0 and (i == 0 or edges[i - 1][1] == 1):    # borda de descida = start bit
            if level_at(t + bit * 0.5) == 0:
                byte = 0
                for b in range(8):
                    byte |= level_at(t + bit * (1.5 + b)) << b
                out.append(byte)
                frame_end = t + bit * 9.5
                while i < len(edges) and edges[i][0] < frame_end:
                    i += 1
                continue
        i += 1
        if t > end_t:
            break
    return baud, bytes(out), min_w


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vcd")
    ap.add_argument("--channel", default="D0", help="nome do canal no VCD (padrão D0 = TX0)")
    ap.add_argument("--baud", type=int, help="força o baud rate (padrão: estimado)")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    ts, signals, changes = parse_vcd(a.vcd)
    if a.list or not signals:
        for sid, name in signals.items():
            print(f"{name:10s} id={sid}  transições={len(changes[sid])}")
        return
    sid = next((k for k, n in signals.items() if n == a.channel), None)
    if sid is None:
        raise SystemExit(f"Canal {a.channel} não encontrado. Use --list. Canais: {list(signals.values())}")
    edges = changes[sid]
    baud, data, min_w = decode(edges, ts, a.baud)
    text = data.decode("utf-8", "replace")
    masked = "\n".join(MASK_RX.sub(lambda m: m.group(1) + m.group(2)[:2] + "*" * max(len(m.group(2)) - 2, 0), l)
                       for l in text.splitlines())
    est = (1 / min_w) if min_w else 0
    report = (
        f"# Decodificação UART do VCD do analisador lógico\n"
        f"# arquivo: {Path(a.vcd).name}  canal: {a.channel}  timescale: {ts} s\n"
        f"# transições: {len(edges)}  menor largura de pulso: {min_w * 1e6 if min_w else 0:.3f} us "
        f"(~{est:.0f} bit/s)\n"
        f"# baud usado: {baud}  formato: 8N1, LSB primeiro, nível ocioso alto\n"
        f"# bytes decodificados: {len(data)}\n\n{masked}\n"
    )
    EVID.mkdir(parents=True, exist_ok=True)
    out = EVID / f"vcd_uart_{a.channel}.txt"
    out.write_text(report, encoding="utf-8")
    print(report[:3000])
    print(f"Evidência: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
