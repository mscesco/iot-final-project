#!/usr/bin/env python3
"""
Etapa 4 - Evidência da UART0 (log de boot + console de diagnóstico).

Três modos:
  --from-text ARQ   importa o texto copiado do Serial Monitor do Wokwi (navegador)   <- modo principal
  --url URL         lê direto do simulador no Wokwi for VS Code (rfc2217://localhost:4000)
  --port COMx       placa física (reinicia pela linha RTS e grava o boot)

Sempre salva duas versões:
  hardware/evidence/raw/uart_<data>.log   bruto (NÃO publicar, está no .gitignore)
  hardware/evidence/uart_<data>.log       com valores de senha mascarados (publicável)

Exemplos:
  py scripts\\serial_capture.py --from-text uart_copiado.txt
  py scripts\\serial_capture.py --url rfc2217://localhost:4000 --seconds 25 --send help --send config
"""
import argparse
import datetime as dt
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "hardware" / "evidence"
RAW = EVID / "raw"
MASK_RX = re.compile(r"((?:wifi_pass|mqtt_pass|password|passwd|pwd|token|secret)\s*[=:]\s*)(\S+)", re.I)


def mask_line(line: str) -> str:
    return MASK_RX.sub(lambda m: m.group(1) + m.group(2)[:2] + "*" * max(len(m.group(2)) - 2, 0), line)


def write_pair(header, entries):
    RAW.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path, pub_path = RAW / f"uart_{stamp}.log", EVID / f"uart_{stamp}.log"
    raw_path.write_text(header + "".join(entries), encoding="utf-8")
    pub_path.write_text(header + "".join(mask_line(e) for e in entries), encoding="utf-8")
    print(f"\nBruto (não publicar): {raw_path.relative_to(ROOT)}")
    print(f"Mascarado (evidência): {pub_path.relative_to(ROOT)}")


def from_text(path):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    header = (f"# Captura UART0 importada do Serial Monitor do Wokwi\n"
              f"# arquivo de origem: {Path(path).name}  importado em {dt.datetime.now().isoformat(timespec='seconds')}\n"
              f"# parâmetros da porta simulada: 115200 8N1 (GPIO1 TX0 / GPIO3 RX0)\n")
    entries = [l + "\n" for l in lines]
    for e in entries:
        print(mask_line(e), end="")
    write_pair(header, entries)


def live(url_or_port, baud, seconds, sends, send_after, reset):
    import serial  # pyserial
    ser = serial.serial_for_url(url_or_port, baudrate=baud, timeout=0.1)
    header = (f"# Captura UART0  origem={url_or_port}  baud={baud} 8N1  inicio={dt.datetime.now().isoformat()}\n"
              f"# comandos enviados: {sends or 'nenhum'}\n")
    if reset:
        ser.dtr = False   # GPIO0 alto = boot normal
        ser.rts = True    # pulso em EN
        time.sleep(0.15)
        ser.rts = False
    t0, buf, entries, pending = time.time(), b"", [], list(sends)
    while time.time() - t0 < seconds:
        if pending and time.time() - t0 > send_after:
            cmd = pending.pop(0)
            ser.write((cmd + "\n").encode())
            entries.append(f"[{time.time() - t0:7.3f}] >>> {cmd}\n")
            print(entries[-1], end="")
            time.sleep(0.6)
        buf += ser.read(512)
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            e = f"[{time.time() - t0:7.3f}] {line.decode('utf-8', 'replace').rstrip(chr(13))}\n"
            entries.append(e)
            print(mask_line(e), end="")
    ser.close()
    write_pair(header, entries)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-text")
    src.add_argument("--url")
    src.add_argument("--port")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--seconds", type=float, default=20)
    ap.add_argument("--send", action="append", default=[])
    ap.add_argument("--send-after", type=float, default=6.0)
    a = ap.parse_args()
    if a.from_text:
        from_text(a.from_text)
    else:
        live(a.url or a.port, a.baud, a.seconds, a.send, a.send_after, reset=bool(a.port))


if __name__ == "__main__":
    main()
