#!/usr/bin/env python3
"""
Etapa 2 - Preservação e identificação do firmware (aquisição lógica via ROM bootloader).

O que faz, em ordem, sem escrever nada na placa:
  1. identifica o chip e a Flash (esptool chip-id / flash-id)
  2. lê o resumo de eFuses em modo somente leitura (espefuse summary)
  3. lê a Flash inteira (read-flash 0 ALL) -> firmware/original/firmware_original.bin
  4. faz uma segunda leitura e compara os hashes (prova de leitura estável)
  5. marca o original como somente leitura, cria a cópia de trabalho em firmware/work/
  6. registra nome, tamanho, origem, data e SHA-256 em firmware/hashes.txt
     e os metadados completos em firmware/evidence/acquisition.json

Uso (Windows):  py scripts\\opcional_dump_placa_fisica.py --port COM5
Uso (Linux):    python3 scripts/opcional_dump_placa_fisica.py --port /dev/ttyUSB0

ATENÇÃO: este script NUNCA chama write-flash, erase-flash nem comandos burn do espefuse.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORIG_DIR = ROOT / "firmware" / "original"
WORK_DIR = ROOT / "firmware" / "work"
EVID_DIR = ROOT / "firmware" / "evidence"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, log_name):
    """Executa um comando, mostra a saída e salva em firmware/evidence/<log_name>."""
    print(f"\n$ {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    print(out)
    (EVID_DIR / log_name).write_text(f"$ {' '.join(cmd)}\n{out}", encoding="utf-8")
    if proc.returncode != 0:
        sys.exit(f"Falhou: {' '.join(cmd)} (rc={proc.returncode})")
    return out


def tool_version(module):
    try:
        out = subprocess.run([sys.executable, "-m", module, "version"],
                             capture_output=True, text=True).stdout.strip().splitlines()
        return out[-1] if out else "desconhecida"
    except Exception:
        return "desconhecida"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="porta serial (ex.: COM5 ou /dev/ttyUSB0)")
    ap.add_argument("--baud", default="460800")
    ap.add_argument("--name", default="firmware_original.bin")
    ap.add_argument("--analyst", default=os.environ.get("USERNAME") or os.environ.get("USER") or "")
    ap.add_argument("--skip-second-read", action="store_true",
                    help="não faz a leitura de verificação (mais rápido, menos rigoroso)")
    args = ap.parse_args()

    for d in (ORIG_DIR, WORK_DIR, EVID_DIR):
        d.mkdir(parents=True, exist_ok=True)

    original = ORIG_DIR / args.name
    if original.exists():
        sys.exit(f"{original} já existe. O original não é sobrescrito. "
                 "Mova-o manualmente se quiser repetir a aquisição.")

    esptool = [sys.executable, "-m", "esptool", "--port", args.port, "--baud", args.baud]
    espefuse = [sys.executable, "-m", "espefuse", "--port", args.port]

    chip_out = run(esptool + ["chip-id"], "01_chip_id.txt")
    flash_out = run(esptool + ["flash-id"], "02_flash_id.txt")
    run(espefuse + ["summary"], "03_efuse_summary.txt")          # somente leitura
    run(esptool + ["read-flash", "0", "ALL", str(original)], "04_read_flash.txt")

    first_hash = sha256(original)
    second_hash = None
    if not args.skip_second_read:
        verify = WORK_DIR / "verificacao_segunda_leitura.bin"
        run(esptool + ["read-flash", "0", "ALL", str(verify)], "05_read_flash_verify.txt")
        second_hash = sha256(verify)
        verify.unlink()
        if second_hash != first_hash:
            print("AVISO: as duas leituras têm hashes diferentes. Verifique cabo/alimentação e repita.")

    # original somente leitura + cópia de trabalho
    os.chmod(original, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    work_copy = WORK_DIR / "firmware_work.bin"
    shutil.copyfile(original, work_copy)
    os.chmod(work_copy, stat.S_IREAD | stat.S_IWRITE)

    def grab(text, label):
        for line in text.splitlines():
            if label in line:
                return line.split(label, 1)[1].strip(" :")
        return ""

    meta = {
        "arquivo": original.name,
        "caminho": str(original.relative_to(ROOT)),
        "tamanho_bytes": original.stat().st_size,
        "sha256": first_hash,
        "sha256_segunda_leitura": second_hash,
        "leituras_identicas": (second_hash == first_hash) if second_hash else None,
        "origem": f"Aquisição lógica da Flash SPI via ROM bootloader (UART0) - porta {args.port}",
        "metodo": "esptool read-flash 0 ALL",
        "data_analise_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "analista": args.analyst,
        "chip": grab(chip_out, "Chip type") or grab(chip_out, "Chip is"),
        "mac": grab(chip_out, "MAC"),
        "flash_detectada": grab(flash_out, "Detected flash size"),
        "ferramentas": {
            "esptool": tool_version("esptool"),
            "python": platform.python_version(),
            "sistema": f"{platform.system()} {platform.release()}",
        },
        "copia_de_trabalho": str(work_copy.relative_to(ROOT)),
        "sha256_copia_de_trabalho": sha256(work_copy),
    }
    (EVID_DIR / "acquisition.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    hashes = ROOT / "firmware" / "hashes.txt"
    with open(hashes, "a", encoding="utf-8") as f:
        f.write(
            "# Registro de integridade do firmware\n"
            f"arquivo:   {meta['arquivo']}\n"
            f"tamanho:   {meta['tamanho_bytes']} bytes\n"
            f"origem:    {meta['origem']}\n"
            f"data_utc:  {meta['data_analise_utc']}\n"
            f"chip:      {meta['chip']}  flash: {meta['flash_detectada']}\n"
            f"SHA-256:   {meta['sha256']}\n"
            f"2a leitura:{' ' + second_hash if second_hash else ' não realizada'}\n"
            f"copia:     {meta['copia_de_trabalho']}  SHA-256 {meta['sha256_copia_de_trabalho']}\n\n"
        )

    print("\n=== Aquisição concluída ===")
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    print(f"\nRegistro em {hashes.relative_to(ROOT)}. O .bin original NÃO deve ir para o repositório "
          "(contém credenciais do laboratório); ele está no .gitignore.")


if __name__ == "__main__":
    main()
