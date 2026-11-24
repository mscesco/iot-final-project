#!/usr/bin/env python3
"""
Etapa 2 - Preservação e identificação do firmware (laboratório virtual).

Recebe o .bin baixado do Wokwi (F1 > download do firmware compilado) ou gerado pelo PlatformIO
e faz a cadeia de custódia, sem alterar o arquivo de origem:
  1. copia para firmware/original/ e marca como somente leitura
  2. calcula SHA-256 (e confere que a cópia é idêntica à origem)
  3. cria a cópia de trabalho em firmware/work/
  4. registra nome, tamanho, origem, data e SHA-256 em firmware/hashes.txt
     e os metadados completos em firmware/evidence/acquisition.json

Uso:  py scripts\\preserve_firmware.py C:\\Users\\voce\\Downloads\\sketch.ino.bin --source "Wokwi, projeto <link>"

Obs.: em placa física a aquisição seria lógica, via ROM bootloader:
      py -m esptool --port COM5 read-flash 0 ALL firmware_original.bin
      Esse caminho está documentado em docs/hardware-fisico.md.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import stat
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


def describe(path: Path) -> str:
    head = path.read_bytes()[:0x9000]
    if head[:1] == b"\xE9":
        return "imagem de aplicação ESP32 (começa com magic 0xE9 no offset 0)"
    if len(head) > 0x1000 and head[0x1000:0x1001] == b"\xE9" and head[0x8000:0x8002] == b"\xAA\x50":
        return "imagem completa da Flash (bootloader 0x1000 + tabela de partições 0x8000)"
    return "formato não reconhecido (ver analyze_firmware.py)"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="arquivo .bin a preservar")
    ap.add_argument("--source", required=True, help='origem, ex.: "Wokwi - download do firmware compilado, projeto https://wokwi.com/projects/..."')
    ap.add_argument("--name", default="firmware_original.bin")
    ap.add_argument("--analyst", default=os.environ.get("USERNAME") or os.environ.get("USER") or "")
    args = ap.parse_args()

    src = Path(args.file)
    if not src.is_file():
        sys.exit(f"Arquivo não encontrado: {src}")
    for d in (ORIG_DIR, WORK_DIR, EVID_DIR):
        d.mkdir(parents=True, exist_ok=True)
    original = ORIG_DIR / args.name
    if original.exists():
        sys.exit(f"{original} já existe. O original não é sobrescrito; mova-o se quiser repetir.")

    src_hash = sha256(src)
    shutil.copyfile(src, original)
    orig_hash = sha256(original)
    if orig_hash != src_hash:
        sys.exit("ERRO: a cópia preservada difere da origem. Repita.")
    os.chmod(original, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    work = WORK_DIR / "firmware_work.bin"
    shutil.copyfile(original, work)
    os.chmod(work, stat.S_IREAD | stat.S_IWRITE)

    meta = {
        "arquivo": original.name,
        "nome_na_origem": src.name,
        "tamanho_bytes": original.stat().st_size,
        "formato": describe(original),
        "sha256": orig_hash,
        "sha256_origem": src_hash,
        "copia_identica_a_origem": True,
        "origem": args.source,
        "metodo": "download do binário compilado (equivalente a pacote de firmware do fabricante); "
                  "aquisição física via ROM bootloader não aplicável no laboratório virtual",
        "data_analise_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "analista": args.analyst,
        "ferramentas": {"python": platform.python_version(), "sistema": f"{platform.system()} {platform.release()}"},
        "copia_de_trabalho": str(work.relative_to(ROOT)),
        "sha256_copia_de_trabalho": sha256(work),
    }
    (EVID_DIR / "acquisition.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    with open(ROOT / "firmware" / "hashes.txt", "a", encoding="utf-8") as f:
        f.write(
            "# Registro de integridade do firmware\n"
            f"arquivo:   {meta['arquivo']}  (origem: {meta['nome_na_origem']})\n"
            f"tamanho:   {meta['tamanho_bytes']} bytes\n"
            f"formato:   {meta['formato']}\n"
            f"origem:    {meta['origem']}\n"
            f"data_utc:  {meta['data_analise_utc']}\n"
            f"SHA-256:   {meta['sha256']}\n"
            f"copia:     {meta['copia_de_trabalho']}  SHA-256 {meta['sha256_copia_de_trabalho']}\n\n"
        )
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    print("\nRegistrado em firmware/hashes.txt. Próximo passo:\n"
          "  py scripts\\analyze_firmware.py firmware\\work\\firmware_work.bin")


if __name__ == "__main__":
    main()
