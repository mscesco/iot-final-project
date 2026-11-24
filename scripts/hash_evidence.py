#!/usr/bin/env python3
"""
Gera EVIDENCE_MANIFEST.sha256 com o SHA-256 de todas as evidências publicáveis.
Rode no fim da avaliação; quem corrigir pode conferir com --verify.

Uso:  py scripts\\hash_evidence.py            (gera)
      py scripts\\hash_evidence.py --verify   (confere)
"""
import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = ["architecture", "firmware/evidence", "hardware/evidence", "network/evidence", "findings"]
SKIP_PARTS = {"raw"}
MANIFEST = ROOT / "EVIDENCE_MANIFEST.sha256"


def files():
    for folder in FOLDERS:
        for p in sorted((ROOT / folder).rglob("*")):
            if p.is_file() and not SKIP_PARTS.intersection(p.relative_to(ROOT).parts) and p.name != ".gitkeep":
                yield p


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    if a.verify:
        bad = 0
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            h, rel = line.split("  ", 1)
            p = ROOT / rel
            ok = p.exists() and digest(p) == h
            bad += not ok
            print(f"{'OK  ' if ok else 'FALHA'} {rel}")
        sys.exit(1 if bad else 0)
    lines = [f"{digest(p)}  {p.relative_to(ROOT).as_posix()}" for p in files()]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(lines)} arquivos registrados em {MANIFEST.name}")


if __name__ == "__main__":
    main()
