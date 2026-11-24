#!/usr/bin/env python3
"""
Etapa 3 - Análise básica de uma imagem de Flash completa do ESP32 (sem executar nada).

Trabalha SEMPRE sobre a cópia de trabalho. Produz:
  firmware/work/partitions/*.bin         partições extraídas (local, não publicar)
  firmware/work/strings_all.txt          todas as strings (local, não publicar)
  firmware/evidence/firmware_analysis.md relatório com segredos MASCARADOS (publicável)
  firmware/evidence/firmware_analysis.json

O que é analisado:
  - tabela de partições (0x8000) e hash de cada partição
  - cabeçalho da imagem da aplicação e esp_app_desc_t (versão, projeto, data, IDF)
  - presença de hash anexado e de bloco de assinatura Secure Boot V2
  - entropia (indício de Flash Encryption: dados cifrados têm entropia ~8 bits/byte)
  - otadata (qual slot OTA está ativo)
  - partição NVS: namespaces, chaves e valores (ex.: credenciais gravadas em texto claro)
  - strings classificadas: URLs, IPs, tópicos MQTT, palavras de credencial, mensagens de debug, OTA, TLS

Uso:  py scripts\\analyze_firmware.py firmware\\work\\firmware_work.bin
      py scripts\\analyze_firmware.py firmware\\work\\firmware_work.bin --show-secrets   (só na tela)
"""
import argparse
import hashlib
import json
import math
import re
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "firmware" / "work"
EVID = ROOT / "firmware" / "evidence"

PART_TABLE_OFFSET = 0x8000
TYPE_NAMES = {0x00: "app", 0x01: "data"}
APP_SUBTYPES = {0x00: "factory", 0x20: "test"} | {0x10 + i: f"ota_{i}" for i in range(16)}
DATA_SUBTYPES = {0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump", 0x04: "nvs_keys",
                 0x05: "efuse", 0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"}

SENSITIVE_KEY = re.compile(r"pass|pwd|secret|token|key|psk|cred", re.I)


# ------------------------------------------------------------------ utilidades
def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("latin-1", "replace")


def mask(value: str) -> str:
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 2)} ({len(value)} caracteres)"


# ------------------------------------------------------------------ partições
def parse_partition_table(img: bytes):
    parts = []
    table = img[PART_TABLE_OFFSET:PART_TABLE_OFFSET + 0xC00]
    md5_ok = None
    for i in range(0, len(table), 32):
        e = table[i:i + 32]
        magic = e[:2]
        if magic == b"\xEB\xEB":  # entrada MD5
            md5_ok = hashlib.md5(table[:i]).digest() == e[16:32]
            continue
        if magic != b"\xAA\x50":
            break
        ptype, subtype = e[2], e[3]
        offset, size = struct.unpack_from("<II", e, 4)
        label = cstr(e[12:28])
        flags = struct.unpack_from("<I", e, 28)[0]
        st = (APP_SUBTYPES if ptype == 0 else DATA_SUBTYPES).get(subtype, hex(subtype))
        parts.append({"label": label, "type": TYPE_NAMES.get(ptype, hex(ptype)), "subtype": st,
                      "offset": offset, "size": size, "encrypted_flag": bool(flags & 1)})
    return parts, md5_ok


# ------------------------------------------------------------------ imagem de app
def parse_app_image(data: bytes):
    info = {"valid": False}
    if len(data) < 24 or data[0] != 0xE9:
        info["note"] = "sem magic 0xE9 (vazia, apagada ou cifrada)"
        return info
    seg_count = data[1]
    entry = struct.unpack_from("<I", data, 4)[0]
    chip_id = struct.unpack_from("<H", data, 12)[0]
    hash_appended = data[23] == 1
    info.update({"valid": True, "segments": seg_count, "entry_point": hex(entry),
                 "chip_id": chip_id, "hash_appended": hash_appended})
    pos = 24
    first_seg_data = None
    for s in range(seg_count):
        if pos + 8 > len(data):
            break
        load, length = struct.unpack_from("<II", data, pos)
        if s == 0:
            first_seg_data = data[pos + 8:pos + 8 + length]
        pos += 8 + length
    pos += 1                         # checksum
    pos = (pos + 15) & ~15           # alinhamento de 16 bytes
    if hash_appended:
        pos += 32
    info["image_length"] = pos
    # Secure Boot V2: bloco de assinatura no próximo limite de 4 KB (magic 0xE7, versão 0x02)
    sig_pos = (pos + 0xFFF) & ~0xFFF
    sig = data[sig_pos:sig_pos + 4]
    info["secure_boot_v2_signature_block"] = len(sig) == 4 and sig[0] == 0xE7 and sig[1] == 0x02
    # esp_app_desc_t no início do primeiro segmento
    if first_seg_data and len(first_seg_data) >= 256:
        magic = struct.unpack_from("<I", first_seg_data, 0)[0]
        if magic == 0xABCD5432:
            info["app_desc"] = {
                "secure_version": struct.unpack_from("<I", first_seg_data, 4)[0],
                "version": cstr(first_seg_data[16:48]),
                "project_name": cstr(first_seg_data[48:80]),
                "compile_time": cstr(first_seg_data[80:96]),
                "compile_date": cstr(first_seg_data[96:112]),
                "idf_ver": cstr(first_seg_data[112:144]),
                "elf_sha256_prefix": first_seg_data[144:152].hex(),
            }
    return info


def parse_otadata(data: bytes):
    out = []
    for off in (0, 0x1000):
        e = data[off:off + 32]
        if len(e) < 32:
            continue
        seq = struct.unpack_from("<I", e, 0)[0]
        state = struct.unpack_from("<I", e, 24)[0]
        crc = struct.unpack_from("<I", e, 28)[0]
        # ESP-IDF: esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4), equivalente a zlib.crc32(dados, 0xFFFFFFFF)
        valid = seq != 0xFFFFFFFF and zlib.crc32(e[0:4], 0xFFFFFFFF) == crc
        out.append({"offset": hex(off), "ota_seq": seq if seq != 0xFFFFFFFF else None,
                    "state": hex(state), "crc_ok": valid})
    seqs = [o["ota_seq"] for o in out if o["crc_ok"] and o["ota_seq"]]
    active = None
    if seqs:
        active = f"ota_{(max(seqs) - 1) % 2}"
    return {"entries": out, "active_slot_guess": active or "factory/ota_0 (otadata vazio)"}


# ------------------------------------------------------------------ NVS
NVS_TYPES = {0x01: "u8", 0x11: "i8", 0x02: "u16", 0x12: "i16", 0x04: "u32", 0x14: "i32",
             0x08: "u64", 0x18: "i64", 0x21: "str", 0x41: "blob", 0x42: "blob_data", 0x48: "blob_idx"}
INT_FMT = {0x01: "<B", 0x11: "<b", 0x02: "<H", 0x12: "<h", 0x04: "<I", 0x14: "<i", 0x08: "<Q", 0x18: "<q"}


def parse_nvs(data: bytes):
    """Leitor simplificado do formato NVS (páginas de 4 KB, entradas de 32 bytes)."""
    namespaces = {0: "<root>"}
    entries = []
    pages_active = 0
    for p in range(0, len(data) - 4095, 4096):
        page = data[p:p + 4096]
        state = struct.unpack_from("<I", page, 0)[0]
        if state in (0xFFFFFFFF,):        # página vazia
            continue
        if state not in (0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8):   # ativa, cheia, liberando
            continue
        pages_active += 1
        bitmap = page[32:64]
        i = 0
        while i < 126:
            bits = (bitmap[i // 4] >> ((i % 4) * 2)) & 0b11
            if bits != 0b10:              # só entradas "written"
                i += 1
                continue
            e = page[64 + i * 32:64 + (i + 1) * 32]
            ns, etype, span = e[0], e[1], e[2]
            key = cstr(e[8:24])
            raw = e[24:32]
            span = max(span, 1)
            value = None
            if etype in INT_FMT:
                value = struct.unpack_from(INT_FMT[etype], raw)[0]
                if ns == 0:               # definição de namespace
                    namespaces[value] = key
            elif etype == 0x21:
                size = struct.unpack_from("<H", raw, 0)[0]
                payload = page[64 + (i + 1) * 32:64 + (i + span) * 32]
                value = payload[:size].rstrip(b"\x00").decode("utf-8", "replace")
            elif etype in (0x41, 0x42):
                size = struct.unpack_from("<H", raw, 0)[0]
                payload = page[64 + (i + 1) * 32:64 + (i + span) * 32]
                value = payload[:size].hex()
            elif etype == 0x48:
                value = f"blob_idx size={struct.unpack_from('<I', raw, 0)[0]}"
            if ns != 0:
                entries.append({"ns_index": ns, "key": key, "type": NVS_TYPES.get(etype, hex(etype)),
                                "value": value})
            i += span
    for e in entries:
        e["namespace"] = namespaces.get(e.pop("ns_index"), "?")
    return {"active_pages": pages_active, "entries": entries}


# ------------------------------------------------------------------ strings
CATEGORIES = [
    ("URLs / endpoints", re.compile(r"(https?|mqtts?|wss?|coap)://[\w\-.:/%?#=&@]+", re.I)),
    ("Endereços IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("Tópicos MQTT / caminhos de API", re.compile(r"^(?!.*://)(?!.*\.(c|cpp|h|hpp)$)(?!/home/|/Users/|[A-Z]:\\)"
                                               r"(?:[\w\-]+/(?:[\w\-+#%]*/?)*|/[\w\-]+(?:/[\w\-]+)*)$")),
    ("Caminhos de build (vazam ambiente do desenvolvedor)", re.compile(r"(/home/|/Users/|[A-Z]:\\\\?|\.platformio|\.arduino15).*", re.I)),
    ("Credenciais / segredos (palavras-chave)", re.compile(r"pass|pwd|secret|token|apikey|api_key|psk|credential|user", re.I)),
    ("Mensagens de debug / console", re.compile(r"\[(boot|debug|mqtt|wifi|ota|cmd|tele|http|nexa)\]|debug|console|help|factory|comandos", re.I)),
    ("Atualização / OTA", re.compile(r"\bota\b|update|firmware|httpUpdate|rollback", re.I)),
    ("TLS / certificados / chaves", re.compile(r"BEGIN (CERTIFICATE|PRIVATE KEY|RSA)|setCACert|x509|mbedtls", re.I)),
    ("Versões e bibliotecas", re.compile(r"v\d+\.\d+(\.\d+)?|esp-idf|arduino|PubSubClient|ArduinoJson|DHT|lwip|mbedtls", re.I)),
]


def extract_strings(data: bytes, base: int, min_len=6):
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        yield base + m.start(), m.group().decode("ascii")


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="cópia de trabalho da Flash completa (ex.: firmware/work/firmware_work.bin)")
    ap.add_argument("--show-secrets", action="store_true", help="mostra segredos sem máscara APENAS no terminal")
    ap.add_argument("--max-per-category", type=int, default=25)
    ap.add_argument("--known-secret", action="append", default=[], metavar="NOME=VALOR",
                    help="valor observado em outra evidência (ex.: senha lida na UART) para localizar no binário; "
                         "sai mascarado no relatório. Repetível.")
    args = ap.parse_args()

    img_path = Path(args.image)
    img = img_path.read_bytes()
    (WORK / "partitions").mkdir(parents=True, exist_ok=True)
    EVID.mkdir(parents=True, exist_ok=True)

    result = {"image": img_path.name, "size": len(img), "sha256": sha256(img)}
    print(f"Imagem: {img_path}  {len(img)} bytes  SHA-256 {result['sha256']}")

    app_only = img[:1] == b"\xE9"
    result["mode"] = "aplicação isolada" if app_only else "Flash completa"
    if app_only:
        # Binário só da aplicação (ex.: download do Wokwi ou .pio/build/<env>/firmware.bin):
        # não há bootloader, tabela de partições nem NVS no arquivo.
        result["bootloader"] = {"valid": None, "note": "não presente no arquivo (imagem só de aplicação)"}
        parts = [{"label": "app (arquivo inteiro)", "type": "app", "subtype": "app", "offset": 0,
                  "size": len(img), "encrypted_flag": False}]
        md5_ok = None
        print("Imagem só de aplicação detectada (magic 0xE9 no offset 0).")
    else:
        result["bootloader"] = parse_app_image(img[0x1000:0x8000])
        result["bootloader"]["entropy"] = round(entropy(img[0x1000:0x8000]), 3)
        parts, md5_ok = parse_partition_table(img)
        if not parts:
            print("Tabela de partições não encontrada em 0x8000 (imagem parcial ou cifrada?).")
    result["partition_table_md5_ok"] = md5_ok
    secrets = {}
    for ks in args.known_secret:
        name, _, val = ks.partition("=")
        if val:
            secrets[val] = f"informado:{name}"
    for p in parts:
        blob = img[p["offset"]:p["offset"] + p["size"]]
        p["sha256"] = sha256(blob)
        p["entropy"] = round(entropy(blob.rstrip(b"\xff")), 3)
        p["empty"] = blob.count(0xFF) == len(blob)
        (WORK / "partitions" / f"{p['label']}.bin").write_bytes(blob)
        if p["type"] == "app" and not p["empty"]:
            p["image"] = parse_app_image(blob)
        if p["subtype"] == "ota":
            p["otadata"] = parse_otadata(blob)
        if p["subtype"] == "nvs":
            p["nvs"] = parse_nvs(blob)
            for e in p["nvs"]["entries"]:
                if isinstance(e["value"], str) and SENSITIVE_KEY.search(e["key"]) and e["value"]:
                    secrets[e["value"]] = f"{e['namespace']}.{e['key']}"
    result["partitions"] = parts

    # strings (somente regiões com dados: bootloader + partições app)
    all_strings = [] if app_only else list(extract_strings(img[0x1000:0x8000], 0x1000))
    for p in parts:
        if p["type"] == "app" and not p["empty"]:
            all_strings += list(extract_strings(img[p["offset"]:p["offset"] + p["size"]], p["offset"]))
    with open(WORK / "strings_all.txt", "w", encoding="utf-8") as f:
        for off, s in all_strings:
            f.write(f"0x{off:08x}  {s}\n")

    def safe(s: str) -> str:
        if args.show_secrets:
            return s
        for val, where in secrets.items():
            if val and val in s:
                s = s.replace(val, f"<{where}: {mask(val)}>")
        return s

    cats = {}
    for name, rx in CATEGORIES:
        hits = [(off, s) for off, s in all_strings if rx.search(s)]
        cats[name] = {"total": len(hits), "exemplos": [(f"0x{o:08x}", safe(s)) for o, s in hits[:args.max_per_category]]}
    result["strings_total"] = len(all_strings)
    result["string_categories"] = cats

    # segredos da NVS que também aparecem literalmente no binário da aplicação
    hardcoded = []
    for val, where in secrets.items():
        offs = [o for o, s in all_strings if val in s]
        if offs:
            hardcoded.append({"nvs_key": where, "value_masked": mask(val),
                              "found_in_app_at": [f"0x{o:08x}" for o in offs[:5]]})
    result["secrets_also_in_app_binary"] = hardcoded

    (EVID / "firmware_analysis.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=lambda x: safe(str(x))), encoding="utf-8")
    write_markdown(result, secrets, args.show_secrets)
    print(f"\nRelatório: {(EVID / 'firmware_analysis.md').relative_to(ROOT)}")
    print(f"Strings brutas (NÃO publicar): {(WORK / 'strings_all.txt').relative_to(ROOT)}")


def write_markdown(r, secrets, show):
    L = []
    w = L.append
    w("# Análise do firmware (gerado por scripts/analyze_firmware.py)\n")
    w(f"- Imagem analisada: `{r['image']}` ({r['size']} bytes)")
    w(f"- SHA-256: `{r['sha256']}`")
    w(f"- Tipo de imagem: {r.get('mode')}")
    w(f"- Total de strings imprimíveis (>= 6 chars): {r['strings_total']}")
    w(f"- Segredos exibidos: {'SIM (não publique este arquivo)' if show else 'não, valores mascarados'}\n")

    b = r["bootloader"]
    if r.get("mode") == "aplicação isolada":
        w("## Escopo da imagem\n")
        w("O arquivo contém só a aplicação. Bootloader, tabela de partições e NVS não estão nele; "
          "a estrutura de partições usada pelo build é a `default.csv` do Arduino-ESP32 "
          "(nvs, otadata, app0, app1, spiffs, coredump) e está descrita em architecture/architecture.md.\n")
        w("## Aplicação\n")
    else:
        w("## Bootloader (0x1000)\n")
        w(f"- Imagem válida: {b.get('valid')}  | entropia: {b.get('entropy')} bits/byte")
        w(f"- Bloco de assinatura Secure Boot V2 detectado: {b.get('secure_boot_v2_signature_block', False)}\n")
        w("## Tabela de partições (0x8000)\n")
        w(f"MD5 da tabela confere: {r['partition_table_md5_ok']}\n")
    w("| Label | Tipo | Subtipo | Offset | Tamanho | Vazia | Entropia | SHA-256 (16 primeiros) |")
    w("|---|---|---|---|---|---|---|---|")
    for p in r["partitions"]:
        w(f"| {p['label']} | {p['type']} | {p['subtype']} | 0x{p['offset']:06x} | {p['size']} | "
          f"{p['empty']} | {p['entropy']} | `{p['sha256'][:16]}` |")
    w("\nEntropia próxima de 8 em toda a partição de app indicaria dados cifrados (Flash Encryption). "
      "Valores típicos de código não cifrado ficam entre 5 e 6,5.\n")

    for p in r["partitions"]:
        if "image" in p:
            im = p["image"]
            w(f"## Aplicação `{p['label']}`\n")
            w(f"- Cabeçalho válido: {im.get('valid')}  | segmentos: {im.get('segments')}  | entry: {im.get('entry_point')}")
            w(f"- Hash SHA-256 anexado à imagem: {im.get('hash_appended')}")
            w(f"- **Bloco de assinatura Secure Boot V2: {im.get('secure_boot_v2_signature_block')}**")
            d = im.get("app_desc")
            if d:
                w(f"- Projeto: `{d['project_name']}`  | versão: `{d['version']}`  | secure_version (anti-rollback): {d['secure_version']}")
                w(f"- Compilado em: {d['compile_date']} {d['compile_time']}  | IDF: `{d['idf_ver']}`")
            w("")
        if "otadata" in p:
            w(f"## otadata\n\n- Slot ativo (estimado): {p['otadata']['active_slot_guess']}\n")
        if "nvs" in p:
            w(f"## NVS `{p['label']}` (páginas ativas: {p['nvs']['active_pages']})\n")
            if not p["nvs"]["entries"]:
                w("Nenhuma entrada legível (vazia ou NVS Encryption ativa).\n")
            else:
                w("| Namespace | Chave | Tipo | Valor |")
                w("|---|---|---|---|")
                for e in p["nvs"]["entries"]:
                    v = e["value"]
                    if isinstance(v, str) and SENSITIVE_KEY.search(e["key"]) and not show:
                        v = mask(v)
                    w(f"| {e['namespace']} | {e['key']} | {e['type']} | `{v}` |")
                w("\nValores legíveis aqui significam que os parâmetros estão em **texto claro** na Flash.\n")

    w("## Segredos (da NVS ou informados com --known-secret) que aparecem literalmente no binário\n")
    if r["secrets_also_in_app_binary"]:
        w("| Chave NVS | Valor (mascarado) | Offsets no binário |")
        w("|---|---|---|")
        for h in r["secrets_also_in_app_binary"]:
            w(f"| {h['nvs_key']} | {h['value_masked']} | {', '.join(h['found_in_app_at'])} |")
        w("\nIsso indica credencial **embutida no firmware**: igual em todas as unidades que recebem a mesma imagem.\n")
    else:
        w("Nenhum.\n")

    w("## Strings por categoria\n")
    for name, c in r["string_categories"].items():
        w(f"### {name} ({c['total']} ocorrências)\n")
        for off, s in c["exemplos"]:
            w(f"- `{off}` {s.replace('|', '¦')[:160]}")
        w("")
    (EVID / "firmware_analysis.md").write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
