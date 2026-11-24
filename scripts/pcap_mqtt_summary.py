#!/usr/bin/env python3
"""
Etapa 5 - Resume o tráfego MQTT de um PCAP (ex.: wokwi.pcap baixado pelo ícone de Wi-Fi do Wokwi).

Para cada fluxo TCP em portas MQTT, remonta os dados e decodifica:
  CONNECT   -> client id, keepalive, flags, usuário, senha (MASCARADA), last will
  PUBLISH   -> tópico, QoS, retain, payload (campos de identificação destacados)
  SUBSCRIBE -> filtros de tópico
Em portas TLS (8883/8885...) apenas reporta que o conteúdo está cifrado (registro TLS).

Também lista DNS (nomes resolvidos) e todos os destinos IP:porta, para o mapa de comunicação.

Requer: py -m pip install scapy
Uso:    py scripts\\pcap_mqtt_summary.py network\\evidence\\wokwi.pcap
Saída:  network/evidence/pcap_summary.md
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, rdpcap  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "network" / "evidence"
MQTT_PLAIN = {1883, 1884}
MQTT_TLS = {8883, 8884, 8885, 8886, 8887}
TYPES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE", 9: "SUBACK",
         12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}
IDENT_KEYS = {"mac", "ip", "device", "fw", "serial", "imei"}


def mask(v: str) -> str:
    return (v[:2] + "*" * (len(v) - 2)) if len(v) > 2 else "*" * len(v)


def u16(b, i):
    return (b[i] << 8) | b[i + 1], i + 2


def mstr(b, i):
    n, i = u16(b, i)
    return b[i:i + n].decode("utf-8", "replace"), i + n


def parse_mqtt(stream: bytes):
    i, out = 0, []
    while i + 2 <= len(stream):
        h = stream[i]
        ptype, flags = h >> 4, h & 0x0F
        mult, rl, j = 1, 0, i + 1
        while j < len(stream):
            d = stream[j]
            rl += (d & 0x7F) * mult
            mult *= 128
            j += 1
            if not d & 0x80:
                break
        body = stream[j:j + rl]
        if len(body) < rl or ptype not in TYPES:
            break
        pkt = {"type": TYPES[ptype]}
        try:
            if ptype == 1:
                proto, k = mstr(body, 0)
                level, cflags = body[k], body[k + 1]
                keep, k = u16(body, k + 2)
                cid, k = mstr(body, k)
                pkt.update({"protocol": f"{proto} v{level}", "keepalive": keep, "client_id": cid,
                            "clean_session": bool(cflags & 2)})
                if cflags & 4:
                    wt, k = mstr(body, k)
                    wm, k = mstr(body, k)
                    pkt["will"] = f"{wt} = {wm} (retain={bool(cflags & 0x20)})"
                if cflags & 0x80:
                    user, k = mstr(body, k)
                    pkt["username"] = user
                if cflags & 0x40:
                    pw, k = mstr(body, k)
                    pkt["password_in_clear"] = mask(pw)
                    pkt["password_length"] = len(pw)
            elif ptype == 3:
                topic, k = mstr(body, 0)
                qos = (flags >> 1) & 3
                if qos:
                    k += 2
                payload = body[k:].decode("utf-8", "replace")
                pkt.update({"topic": topic, "qos": qos, "retain": bool(flags & 1), "payload": payload})
                try:
                    keys = set(json.loads(payload).keys())
                    pkt["identifiers"] = sorted(keys & IDENT_KEYS)
                except Exception:
                    pass
            elif ptype == 8:
                _, k = u16(body, 0)
                filters = []
                while k < len(body):
                    f, k = mstr(body, k)
                    filters.append(f)
                    k += 1
                pkt["filters"] = filters
        except IndexError:
            pkt["note"] = "pacote truncado"
        out.append(pkt)
        i = j + rl
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    a = ap.parse_args()
    pkts = rdpcap(a.pcap)

    streams = defaultdict(dict)       # (src, sport, dst, dport) -> {seq: payload}
    endpoints = defaultdict(int)
    dns = set()
    tls_seen = defaultdict(int)
    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        if p.haslayer(UDP) and p.haslayer(DNS):
            d = p[DNS]
            if d.qr == 1 and d.an:
                for k in range(d.ancount):
                    rr = d.an[k]
                    if isinstance(rr, DNSRR) and rr.type == 1:
                        dns.add(f"{rr.rrname.decode().rstrip('.')} -> {rr.rdata}")
            elif d.qr == 0 and p.haslayer(DNSQR):
                dns.add(f"consulta: {p[DNSQR].qname.decode().rstrip('.')}")
        if p.haslayer(TCP):
            t = p[TCP]
            endpoints[f"{ip.src} -> {ip.dst}:{t.dport}"] += 1
            data = bytes(t.payload)
            if not data:
                continue
            if t.dport in MQTT_TLS or t.sport in MQTT_TLS:
                if data[:1] in (b"\x16", b"\x17") and data[1:2] == b"\x03":
                    tls_seen[f"{ip.src} -> {ip.dst}:{t.dport}"] += 1
                continue
            if t.dport in MQTT_PLAIN or t.sport in MQTT_PLAIN:
                streams[(ip.src, t.sport, ip.dst, t.dport)].setdefault(t.seq, data)

    L = ["# Resumo do PCAP (gerado por scripts/pcap_mqtt_summary.py)\n",
         f"- Arquivo: `{Path(a.pcap).name}`  | pacotes: {len(pkts)}\n",
         "## Destinos TCP observados\n", "| Fluxo | Pacotes |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in sorted(endpoints.items(), key=lambda x: -x[1])]
    L += ["\n## DNS\n"] + [f"- {d}" for d in sorted(dns)] + [""]
    L += ["## MQTT sem TLS\n"]
    if not streams:
        L.append("Nenhum fluxo MQTT em texto claro.\n")
    for (src, sp, dst, dp), segs in streams.items():
        data = b"".join(segs[s] for s in sorted(segs))
        msgs = parse_mqtt(data)
        L.append(f"### {src}:{sp} -> {dst}:{dp}  ({len(msgs)} mensagens)\n")
        for m in msgs:
            line = f"- **{m['type']}** " + ", ".join(f"{k}=`{v}`" for k, v in m.items() if k != "type")
            L.append(line[:400])
        L.append("")
    L += ["## MQTT sobre TLS\n"]
    L += ([f"- {k}: {v} registros TLS (conteúdo cifrado, não legível)" for k, v in tls_seen.items()]
          or ["Nenhum."])
    L.append("\nSenhas aparecem mascaradas; o fato relevante é que estavam legíveis no pacote CONNECT.")
    EVID.mkdir(parents=True, exist_ok=True)
    out = EVID / "pcap_summary.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"\nEvidência: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
