#!/usr/bin/env python3
"""
Etapa 5 - Observa as mensagens MQTT do laboratório (assina nexahome/#) e registra como evidência.

Mostra: tópicos usados, origem (device id no tópico), tipo de informação na telemetria,
mensagens de controle (cmd/status) e identificadores expostos (MAC, IP).

As credenciais NÃO ficam no código: passe por variáveis de ambiente.
  Windows (PowerShell):  $env:MQTT_USER="analyst"; $env:MQTT_PASS="<senha-do-analista>"
  Linux:                 export MQTT_USER=analyst MQTT_PASS=<senha-do-analista>

Uso (broker local do laboratório, com a simulação rodando):
  $env:MQTT_USER="analyst"; $env:MQTT_PASS="<senha-do-analista>"
  py scripts\\mqtt_observer.py --root nexahome --seconds 60
"""
import argparse
import datetime as dt
import json
import os
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "network" / "evidence"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--root", default="nexahome", help="raiz de tópicos configurada no firmware (LAB_TOPIC_ROOT)")
    ap.add_argument("--topic", help="filtro de assinatura (padrão: <root>/#)")
    ap.add_argument("--seconds", type=float, default=60)
    ap.add_argument("--tls-ca", help="caminho da CA para testar a porta 8883 (reteste hardened)")
    args = ap.parse_args()

    args.topic = args.topic or f"{args.root}/#"
    EVID.mkdir(parents=True, exist_ok=True)
    out = EVID / f"mqtt_observer_{dt.datetime.now():%Y%m%d_%H%M%S}.log"
    log = open(out, "w", encoding="utf-8")
    seen_topics, seen_fields = set(), set()

    def w(line):
        print(line)
        log.write(line + "\n")
        log.flush()

    def on_connect(c, userdata, flags, rc, props=None):
        w(f"# conectado em {args.host}:{args.port} rc={rc} tls={'sim' if args.tls_ca else 'NAO'}; assinando {args.topic}")
        c.subscribe(args.topic)

    def on_message(c, userdata, msg):
        payload = msg.payload.decode("utf-8", "replace")
        seen_topics.add(msg.topic)
        try:
            seen_fields.update(json.loads(payload).keys())
        except Exception:
            pass
        w(f"{dt.datetime.now().isoformat(timespec='seconds')}  {msg.topic}  retain={msg.retain}  {payload}")

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"observer-{os.getpid()}")
    user, pw = os.environ.get("MQTT_USER"), os.environ.get("MQTT_PASS")
    if user:
        c.username_pw_set(user, pw)
    if args.tls_ca:
        c.tls_set(ca_certs=args.tls_ca)
    c.on_connect = on_connect
    c.on_message = on_message
    c.connect(args.host, args.port, 30)
    c.loop_start()
    time.sleep(args.seconds)
    c.loop_stop()
    w("\n# Resumo")
    w(f"# tópicos observados: {sorted(seen_topics)}")
    w(f"# campos presentes na telemetria/comandos: {sorted(seen_fields)}")
    log.close()
    print(f"\nEvidência: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
