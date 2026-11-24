#!/usr/bin/env bash
# Gera uma CA de laboratório e o certificado do broker para o reteste (perfil hardened).
# O ESP32 simulado conecta em "host.wokwi.internal", então o certificado é emitido para
# esse nome (CN e SAN DNS). Assim a validação TLS no dispositivo confere.
# Uso: bash lab/mosquitto/gen-certs.sh
# (No Windows, rode no Git Bash ou WSL; precisa do openssl.)
set -euo pipefail
HOSTNAME_CN="host.wokwi.internal"
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR" && cd "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=NexaHome Lab CA" \
  -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj "/CN=$HOSTNAME_CN" -keyout server.key -out server.csr
printf "subjectAltName=DNS:%s\n" "$HOSTNAME_CN" > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
  -extfile san.ext -out server.crt
rm -f server.csr san.ext
echo "Pronto. Copie o conteúdo de certs/ca.crt para firmware-src/include/ca_cert.h"
echo "no formato:  static const char NEXA_CA_CERT[] = R\"EOF(...conteudo do ca.crt...)EOF\";"
echo "NAO publique ca.key nem server.key (estão no .gitignore)."
