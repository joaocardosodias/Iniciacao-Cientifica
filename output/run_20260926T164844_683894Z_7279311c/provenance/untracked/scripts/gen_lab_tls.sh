#!/usr/bin/env bash
set -euo pipefail

out="${1:-experiments/tls}"
mkdir -p "$out"
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$out/lab-key.pem" -out "$out/lab-cert.pem" \
  -subj "/CN=lab-c2/O=iniciacao-cientifica" \
  -addext "subjectAltName=IP:192.168.15.12,DNS:localhost,IP:127.0.0.1"
echo "cert: $out/lab-cert.pem"
echo "key:  $out/lab-key.pem"
