#!/bin/bash
# Certificates for the MITM scenario. Run from scenarios/04_tls_mitm/:
#   bash make_rogue_certs.sh <broker_ip>
# A: rogue CA + broker cert with the SAME IP as the real broker (attacker's PKI)
# B: cert signed by the REAL CA but for a different IP (mis-issued / wrong host)
set -euo pipefail
IP="${1:?broker ip}"
mkdir -p certs && cd certs
key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }
ext() { printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$1" > s.ext; }

# A. Rogue CA (not trusted by the device)
key rogue-ca.key
openssl req -x509 -new -key rogue-ca.key -sha256 -days 30 -subj "/CN=Sectel Test CA" -out rogue-ca.crt
key rogue-broker.key
openssl req -new -key rogue-broker.key -subj "/CN=sectel-broker" -out r.csr
ext "IP:${IP},IP:127.0.0.1,DNS:localhost"
openssl x509 -req -in r.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -days 30 -sha256 -extfile s.ext -out rogue-broker.crt

# B. Real CA, wrong address (requires ../../pki/ca.key)
key wrongip-broker.key
openssl req -new -key wrongip-broker.key -subj "/CN=sectel-broker" -out w.csr
ext "IP:10.99.99.99"
openssl x509 -req -in w.csr -CA ../../../pki/ca.crt -CAkey ../../../pki/ca.key -CAcreateserial -days 30 -sha256 -extfile s.ext -out wrongip-broker.crt

rm -f *.csr *.ext *.srl ../../../pki/*.srl
chmod 600 *.key
echo "Rogue CA has the same CN as the real one on purpose: only the key differs."
