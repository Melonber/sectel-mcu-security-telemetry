#!/bin/bash
# Local test PKI for Sectel: CA, broker, collector, one device (ECDSA P-256).
# Usage (from pki/):  ./make_pki.sh <broker_ip> <device_id>
#   e.g. ./make_pki.sh 192.168.18.207 esp32-dcda0c81a1e4
# device_id MUST equal the device's MQTT client_id (esp32-<wifi mac>),
# because the broker uses the certificate CN as the username for ACLs.
set -euo pipefail
BROKER_IP="${1:?broker ip}"
DEVICE_ID="${2:?device id, e.g. esp32-dcda0c81a1e4}"
DAYS=730

key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

# 1. CA (10 years). Keep ca.key offline in a real deployment.
if [ ! -f ca.key ]; then
  key ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "/CN=Sectel Test CA" -out ca.crt
fi

# 2. Broker: SAN must contain every address clients use to reach it.
key broker.key
openssl req -new -key broker.key -subj "/CN=sectel-broker" -out broker.csr
cat > broker.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=IP:${BROKER_IP},IP:127.0.0.1,DNS:localhost
EXT
openssl x509 -req -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days $DAYS -sha256 -extfile broker.ext -out broker.crt

# 3. Clients: collector and device (CN = MQTT username via ACL)
client() {
  key "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days $DAYS -sha256 -extfile client.ext -out "$1.crt"
}
client collector sectel-collector
client device "$DEVICE_ID"

rm -f *.csr *.ext *.srl
chmod 600 *.key
echo "Done. Verify:"
openssl verify -CAfile ca.crt broker.crt collector.crt device.crt
