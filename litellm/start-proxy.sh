#!/bin/sh
set -eu
# Conserva las CA del sistema y agrega las del laboratorio para el tráfico del
# proxy hacia los proveedores. No desactiva la verificación TLS.
proxy_ca_bundle=/tmp/prompt-scanner-ca.pem
cat /etc/ssl/certs/ca-certificates.crt > "$proxy_ca_bundle"
for certificate in /app/certs/*.crt; do
  [ -f "$certificate" ] || continue
  cat "$certificate" >> "$proxy_ca_bundle"
  printf '\n' >> "$proxy_ca_bundle"
done
export SSL_CERT_FILE="$proxy_ca_bundle"
export REQUESTS_CA_BUNDLE="$proxy_ca_bundle"
exec /app/docker/prod_entrypoint.sh "$@"
