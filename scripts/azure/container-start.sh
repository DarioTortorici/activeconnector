#!/bin/sh
# Container entrypoint: materialize the LDAPS trust bundle from the
# MWA_AD_TRUST_STORE_PEM app setting, then run the connector API.
set -eu
mkdir -p /mwa/tls /mwa/state
if [ -n "${MWA_AD_TRUST_STORE_PEM:-}" ]; then
  printf '%s' "$MWA_AD_TRUST_STORE_PEM" > /mwa/tls/domain-ca.pem
fi
exec python -m mwa_ad_connector.entrypoints.api
