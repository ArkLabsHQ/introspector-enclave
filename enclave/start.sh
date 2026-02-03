#!/usr/bin/env sh

set -e

if [ "${INTROSPECTOR_VIPROXY_ENABLED:-true}" = "true" ]; then
  VIPROXY_IN_ADDRS="${INTROSPECTOR_VIPROXY_IN_ADDRS:-127.0.0.1:80}"
  VIPROXY_OUT_ADDRS="${INTROSPECTOR_VIPROXY_OUT_ADDRS:-3:8002}"
  IN_ADDRS="${VIPROXY_IN_ADDRS}" OUT_ADDRS="${VIPROXY_OUT_ADDRS}" /app/proxy &
  if [ -z "${AWS_EC2_METADATA_SERVICE_ENDPOINT:-}" ]; then
    export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:80"
  fi
fi

export INTROSPECTOR_NO_TLS=true

# The AWS SDK needs a region. Inside the enclave, IMDS region detection
# may fail, so we set it explicitly from the deployment config.
if [ -z "${AWS_DEFAULT_REGION:-}" ]; then
  export AWS_DEFAULT_REGION="${INTROSPECTOR_AWS_REGION:-us-east-1}"
fi
APP_PORT="${INTROSPECTOR_PORT:-7073}"
NITRIDING_EXT_PORT="${INTROSPECTOR_NITRIDING_EXT_PORT:-443}"
NITRIDING_INT_PORT="${INTROSPECTOR_NITRIDING_INT_PORT:-8080}"
NITRIDING_PROM_PORT="${INTROSPECTOR_NITRIDING_PROM_PORT:-9090}"
NITRIDING_PROM_NS="${INTROSPECTOR_NITRIDING_PROM_NAMESPACE:-introspector}"
NITRIDING_FQDN="${INTROSPECTOR_NITRIDING_FQDN:-localhost}"

NITRIDING_ARGS="-fqdn ${NITRIDING_FQDN} \
  -ext-pub-port ${NITRIDING_EXT_PORT} \
  -intport ${NITRIDING_INT_PORT} \
  -appwebsrv http://127.0.0.1:${APP_PORT} \
  -prometheus-namespace ${NITRIDING_PROM_NS} \
  -prometheus-port ${NITRIDING_PROM_PORT}"

if [ "${INTROSPECTOR_NITRIDING_DEBUG:-false}" = "true" ]; then
  NITRIDING_ARGS="${NITRIDING_ARGS} -debug"
fi

exec /app/nitriding ${NITRIDING_ARGS} -appcmd "/app/introspector-skeleton"
