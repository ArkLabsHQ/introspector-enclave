#!/usr/bin/env sh

set -e

# Default to insecure HTTP for the skeleton server.
export INTROSPECTOR_NO_TLS="${INTROSPECTOR_NO_TLS:-true}"

exec /app/introspector-skeleton
