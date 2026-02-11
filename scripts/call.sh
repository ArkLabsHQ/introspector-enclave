#!/usr/bin/env bash
# Calls the enclave: verifies attestation + pubkey binding via PCR16.
#
# Usage:
#   ./scripts/call.sh [cdk-outputs.json]
#
# Environment:
#   CDK_DEPLOY_REGION   AWS region (required)
#   CDK_PREFIX          Deployment prefix (optional, defaults to "dev")
#   BASE_URL            Override enclave URL (optional, auto-detected from Elastic IP)
#   EXPECTED_PCR0       Expected PCR0 hex (optional)
#   STRICT_TLS          Set to require CA-signed TLS cert (optional, default: skip)
#   VERIFY_BUILD        Set to build EIF and derive PCR0 (optional)
#   BUILD_VERSION       VERSION for nix build (optional, used with VERIFY_BUILD)
#   BUILD_REGION        AWS_REGION for nix build (optional, used with VERIFY_BUILD)
set -euo pipefail
export AWS_PAGER=""

output=${1:-cdk-outputs.json}
prefix=${CDK_PREFIX:-dev}
stack_name="${prefix}NitroIntrospector"

if [[ -z "${BASE_URL:-}" ]]; then
  # Read Elastic IP from CDK outputs
  elastic_ip=$(jq -r --arg stack "${stack_name}" '.[$stack].ElasticIP // .[$stack]["Elastic IP"] // empty' "${output}" 2>/dev/null || true)
  if [[ -n "${elastic_ip}" ]]; then
    base_url="https://${elastic_ip}"
    echo "[call] Elastic IP: ${elastic_ip}"
  else
    echo "ElasticIP not found in ${output}. Set BASE_URL manually." >&2
    exit 1
  fi
else
  base_url="${BASE_URL}"
fi

echo "[call] Calling ${base_url}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "${REPO_ROOT}/client"
go run . \
  --base-url "${base_url}" \
  ${EXPECTED_PCR0:+--expected-pcr0 "${EXPECTED_PCR0}"} \
  ${STRICT_TLS:+--strict-tls} \
  ${VERIFY_BUILD:+--verify-build --repo-path "${REPO_ROOT}"} \
  ${BUILD_VERSION:+--build-version "${BUILD_VERSION}"} \
  ${BUILD_REGION:+--build-region "${BUILD_REGION}"}
