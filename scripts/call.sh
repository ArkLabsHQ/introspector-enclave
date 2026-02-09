#!/usr/bin/env bash
# Calls the enclave: verifies attestation + pubkey binding via PCR16.
#
# Usage:
#   ./scripts/call.sh [cdk-outputs.json]
#
# Environment:
#   CDK_DEPLOY_REGION   AWS region (required)
#   CDK_DEPLOY_ACCOUNT  AWS account ID (required)
#   BASE_URL            Override enclave URL (optional, auto-detected from instance IP)
#   EXPECTED_PCR0       Expected PCR0 hex (optional)
#   INSECURE_TLS        Set to skip TLS verification (optional)
#   VERIFY_BUILD        Set to build EIF and derive PCR0 (optional)
#   BUILD_VERSION       VERSION for nix build (optional, used with VERIFY_BUILD)
#   BUILD_REGION        AWS_REGION for nix build (optional, used with VERIFY_BUILD)
set -euo pipefail
export AWS_PAGER=""

output=${1:-cdk-outputs.json}
prefix=${CDK_PREFIX:-dev}
region=${CDK_DEPLOY_REGION:-}

if [[ -z "${region}" ]]; then
  echo "CDK_DEPLOY_REGION must be set" >&2
  exit 1
fi

stack_name="${prefix}NitroIntrospector"

if [[ -z "${BASE_URL:-}" ]]; then
  instance_id=$(jq -r --arg stack "${stack_name}" '.[$stack].InstanceID // .[$stack].InstanceId // empty' "${output}")
  if [[ -z "${instance_id}" ]]; then
    echo "InstanceID not found in ${output}" >&2
    exit 1
  fi

  public_ip=$(aws ec2 describe-instances --region "${region}" \
    --instance-ids "${instance_id}" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  if [[ -z "${public_ip}" || "${public_ip}" == "None" ]]; then
    echo "Could not find public IP for instance ${instance_id}" >&2
    exit 1
  fi
  base_url="https://${public_ip}"
  echo "[call] Instance IP: ${public_ip}"
else
  base_url="${BASE_URL}"
fi

echo "[call] Calling ${base_url}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "${REPO_ROOT}/client"
go run . \
  --base-url "${base_url}" \
  ${EXPECTED_PCR0:+--expected-pcr0 "${EXPECTED_PCR0}"} \
  ${INSECURE_TLS:+--insecure} \
  ${VERIFY_BUILD:+--verify-build --repo-path "${REPO_ROOT}"} \
  ${BUILD_VERSION:+--build-version "${BUILD_VERSION}"} \
  ${BUILD_REGION:+--build-region "${BUILD_REGION}"}
