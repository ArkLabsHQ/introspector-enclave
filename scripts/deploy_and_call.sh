#!/usr/bin/env bash
set -euo pipefail

output=${1:-cdk-outputs.json}
prefix=${CDK_PREFIX:-dev}
region=${CDK_DEPLOY_REGION:-}
account=${CDK_DEPLOY_ACCOUNT:-}

if [[ -z "${region}" || -z "${account}" ]]; then
  echo "CDK_DEPLOY_REGION and CDK_DEPLOY_ACCOUNT must be set" >&2
  exit 1
fi

./scripts/deploy_introspector.sh "${output}"

stack_name="${prefix}NitroIntrospector"

instance_id=$(jq -r --arg stack "${stack_name}" '.[$stack].InstanceID // .[$stack].InstanceId // empty' "${output}")
if [[ -z "${instance_id}" ]]; then
  echo "InstanceID not found in ${output}" >&2
  exit 1
fi

if [[ -z "${BASE_URL:-}" ]]; then
  public_ip=$(aws ec2 describe-instances --region "${region}" \
    --instance-ids "${instance_id}" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  if [[ -z "${public_ip}" || "${public_ip}" == "None" ]]; then
    echo "Could not find public IP for instance ${instance_id}" >&2
    exit 1
  fi
  base_url="https://${public_ip}"
  echo "Instance IP: ${public_ip}"
else
  base_url="${BASE_URL}"
fi

echo "[client] calling ${base_url}"

go run ./cmd/introspector-client \
  --base-url "${base_url}" \
  --ark-tx "${ARK_TX:-demo-ark-tx}" \
  --checkpoint-tx "${CHECKPOINT_TX:-demo-checkpoint-tx}" \
  ${EXPECTED_PCR0:+--expected-pcr0 "${EXPECTED_PCR0}"} \
  ${INSECURE_TLS:+--insecure} \
  ${VERIFY_BUILD:+--verify-build --repo-path .} \
  ${BUILD_VERSION:+--build-version "${BUILD_VERSION}"} \
  ${BUILD_REGION:+--build-region "${BUILD_REGION}"}
