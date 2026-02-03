#!/usr/bin/env bash
# Fetch PCR0 from a running Nitro Enclave on the given instance via SSM.
set -euo pipefail

instance_id=${1:-}
if [[ -z "${instance_id}" ]]; then
  echo "usage: $0 <instance-id>" >&2
  exit 1
fi

if [[ -z "${CDK_DEPLOY_REGION:-}" ]]; then
  echo "CDK_DEPLOY_REGION must be set" >&2
  exit 1
fi

command_id=$(aws ssm send-command \
  --region "${CDK_DEPLOY_REGION}" \
  --document-name "AWS-RunShellScript" \
  --instance-ids "${instance_id}" \
  --parameters 'commands=["sudo nitro-cli describe-enclaves | jq -r '"'"'.[].Measurements.PCR0'"'"'"]' |
  jq -r '.Command.CommandId')

aws ssm wait command-executed \
  --region "${CDK_DEPLOY_REGION}" \
  --instance-id "${instance_id}" \
  --command-id "${command_id}"

pcr_0=$(aws ssm list-command-invocations \
  --region "${CDK_DEPLOY_REGION}" \
  --instance-id "${instance_id}" \
  --command-id "${command_id}" \
  --details |
  jq -r '.CommandInvocations[0].CommandPlugins[0].Output' | tr -d '\r')

if [[ -z "${pcr_0}" || "${pcr_0}" == "null" ]]; then
  echo "failed to read PCR0; ensure enclave is running on ${instance_id}" >&2
  exit 1
fi

echo "${pcr_0}"
