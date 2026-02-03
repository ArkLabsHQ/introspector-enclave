#!/usr/bin/env bash
# Generate and apply a KMS key policy that allows Nitro Enclave attestation.
set -euo pipefail

output=${1:-}
if [[ -z "${output}" ]]; then
  echo "usage: $0 <cdk-output.json>" >&2
  exit 1
fi

if [[ ! -f "${output}" ]]; then
  echo "output file not found: ${output}" >&2
  exit 1
fi

if [[ -z "${CDK_DEPLOY_REGION:-}" ]]; then
  echo "CDK_DEPLOY_REGION must be set" >&2
  exit 1
fi

prefix=${CDK_PREFIX:-dev}
stack_name="${prefix}NitroIntrospector"

outputs=$(jq -r --arg stack "${stack_name}" '.[$stack]' "${output}")
if [[ "${outputs}" == "null" ]]; then
  echo "stack outputs not found for ${stack_name} in ${output}" >&2
  exit 1
fi

get_output() {
  local key=$1
  jq -r --arg k "${key}" '.[$k] // empty' <<<"${outputs}"
}

instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi

ec2_role_arn=$(get_output "EC2InstanceRoleARN")
if [[ -z "${ec2_role_arn}" ]]; then
  ec2_role_arn=$(get_output "EC2InstanceRoleArn")
fi

kms_key_id=$(get_output "KMSKeyID")
if [[ -z "${kms_key_id}" ]]; then
  kms_key_id=$(get_output "KmsKeyId")
fi

if [[ -z "${instance_id}" || -z "${ec2_role_arn}" || -z "${kms_key_id}" ]]; then
  echo "missing outputs (InstanceID/EC2InstanceRoleARN/KMSKeyID) from ${stack_name}" >&2
  exit 1
fi

pcr_0=$(./scripts/get_pcr0.sh "${instance_id}")
account_id=$(aws sts get-caller-identity | jq -r '.Account')
admin_arn="arn:aws:iam::${account_id}:root"

tmp_policy=$(mktemp)
jq --arg pcr_0 "${pcr_0}" \
   --arg ec2_role_arn "${ec2_role_arn}" \
   --arg admin_arn "${admin_arn}" \
   '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:PCR0"=$pcr_0 |
    .Statement[0].Principal.AWS=$ec2_role_arn |
    .Statement[1].Principal.AWS=$ec2_role_arn |
    .Statement[2].Principal.AWS=$admin_arn' \
   ./scripts/kms_key_policy_template.json > "${tmp_policy}"

aws kms put-key-policy \
  --region "${CDK_DEPLOY_REGION}" \
  --key-id "${kms_key_id}" \
  --policy-name default \
  --policy "file://${tmp_policy}"

cat "${tmp_policy}"
rm -f "${tmp_policy}"
