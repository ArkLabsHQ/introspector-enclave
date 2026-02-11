#!/usr/bin/env bash
# Manual key migration for locked KMS keys.
#
# This is a manual version of what deploy.sh does automatically during
# upgrade when the KMS key is locked. Use this for debugging or when
# deploy.sh's SSM Run Command approach isn't available.
#
# This script runs from the deployer's machine (not the EC2 host).
# It creates a temporary KMS key, calls the old enclave's export endpoint
# to re-encrypt the signing key, then updates SSM for the new enclave.
#
# Prerequisites:
#   - Old enclave is running and healthy
#   - New EIF available at artifacts/image.eif with artifacts/pcr.json
#   - AWS CLI configured with kms:CreateKey, ssm:PutParameter, etc.
#
# Usage:
#   ./scripts/migrate.sh [cdk-outputs.json]
#
# Environment:
#   CDK_PREFIX          Deployment prefix (default: dev)
#   CDK_DEPLOY_REGION   AWS region (required)
#   CDK_DEPLOY_ACCOUNT  AWS account (required)

set -euo pipefail
export AWS_PAGER=""

output=${1:-cdk-outputs.json}
prefix=${CDK_PREFIX:-dev}
region=${CDK_DEPLOY_REGION:-}
account=${CDK_DEPLOY_ACCOUNT:-}

if [[ -z "${region}" || -z "${account}" ]]; then
  echo "CDK_DEPLOY_REGION and CDK_DEPLOY_ACCOUNT must be set" >&2
  exit 1
fi

stack_name="${prefix}NitroIntrospector"

get_output() {
  local key=$1
  jq -r --arg stack "${stack_name}" --arg key "${key}" '.[$stack][$key] // empty' "${output}"
}

reset_ssm_param() {
  local name=$1
  aws ssm put-parameter --region "${region}" \
    --name "${name}" --value "UNSET" --type String --overwrite >/dev/null
}

# Read PCR0 from build artifacts.
if [[ ! -f artifacts/pcr.json ]]; then
  echo "artifacts/pcr.json not found. Run ./scripts/build_eif.sh first." >&2
  exit 1
fi
pcr0=$(jq -r '.PCR0' artifacts/pcr.json)
if [[ -z "${pcr0}" || "${pcr0}" == "null" ]]; then
  echo "Failed to get PCR0 from artifacts/pcr.json" >&2
  exit 1
fi

ec2_role_arn=$(get_output "EC2InstanceRoleARN")
instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi
if [[ -z "${ec2_role_arn}" || -z "${instance_id}" ]]; then
  echo "Missing EC2InstanceRoleARN or InstanceID in ${output}" >&2
  exit 1
fi

# Get instance public IP for the curl call.
instance_ip=$(aws ec2 describe-instances \
  --region "${region}" \
  --instance-ids "${instance_id}" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text 2>/dev/null)
if [[ -z "${instance_ip}" || "${instance_ip}" == "None" ]]; then
  echo "Could not determine instance public IP for ${instance_id}" >&2
  exit 1
fi

echo ""
echo "[migrate] Migration settings:"
echo "  New PCR0:     ${pcr0}"
echo "  Instance:     ${instance_id} (${instance_ip})"
echo "  Region:       ${region}"
echo ""

# Step 1: Create new KMS key.
echo "[migrate] Creating new KMS key..."
new_kms_key_id=$(aws kms create-key --region "${region}" \
  --description "NitroIntrospector migration key for PCR0 ${pcr0:0:16}..." \
  --query 'KeyMetadata.KeyId' --output text)
echo "[migrate] New KMS key: ${new_kms_key_id}"

# Step 2: Apply policy (Encrypt for EC2 role, Decrypt with new PCR0).
account_root="arn:aws:iam::${account}:root"
policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable decrypt from enclave with attestation",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "${pcr0}"
        }
      }
    },
    {
      "Sid": "Enable encrypt from enclave",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:Encrypt",
      "Resource": "*"
    },
    {
      "Sid": "Enable key administration",
      "Effect": "Allow",
      "Principal": {"AWS": "${account_root}"},
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:EnableKeyRotation",
        "kms:DisableKeyRotation",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:Encrypt"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)
aws kms put-key-policy --region "${region}" \
  --key-id "${new_kms_key_id}" --policy-name default --policy "${policy}"

# Step 3: Generate migration token and store in SSM.
migration_token=$(openssl rand -hex 32)
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/MigrationToken" \
  --value "${migration_token}" --type String --overwrite >/dev/null
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/MigrationKMSKeyID" \
  --value "${new_kms_key_id}" --type String --overwrite >/dev/null
echo "[migrate] Migration token and KMS key ID stored in SSM"

# Ensure cleanup on failure.
cleanup() {
  echo "[migrate] Cleaning up migration SSM params..."
  reset_ssm_param "/${prefix}/NitroIntrospector/MigrationToken"
  reset_ssm_param "/${prefix}/NitroIntrospector/MigrationKMSKeyID"
  reset_ssm_param "/${prefix}/NitroIntrospector/MigrationCiphertext"
}
trap cleanup ERR

# Step 4: Call old enclave's export endpoint.
echo "[migrate] Calling old enclave's export endpoint..."
export_response=$(curl -sf -k "https://${instance_ip}:443/v1/export-key" \
  -X POST -H "Authorization: Bearer ${migration_token}")
echo "[migrate] Export response: ${export_response}"

# Step 5: Wait for MigrationCiphertext in SSM.
echo "[migrate] Waiting for migration ciphertext..."
max_wait=60
elapsed=0
while [[ ${elapsed} -lt ${max_wait} ]]; do
  migration_ciphertext=$(aws ssm get-parameter --region "${region}" \
    --name "/${prefix}/NitroIntrospector/MigrationCiphertext" \
    --query 'Parameter.Value' --output text 2>/dev/null || echo "UNSET")

  if [[ "${migration_ciphertext}" != "UNSET" && -n "${migration_ciphertext}" ]]; then
    echo "[migrate] Migration ciphertext stored in SSM"
    break
  fi

  sleep 3
  elapsed=$((elapsed + 3))
done

if [[ ${elapsed} -ge ${max_wait} ]]; then
  echo "[migrate] Timed out waiting for migration ciphertext" >&2
  cleanup
  exit 1
fi

# Step 6: Copy to SecretKeyCiphertext and update KMSKeyID.
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/SecretKeyCiphertext" \
  --value "${migration_ciphertext}" --type String --overwrite >/dev/null
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/KMSKeyID" \
  --value "${new_kms_key_id}" --type String --overwrite >/dev/null

# Step 7: Clean up migration params.
reset_ssm_param "/${prefix}/NitroIntrospector/MigrationToken"
reset_ssm_param "/${prefix}/NitroIntrospector/MigrationKMSKeyID"
reset_ssm_param "/${prefix}/NitroIntrospector/MigrationCiphertext"

echo ""
echo "[migrate] Done. The signing key has been migrated to new KMS key."
echo ""
echo "  New KMS Key:  ${new_kms_key_id}"
echo "  New PCR0:     ${pcr0}"
echo ""
echo "Next steps:"
echo "  1. Stop the old enclave and start the new one with the new EIF"
echo "  2. Verify: INSECURE_TLS=1 ./scripts/call.sh"
echo "  3. (Optional) Lock the new KMS key: ./scripts/lock_kms_policy.sh"
