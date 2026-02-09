#!/usr/bin/env bash
# Deploys the Nitro Introspector stack with a pre-built reproducible EIF.
# Applies KMS policy with PCR0 from build BEFORE the enclave starts, ensuring
# the policy is in place before any decrypt operations.
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

# Apply KMS key policy with PCR0 attestation condition
apply_kms_policy() {
  local key_id=$1
  local pcr0=$2
  local ec2_role_arn=$3
  local account_root="arn:aws:iam::${account}:root"

  echo "[deploy] Applying KMS key policy with PCR0: ${pcr0}"

  local policy
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
      "Sid": "Enable key administration (no decrypt)",
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

  aws kms put-key-policy \
    --region "${region}" \
    --key-id "${key_id}" \
    --policy-name default \
    --policy "${policy}"
}

# Step 1: Read PCR0 from pre-built artifacts (run ./scripts/build_eif.sh first)
if [[ ! -f artifacts/pcr.json ]]; then
  echo "artifacts/pcr.json not found. Run ./scripts/build_eif.sh first." >&2
  exit 1
fi
pcr0=$(jq -r '.PCR0' artifacts/pcr.json)
if [[ -z "${pcr0}" || "${pcr0}" == "null" ]]; then
  echo "Failed to get PCR0 from artifacts/pcr.json" >&2
  exit 1
fi
echo "[deploy] PCR0 from build: ${pcr0}"

# Step 2: Deploy the stack (creates KMS key, EC2 instance, role)
echo "[deploy] Deploying stack..."
cdk deploy -O "${output}"

# Step 3: Get outputs and apply KMS policy IMMEDIATELY (before enclave fully starts)
kms_key_id=$(get_output "KMSKeyID")
if [[ -z "${kms_key_id}" ]]; then
  kms_key_id=$(get_output "KmsKeyId")
fi
if [[ -z "${kms_key_id}" ]]; then
  echo "KMSKeyID not found in ${output} for ${stack_name}" >&2
  exit 1
fi

ec2_role_arn=$(get_output "EC2InstanceRoleARN")
if [[ -z "${ec2_role_arn}" ]]; then
  echo "EC2InstanceRoleARN not found in ${output} for ${stack_name}" >&2
  exit 1
fi

instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi
if [[ -z "${instance_id}" ]]; then
  echo "InstanceID not found in ${output} for ${stack_name}" >&2
  exit 1
fi

# Wait for KMS key to be enabled
echo "[deploy] Waiting for KMS key ${kms_key_id} to be enabled..."
for _ in {1..60}; do
  key_state=$(aws kms describe-key --region "${region}" --key-id "${kms_key_id}" --query 'KeyMetadata.KeyState' --output text)
  if [[ "${key_state}" == "Enabled" ]]; then
    break
  fi
  sleep 2
done

# Apply KMS policy with PCR0 BEFORE waiting for instance/enclave
# This ensures the policy is in place before any decrypt operations
apply_kms_policy "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"

# Step 4: Wait for instance to be ready
echo "[deploy] Waiting for instance ${instance_id} to be ready..."
aws ec2 wait instance-status-ok --region "${region}" --instance-ids "${instance_id}"

echo ""
echo "[deploy] Done."
echo "Instance ID: ${instance_id}"
echo "KMS Key ID: ${kms_key_id}"
echo "PCR0: ${pcr0}"
echo ""
echo "The enclave workflow:"
echo "  1. KMS policy with PCR0 is already applied (done above)"
echo "  2. First run: Generate key, encrypt with KMS, store ciphertext in SSM"
echo "  3. Subsequent runs: Decrypt ciphertext from SSM using KMS with attestation"
echo ""
echo "The PCR0 policy ensures only this specific enclave image can decrypt the key."
