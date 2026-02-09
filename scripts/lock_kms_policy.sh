#!/usr/bin/env bash
# IRREVERSIBLY locks the KMS key policy so that ONLY the enclave with
# the matching PCR0 can decrypt.  After this script runs:
#
#   - No IAM principal (including root) can call kms:Decrypt without attestation
#   - No IAM principal can modify the key policy (kms:PutKeyPolicy)
#   - No IAM principal can create grants to bypass the policy
#   - No IAM principal can delete the key
#
# THIS IS NOT REVERSIBLE.  The key becomes permanently bound to the given PCR0.
# To rotate to new enclave code, use scripts/migrate_key.sh BEFORE locking the
# new key.
#
# Usage:
#   ./scripts/lock_kms_policy.sh [cdk-outputs.json]
#
# Requires:
#   - CDK_DEPLOY_REGION and CDK_DEPLOY_ACCOUNT environment variables
#   - artifacts/pcr.json from a Nix build (for PCR0)
#   - cdk-outputs.json (or argument) with KMSKeyID and EC2InstanceRoleARN

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

# Read PCR0 from build output
pcr0=$(jq -r '.PCR0' artifacts/pcr.json 2>/dev/null || true)
if [[ -z "${pcr0}" || "${pcr0}" == "null" ]]; then
  echo "Failed to read PCR0 from artifacts/pcr.json" >&2
  echo "Run './scripts/build_eif.sh' first." >&2
  exit 1
fi

# Read KMS key ID and EC2 role ARN from CDK outputs
kms_key_id=$(get_output "KMSKeyID")
if [[ -z "${kms_key_id}" ]]; then
  kms_key_id=$(get_output "KmsKeyId")
fi
if [[ -z "${kms_key_id}" ]]; then
  echo "KMSKeyID not found in ${output}" >&2
  exit 1
fi

ec2_role_arn=$(get_output "EC2InstanceRoleARN")
if [[ -z "${ec2_role_arn}" ]]; then
  echo "EC2InstanceRoleARN not found in ${output}" >&2
  exit 1
fi

echo ""
echo "============================================================"
echo "  WARNING: THIS OPERATION IS IRREVERSIBLE"
echo "============================================================"
echo ""
echo "  KMS Key ID:      ${kms_key_id}"
echo "  PCR0:            ${pcr0}"
echo "  EC2 Role:        ${ec2_role_arn}"
echo "  Region:          ${region}"
echo ""
echo "  After this, the key policy CANNOT be modified by anyone."
echo "  Only an enclave with PCR0=${pcr0:0:16}... can decrypt."
echo ""
echo "  To update enclave code later, you MUST use migrate_key.sh"
echo "  BEFORE running this script on the new KMS key."
echo ""
read -r -p "  Type 'LOCK' to proceed: " confirmation

if [[ "${confirmation}" != "LOCK" ]]; then
  echo "Aborted." >&2
  exit 1
fi

policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveDecryptWithAttestation",
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
      "Sid": "EnclaveEncrypt",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:Encrypt",
      "Resource": "*"
    }
  ]
}
EOF
)

echo "[lock] Applying locked policy with --bypass-policy-lockout-safety-check..."

aws kms put-key-policy \
  --region "${region}" \
  --key-id "${kms_key_id}" \
  --policy-name default \
  --policy "${policy}" \
  --bypass-policy-lockout-safety-check

echo "[lock] Done. KMS key ${kms_key_id} is now permanently locked to PCR0: ${pcr0}"
echo "[lock] No principal can modify this policy or decrypt without matching attestation."
