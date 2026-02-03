#!/usr/bin/env bash
# Post-deploy setup: wait for enclave, apply KMS key policy, generate and store secret key.
# Run this after the CDK stack is already deployed (skips cdk deploy).
set -euo pipefail

output=${1:-cdk-outputs.json}
prefix=${CDK_PREFIX:-dev}
region=${CDK_DEPLOY_REGION:-}

if [[ -z "${region}" ]]; then
  echo "CDK_DEPLOY_REGION must be set" >&2
  exit 1
fi

if [[ ! -f "${output}" ]]; then
  echo "CDK outputs file not found: ${output}" >&2
  echo "Run the full deploy first, or pass the correct path as \$1" >&2
  exit 1
fi

stack_name="${prefix}NitroIntrospector"

get_output() {
  local key=$1
  jq -r --arg stack "${stack_name}" --arg key "${key}" '.[$stack][$key] // empty' "${output}"
}

kms_key_id=$(get_output "KMSKeyID")
if [[ -z "${kms_key_id}" ]]; then
  kms_key_id=$(get_output "KmsKeyId")
fi
if [[ -z "${kms_key_id}" ]]; then
  echo "KMSKeyID not found in ${output} for ${stack_name}" >&2
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

echo "[setup] KMS Key: ${kms_key_id}"
echo "[setup] Instance: ${instance_id}"

echo "[setup] Waiting for enclave to be running on ${instance_id}..."
max_attempts=60
for attempt in $(seq 1 $max_attempts); do
  if pcr0_out=$(./scripts/get_pcr0.sh "${instance_id}" 2>/dev/null) && [[ -n "${pcr0_out}" ]]; then
    echo "[setup] Enclave is running (PCR0: ${pcr0_out:0:16}...)"
    break
  fi
  if [[ $attempt -eq $max_attempts ]]; then
    echo "Enclave did not start after ${max_attempts} attempts" >&2
    exit 1
  fi
  echo "[setup] Enclave not ready yet (attempt ${attempt}/${max_attempts}), waiting 30s..."
  sleep 30
done

echo "[setup] Applying KMS key policy with enclave PCR0..."
./scripts/generate_kms_key_policy.sh "${output}"

secret_hex=$(openssl rand -hex 32)
secret_bin=$(mktemp)
trap 'rm -f "${secret_bin}"' EXIT
echo -n "${secret_hex}" | xxd -r -p > "${secret_bin}"

echo "[setup] Encrypting secret key with KMS..."
ciphertext_b64=$(aws kms encrypt \
  --region "${region}" \
  --key-id "${kms_key_id}" \
  --plaintext "fileb://${secret_bin}" \
  --query CiphertextBlob \
  --output text)

param_name=$(get_output "SecretKeyCiphertextParam")
if [[ -z "${param_name}" ]]; then
  param_name="/${prefix}/NitroIntrospector/SecretKeyCiphertext"
fi

echo "[setup] Storing ciphertext in SSM parameter ${param_name}..."
aws ssm put-parameter \
  --region "${region}" \
  --name "${param_name}" \
  --type String \
  --overwrite \
  --value "${ciphertext_b64}"

echo "[setup] Done."
echo "INTROSPECTOR_SECRET_KEY (hex): ${secret_hex}"
