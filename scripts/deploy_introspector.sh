#!/usr/bin/env bash
# Deploys the Nitro Introspector stack, generates a secret key, encrypts it with KMS,
# rebuilds the enclave image with the ciphertext baked in, and applies the attestation key policy.
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

deploy() {
  cdk deploy -O "${output}"
}

get_output() {
  local key=$1
  jq -r --arg stack "${stack_name}" --arg key "${key}" '.[$stack][$key] // empty' "${output}"
}

echo "[deploy] Building enclave image with Nix..."
VERSION="${prefix}" AWS_REGION="${region}" nix build --impure .#enclave-image -o enclave-image.tar.gz

echo "[deploy] Deploying stack..."
deploy

kms_key_id=$(get_output "KMSKeyID")
if [[ -z "${kms_key_id}" ]]; then
  kms_key_id=$(get_output "KmsKeyId")
fi

if [[ -z "${kms_key_id}" ]]; then
  echo "KMSKeyID not found in ${output} for ${stack_name}" >&2
  exit 1
fi

echo "[deploy] Waiting for KMS key ${kms_key_id} to be enabled..."
for _ in {1..60}; do
  key_state=$(aws kms describe-key --region "${region}" --key-id "${kms_key_id}" --query 'KeyMetadata.KeyState' --output text)
  if [[ "${key_state}" == "Enabled" ]]; then
    break
  fi
  sleep 5
done

instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi

if [[ -z "${instance_id}" ]]; then
  echo "InstanceID not found in ${output} for ${stack_name}" >&2
  exit 1
fi

echo "[deploy] Waiting for instance ${instance_id} to be ready..."
aws ec2 wait instance-status-ok --region "${region}" --instance-ids "${instance_id}"

echo "[deploy] Waiting for enclave to be running on ${instance_id}..."
max_attempts=60
for attempt in $(seq 1 $max_attempts); do
  if pcr0_out=$(./scripts/get_pcr0.sh "${instance_id}" 2>/dev/null) && [[ -n "${pcr0_out}" ]]; then
    echo "[deploy] Enclave is running (PCR0: ${pcr0_out:0:16}...)"
    break
  fi
  if [[ $attempt -eq $max_attempts ]]; then
    echo "Enclave did not start after ${max_attempts} attempts" >&2
    exit 1
  fi
  echo "[deploy] Enclave not ready yet (attempt ${attempt}/${max_attempts}), waiting 30s..."
  sleep 30
done

echo "[deploy] Applying KMS key policy with enclave PCR0..."
./scripts/generate_kms_key_policy.sh "${output}" >/tmp/introspector_kms_policy.json

secret_hex=$(openssl rand -hex 32)
secret_bin=$(mktemp)
trap 'rm -f "${secret_bin}"' EXIT
echo -n "${secret_hex}" | xxd -r -p > "${secret_bin}"

echo "[deploy] Encrypting secret key with KMS..."
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

echo "[deploy] Storing ciphertext in SSM parameter ${param_name}..."
aws ssm put-parameter \
  --region "${region}" \
  --name "${param_name}" \
  --type String \
  --overwrite \
  --value "${ciphertext_b64}"

echo "[deploy] Done."
echo "INTROSPECTOR_SECRET_KEY (hex): ${secret_hex}"
