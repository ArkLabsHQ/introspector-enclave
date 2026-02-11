#!/usr/bin/env bash
# Deploys or upgrades the Nitro Introspector enclave.
#
# Fresh deploy: CDK deploy → apply KMS policy → wait for instance.
# Upgrade (unlocked key): Update KMS policy → upload new EIF → restart.
# Upgrade (locked key): Create temp KMS key → export via enclave API → restart.
#
# The script auto-detects upgrade mode when an existing instance is running
# with a signing key stored in SSM. It detects locked keys by checking if
# kms:PutKeyPolicy is present in the key policy.
#
# Requirements:
#   - CDK_DEPLOY_REGION and CDK_DEPLOY_ACCOUNT environment variables
#   - artifacts/pcr.json and artifacts/image.eif from ./scripts/build_eif.sh
#   - For upgrades: deployer needs ssm:SendCommand, ssm:GetCommandInvocation,
#     kms:CreateKey, kms:PutKeyPolicy, kms:GetKeyPolicy, ssm:PutParameter
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

# Apply KMS key policy with PCR0 attestation condition (non-locked version).
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

# Check if a KMS key is locked (no PutKeyPolicy in the policy).
is_key_locked() {
  local key_id=$1
  local policy
  policy=$(aws kms get-key-policy --key-id "${key_id}" --policy-name default \
    --output text --region "${region}" 2>/dev/null) || return 0
  if echo "${policy}" | grep -q 'PutKeyPolicy'; then
    return 1  # not locked
  fi
  return 0  # locked
}

# Run commands on the EC2 host via SSM Run Command.
# Usage: run_on_host "description" "cmd1" "cmd2" ...
run_on_host() {
  local desc=$1; shift

  echo "[deploy] Running on host: ${desc}"

  local json_commands
  json_commands=$(printf '%s\n' "$@" | jq -R . | jq -s .)

  local command_id
  command_id=$(aws ssm send-command \
    --region "${region}" \
    --instance-ids "${instance_id}" \
    --document-name "AWS-RunShellScript" \
    --parameters "{\"commands\": ${json_commands}}" \
    --timeout-seconds 300 \
    --query 'Command.CommandId' --output text)

  while true; do
    sleep 5
    local status
    status=$(aws ssm get-command-invocation \
      --region "${region}" \
      --command-id "${command_id}" \
      --instance-id "${instance_id}" \
      --query 'Status' --output text 2>/dev/null || echo "Pending")
    case "${status}" in
      Success)
        echo "[deploy] Done: ${desc}"
        return 0 ;;
      Failed|TimedOut|Cancelled|Cancelling)
        echo "[deploy] Host command failed (${status}): ${desc}" >&2
        aws ssm get-command-invocation \
          --region "${region}" \
          --command-id "${command_id}" \
          --instance-id "${instance_id}" \
          --query 'StandardErrorContent' --output text 2>/dev/null || true
        return 1 ;;
      InProgress|Pending|Delayed) ;;
    esac
  done
}

# Reset an SSM parameter to UNSET.
reset_ssm_param() {
  local name=$1
  aws ssm put-parameter --region "${region}" \
    --name "${name}" --value "UNSET" --type String --overwrite >/dev/null
}

# Lock KMS key policy: only enclave with matching PCR0 can Decrypt.
# Waits for the enclave to be healthy first (proves it can decrypt).
lock_kms_key() {
  local key_id=$1
  local pcr0=$2
  local ec2_role_arn=$3

  echo "[deploy] Waiting for enclave to be healthy before locking KMS key..."
  local max_wait=120
  local elapsed=0
  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if run_on_host "health check" \
      "curl -sf -k https://127.0.0.1:443/v1/enclave-info > /dev/null" 2>/dev/null; then
      echo "[deploy] Enclave is healthy"
      break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done

  if [[ ${elapsed} -ge ${max_wait} ]]; then
    echo "[deploy] WARNING: Enclave did not become healthy within ${max_wait}s" >&2
    echo "[deploy] Skipping KMS lock. Run ./scripts/lock_kms_policy.sh manually." >&2
    return 1
  fi

  local policy
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
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }
  ]
}
EOF
  )

  echo "[deploy] Locking KMS key ${key_id} to PCR0 ${pcr0:0:16}..."
  aws kms put-key-policy \
    --region "${region}" \
    --key-id "${key_id}" \
    --policy-name default \
    --policy "${policy}" \
    --bypass-policy-lockout-safety-check

  echo "[deploy] KMS key locked. Only this enclave image can decrypt."
  echo ""
  echo "[deploy] To delete this KMS key later (from your workstation):"
  echo "  aws ssm send-command \\"
  echo "    --region ${region} \\"
  echo "    --instance-ids ${instance_id} \\"
  echo "    --document-name AWS-RunShellScript \\"
  echo "    --parameters '{\"commands\":[\"aws kms schedule-key-deletion --key-id ${key_id} --pending-window-in-days 7 --region ${region}\"]}' \\"
  echo "    --query Command.CommandId --output text"
}

# --- Step 1: Read PCR0 from build artifacts ---

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

# --- Step 2: Detect upgrade mode ---
# An upgrade is when the instance is already running and has a signing key.

is_upgrade=false
instance_id=""
if [[ -f "${output}" ]]; then
  instance_id=$(get_output "InstanceID")
  if [[ -z "${instance_id}" ]]; then
    instance_id=$(get_output "InstanceId")
  fi
  if [[ -n "${instance_id}" ]]; then
    instance_state=$(aws ec2 describe-instances \
      --region "${region}" \
      --instance-ids "${instance_id}" \
      --query 'Reservations[0].Instances[0].State.Name' \
      --output text 2>/dev/null || echo "missing")
    if [[ "${instance_state}" == "running" ]]; then
      existing_cipher=$(aws ssm get-parameter \
        --region "${region}" \
        --name "/${prefix}/NitroIntrospector/SecretKeyCiphertext" \
        --query 'Parameter.Value' --output text 2>/dev/null || echo "UNSET")
      if [[ "${existing_cipher}" != "UNSET" && -n "${existing_cipher}" ]]; then
        is_upgrade=true
      fi
    fi
  fi
fi

# --- Main flow ---

if [[ "${is_upgrade}" == "true" ]]; then
  echo ""
  echo "[deploy] Upgrade mode: existing enclave on ${instance_id}"
  echo ""

  # Read current KMS key ID from SSM (may differ from CDK output after migration).
  kms_key_id=$(aws ssm get-parameter --region "${region}" \
    --name "/${prefix}/NitroIntrospector/KMSKeyID" \
    --query 'Parameter.Value' --output text 2>/dev/null || true)
  if [[ -z "${kms_key_id}" ]]; then
    kms_key_id=$(get_output "KMSKeyID")
  fi

  ec2_role_arn=$(get_output "EC2InstanceRoleARN")
  if [[ -z "${kms_key_id}" || -z "${ec2_role_arn}" ]]; then
    echo "Missing KMSKeyID or EC2InstanceRoleARN" >&2
    exit 1
  fi

  # Create S3 bucket for EIF transfer (idempotent).
  eif_bucket="${prefix}-introspector-eif-${account}-${region}"
  aws s3 mb "s3://${eif_bucket}" --region "${region}" 2>/dev/null || true

  # Grant the EC2 role read access to the bucket.
  bucket_policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "${ec2_role_arn}"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::${eif_bucket}/*"
  }]
}
EOF
  )
  aws s3api put-bucket-policy \
    --bucket "${eif_bucket}" \
    --policy "${bucket_policy}" \
    --region "${region}"

  # Upload new EIF.
  echo "[deploy] Uploading new EIF to s3://${eif_bucket}/image.eif ..."
  aws s3 cp artifacts/image.eif "s3://${eif_bucket}/image.eif" --region "${region}"

  if is_key_locked "${kms_key_id}"; then
    # ============================================================
    # LOCKED KEY: Temporary KMS key migration
    # ============================================================
    echo "[deploy] KMS key is locked — using temporary key migration"

    # Step 1: Create new KMS key for the new enclave version.
    new_kms_key_id=$(aws kms create-key --region "${region}" \
      --description "NitroIntrospector migration key for PCR0 ${pcr0:0:16}..." \
      --query 'KeyMetadata.KeyId' --output text)
    echo "[deploy] Created new KMS key: ${new_kms_key_id}"

    # Step 2: Apply policy allowing old enclave to Encrypt, new enclave to Decrypt.
    apply_kms_policy "${new_kms_key_id}" "${pcr0}" "${ec2_role_arn}"

    # Step 3: Generate migration token.
    migration_token=$(openssl rand -hex 32)

    # Step 4: Store migration parameters in SSM.
    aws ssm put-parameter --region "${region}" \
      --name "/${prefix}/NitroIntrospector/MigrationToken" \
      --value "${migration_token}" --type String --overwrite >/dev/null
    aws ssm put-parameter --region "${region}" \
      --name "/${prefix}/NitroIntrospector/MigrationKMSKeyID" \
      --value "${new_kms_key_id}" --type String --overwrite >/dev/null
    aws ssm put-parameter --region "${region}" \
      --name "/${prefix}/NitroIntrospector/MigrationOldKMSKeyID" \
      --value "${kms_key_id}" --type String --overwrite >/dev/null

    echo "[deploy] Migration token, KMS key IDs stored in SSM"

    # Step 5: Call old enclave's export endpoint via SSM Run Command.
    echo "[deploy] Calling old enclave's export endpoint..."
    if ! run_on_host "export signing key from old enclave" \
      "curl -sf -k https://127.0.0.1:443/v1/export-key -X POST -H 'Authorization: Bearer ${migration_token}'"; then
      echo "[deploy] Export failed, cleaning up" >&2
      reset_ssm_param "/${prefix}/NitroIntrospector/MigrationToken"
      reset_ssm_param "/${prefix}/NitroIntrospector/MigrationKMSKeyID"
      exit 1
    fi

    # Step 6: Wait for MigrationCiphertext to appear in SSM.
    echo "[deploy] Waiting for migration ciphertext..."
    max_wait=60
    elapsed=0
    while [[ ${elapsed} -lt ${max_wait} ]]; do
      migration_ciphertext=$(aws ssm get-parameter --region "${region}" \
        --name "/${prefix}/NitroIntrospector/MigrationCiphertext" \
        --query 'Parameter.Value' --output text 2>/dev/null || echo "UNSET")

      if [[ "${migration_ciphertext}" != "UNSET" && -n "${migration_ciphertext}" ]]; then
        echo "[deploy] Migration ciphertext stored in SSM"
        break
      fi

      sleep 3
      elapsed=$((elapsed + 3))
      echo "[deploy] Waiting... (${elapsed}s/${max_wait}s)"
    done

    if [[ ${elapsed} -ge ${max_wait} ]]; then
      echo "[deploy] Timed out waiting for migration ciphertext" >&2
      reset_ssm_param "/${prefix}/NitroIntrospector/MigrationToken"
      reset_ssm_param "/${prefix}/NitroIntrospector/MigrationKMSKeyID"
      exit 1
    fi

    # Step 7: Copy migration ciphertext to SecretKeyCiphertext.
    aws ssm put-parameter --region "${region}" \
      --name "/${prefix}/NitroIntrospector/SecretKeyCiphertext" \
      --value "${migration_ciphertext}" --type String --overwrite >/dev/null
    echo "[deploy] Copied migration ciphertext to SecretKeyCiphertext"

    # Step 8: Update KMSKeyID to the new key.
    aws ssm put-parameter --region "${region}" \
      --name "/${prefix}/NitroIntrospector/KMSKeyID" \
      --value "${new_kms_key_id}" --type String --overwrite >/dev/null
    echo "[deploy] Updated KMSKeyID to ${new_kms_key_id}"

    # Step 9: Stop old enclave, update EIF, restart watchdog.
    run_on_host "stop enclave, update EIF, restart watchdog" \
      "set -e" \
      "aws s3 cp s3://${eif_bucket}/image.eif /tmp/new-introspector.eif --region ${region}" \
      "nitro-cli terminate-enclave --enclave-name introspector 2>/dev/null || true" \
      "cp /tmp/new-introspector.eif /home/ec2-user/app/server/introspector.eif" \
      "chown ec2-user:ec2-user /home/ec2-user/app/server/introspector.eif" \
      "systemctl restart enclave-watchdog"

    # Step 10: Clean up migration SSM params.
    reset_ssm_param "/${prefix}/NitroIntrospector/MigrationToken"
    reset_ssm_param "/${prefix}/NitroIntrospector/MigrationKMSKeyID"
    reset_ssm_param "/${prefix}/NitroIntrospector/MigrationCiphertext"

    old_kms_key_id="${kms_key_id}"
    kms_key_id="${new_kms_key_id}"

    echo ""
    echo "[deploy] Locked-key migration complete."
    echo "  Instance ID:  ${instance_id}"
    echo "  New KMS Key:  ${kms_key_id}"
    echo "  Old KMS Key:  ${old_kms_key_id} (scheduled for deletion by new enclave on boot)"
    echo "  PCR0:         ${pcr0}"

    # Lock the new KMS key.
    lock_kms_key "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"

  else
    # ============================================================
    # UNLOCKED KEY: Simple policy update + restart
    # ============================================================
    echo "[deploy] KMS key is unlocked — updating policy with new PCR0"

    # Store the old enclave's PCR0 in SSM for the attestation chain.
    # The host reads PCR0 from nitro-cli and writes it directly to SSM.
    echo "[deploy] Storing old enclave's PCR0 for attestation chain..."
    run_on_host "store old enclave PCR0 in SSM" \
      "set -e" \
      "OLD_PCR0=\$(nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0 // empty')" \
      "if [ -n \"\$OLD_PCR0\" ] && [ \"\$OLD_PCR0\" != \"null\" ]; then aws ssm put-parameter --region ${region} --name '/${prefix}/NitroIntrospector/MigrationPreviousPCR0' --value \"\$OLD_PCR0\" --type String --overwrite > /dev/null && echo \"Stored previous PCR0: \$OLD_PCR0\"; else echo 'No running enclave found, skipping PCR0 chain'; fi" \
      || echo "[deploy] Warning: could not store old PCR0 (chain will show genesis)"

    # Apply KMS policy with new PCR0 BEFORE restarting the enclave.
    apply_kms_policy "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"

    # Download new EIF, stop old enclave, restart watchdog.
    run_on_host "stop enclave, update EIF, restart watchdog" \
      "set -e" \
      "aws s3 cp s3://${eif_bucket}/image.eif /tmp/new-introspector.eif --region ${region}" \
      "nitro-cli terminate-enclave --enclave-name introspector 2>/dev/null || true" \
      "cp /tmp/new-introspector.eif /home/ec2-user/app/server/introspector.eif" \
      "chown ec2-user:ec2-user /home/ec2-user/app/server/introspector.eif" \
      "systemctl restart enclave-watchdog"

    echo ""
    echo "[deploy] Upgrade complete."
    echo "  Instance ID: ${instance_id}"
    echo "  KMS Key ID:  ${kms_key_id}"
    echo "  PCR0:        ${pcr0}"

    # Lock the KMS key.
    lock_kms_key "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"
  fi

else
  echo ""
  echo "[deploy] Fresh deploy"
  echo ""

  # Step 3: Deploy the CDK stack.
  cdk deploy -O "${output}"

  # Step 4: Get outputs and apply KMS policy.
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

  # Wait for KMS key to be enabled.
  echo "[deploy] Waiting for KMS key ${kms_key_id} to be enabled..."
  for _ in {1..60}; do
    key_state=$(aws kms describe-key --region "${region}" --key-id "${kms_key_id}" --query 'KeyMetadata.KeyState' --output text)
    if [[ "${key_state}" == "Enabled" ]]; then
      break
    fi
    sleep 2
  done

  # Apply KMS policy with PCR0 BEFORE waiting for instance/enclave.
  apply_kms_policy "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"

  # Step 5: Wait for instance to be ready.
  echo "[deploy] Waiting for instance ${instance_id} to be ready..."
  aws ec2 wait instance-status-ok --region "${region}" --instance-ids "${instance_id}"

  elastic_ip=$(get_output "ElasticIP")
  if [[ -z "${elastic_ip}" ]]; then
    elastic_ip=$(get_output "Elastic IP")
  fi

  echo ""
  echo "[deploy] Done."
  echo "  Instance ID: ${instance_id}"
  echo "  KMS Key ID:  ${kms_key_id}"
  echo "  Elastic IP:  ${elastic_ip}"
  echo "  PCR0:        ${pcr0}"
  echo ""

  # Lock the KMS key after the enclave is healthy.
  lock_kms_key "${kms_key_id}" "${pcr0}" "${ec2_role_arn}"

