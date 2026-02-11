#!/usr/bin/env bash
# Schedules deletion of the current KMS key via the enclave's debug endpoint.
#
# This calls POST /v1/delete-kms-key on the running enclave, which schedules
# the KMS key for deletion with a 7-day pending window. The endpoint is
# one-shot and authenticated with a migration token stored in SSM.
#
# After the 7-day window, the key is permanently deleted and the enclave
# can no longer decrypt its signing key on reboot.
#
# Usage:
#   ./scripts/delete_kms_key.sh [cdk-outputs.json]
#
# Requires:
#   - CDK_DEPLOY_REGION environment variable
#   - A running enclave instance

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

get_output() {
  local key=$1
  jq -r --arg stack "${stack_name}" --arg key "${key}" '.[$stack][$key] // empty' "${output}"
}

instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi
if [[ -z "${instance_id}" ]]; then
  echo "InstanceID not found in ${output}" >&2
  exit 1
fi

# Read current KMS key ID from SSM for display.
kms_key_id=$(aws ssm get-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/KMSKeyID" \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "unknown")

echo ""
echo "============================================================"
echo "  WARNING: This schedules the KMS key for DELETION"
echo "============================================================"
echo ""
echo "  Instance ID: ${instance_id}"
echo "  KMS Key ID:  ${kms_key_id}"
echo "  Region:      ${region}"
echo ""
echo "  The key will be deleted after a 7-day pending window."
echo "  The enclave will NOT be able to decrypt on reboot after deletion."
echo ""
read -r -p "  Type 'DELETE' to proceed: " confirmation

if [[ "${confirmation}" != "DELETE" ]]; then
  echo "Aborted." >&2
  exit 1
fi

# Step 1: Generate and store migration token in SSM.
token=$(openssl rand -hex 32)
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/MigrationToken" \
  --value "${token}" --type String --overwrite >/dev/null
echo "[delete] Migration token stored in SSM"

# Step 2: Call the enclave's delete endpoint via SSM Run Command.
echo "[delete] Calling POST /v1/delete-kms-key on enclave..."
command_id=$(aws ssm send-command \
  --region "${region}" \
  --instance-ids "${instance_id}" \
  --document-name "AWS-RunShellScript" \
  --parameters "{\"commands\":[\"curl -sf -k https://127.0.0.1:443/v1/delete-kms-key -X POST -H 'Authorization: Bearer ${token}'\"]}" \
  --timeout-seconds 60 \
  --query 'Command.CommandId' --output text)

# Step 3: Wait for command to complete.
while true; do
  sleep 3
  status=$(aws ssm get-command-invocation \
    --region "${region}" \
    --command-id "${command_id}" \
    --instance-id "${instance_id}" \
    --query 'Status' --output text 2>/dev/null || echo "Pending")
  case "${status}" in
    Success)
      echo "[delete] Done. KMS key ${kms_key_id} scheduled for deletion (7-day pending window)."
      # Show the response from the enclave.
      aws ssm get-command-invocation \
        --region "${region}" \
        --command-id "${command_id}" \
        --instance-id "${instance_id}" \
        --query 'StandardOutputContent' --output text 2>/dev/null || true
      break ;;
    Failed|TimedOut|Cancelled|Cancelling)
      echo "[delete] Command failed (${status}):" >&2
      aws ssm get-command-invocation \
        --region "${region}" \
        --command-id "${command_id}" \
        --instance-id "${instance_id}" \
        --query 'StandardErrorContent' --output text 2>/dev/null || true
      exit 1 ;;
    InProgress|Pending|Delayed) ;;
  esac
done

# Step 4: Clean up migration token.
aws ssm put-parameter --region "${region}" \
  --name "/${prefix}/NitroIntrospector/MigrationToken" \
  --value "UNSET" --type String --overwrite >/dev/null
echo "[delete] Migration token cleared"
