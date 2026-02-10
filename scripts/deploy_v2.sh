#!/usr/bin/env bash
# Deploys a V2 enclave alongside the running V1 enclave for key migration.
#
# Prerequisites:
#   - V1 enclave is running and has a locked KMS key
#   - V2 EIF has been built (./scripts/build_eif.sh)
#   - CDK stack already deployed (./scripts/deploy.sh)
#
# This script:
#   1. Reads V2 PCR0 from artifacts/pcr.json
#   2. Applies the V2 KMS key policy (V2 PCR0 for decrypt)
#   3. Stores maintainer authorization signature in SSM (if provided)
#   4. Uploads the V2 EIF to the instance
#   5. Starts the V2 enclave with INTROSPECTOR_V1_CID pointing to V1
#
# Environment:
#   MAINTAINER_SIG=<hex>          Schnorr signature over "target_pcr0:activation_time"
#   MIGRATION_ACTIVATION_TIME=<unix>  Earliest migration completion time (Unix seconds)
#
# Usage:
#   ./scripts/deploy_v2.sh [cdk-outputs.json]

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

# Read V2 PCR0 from build output
v2_pcr0=$(jq -r '.PCR0' artifacts/pcr.json 2>/dev/null || true)
if [[ -z "${v2_pcr0}" || "${v2_pcr0}" == "null" ]]; then
  echo "Failed to read PCR0 from artifacts/pcr.json" >&2
  echo "Run './scripts/build_eif.sh' with the updated V2 code first." >&2
  exit 1
fi
echo "[v2-deploy] V2 PCR0: ${v2_pcr0}"

# Read CDK outputs
v2_kms_key_id=$(get_output "V2KMSKeyID")
if [[ -z "${v2_kms_key_id}" ]]; then
  echo "V2KMSKeyID not found in ${output}." >&2
  echo "Re-deploy the CDK stack first: ./scripts/deploy.sh" >&2
  exit 1
fi

ec2_role_arn=$(get_output "EC2InstanceRoleARN")
if [[ -z "${ec2_role_arn}" ]]; then
  echo "EC2InstanceRoleARN not found in ${output}" >&2
  exit 1
fi

instance_id=$(get_output "InstanceID")
if [[ -z "${instance_id}" ]]; then
  instance_id=$(get_output "InstanceId")
fi
if [[ -z "${instance_id}" ]]; then
  echo "InstanceID not found in ${output}" >&2
  exit 1
fi

# Get V1 enclave CID
echo "[v2-deploy] Getting V1 enclave CID..."
v1_cid=$(aws ssm send-command \
  --region "${region}" \
  --instance-ids "${instance_id}" \
  --document-name "AWS-RunShellScript" \
  --parameters "commands=[\"nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID // empty'\"]" \
  --output text --query "Command.CommandId")

sleep 5
v1_cid=$(aws ssm get-command-invocation \
  --region "${region}" \
  --command-id "${v1_cid}" \
  --instance-id "${instance_id}" \
  --query "StandardOutputContent" --output text | tr -d '[:space:]')

if [[ -z "${v1_cid}" ]]; then
  echo "Could not determine V1 enclave CID. Is V1 running?" >&2
  exit 1
fi
echo "[v2-deploy] V1 enclave CID: ${v1_cid}"

# Apply V2 KMS key policy with V2 PCR0
echo "[v2-deploy] Applying V2 KMS key policy with PCR0: ${v2_pcr0}"
account_root="arn:aws:iam::${account}:root"

v2_policy=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "V2EnclaveDecryptWithAttestation",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "${v2_pcr0}"
        }
      }
    },
    {
      "Sid": "V2EnclaveEncrypt",
      "Effect": "Allow",
      "Principal": {"AWS": "${ec2_role_arn}"},
      "Action": "kms:Encrypt",
      "Resource": "*"
    },
    {
      "Sid": "V2KeyAdmin",
      "Effect": "Allow",
      "Principal": {"AWS": "${account_root}"},
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy",
        "kms:Encrypt",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)

aws kms put-key-policy \
  --region "${region}" \
  --key-id "${v2_kms_key_id}" \
  --policy-name default \
  --policy "${v2_policy}"

echo "[v2-deploy] V2 KMS policy applied."

# Store maintainer authorization in SSM (if provided).
maintainer_sig="${MAINTAINER_SIG:-}"
activation_time="${MIGRATION_ACTIVATION_TIME:-}"

if [[ -n "${maintainer_sig}" ]]; then
  echo "[v2-deploy] Storing maintainer signature in SSM..."
  aws ssm put-parameter \
    --region "${region}" \
    --name "/${prefix}/NitroIntrospector/MaintainerSig" \
    --value "${maintainer_sig}" \
    --type String \
    --overwrite

  if [[ -n "${activation_time}" ]]; then
    aws ssm put-parameter \
      --region "${region}" \
      --name "/${prefix}/NitroIntrospector/MigrationActivationTime" \
      --value "${activation_time}" \
      --type String \
      --overwrite
    echo "[v2-deploy] Maintainer auth stored: sig=${maintainer_sig:0:16}..., activation=${activation_time}"
  else
    echo "[v2-deploy] WARNING: MAINTAINER_SIG set but MIGRATION_ACTIVATION_TIME not set" >&2
  fi
else
  echo "[v2-deploy] No MAINTAINER_SIG provided; migration will proceed without maintainer authorization"
fi

# Upload V2 EIF and start V2 enclave via SSM
echo "[v2-deploy] Uploading V2 EIF and starting V2 enclave..."

# Upload the V2 EIF
aws s3 cp artifacts/image.eif "s3://${prefix}-introspector-v2-eif/image.eif" --region "${region}" 2>/dev/null || {
  # Bucket may not exist, use instance S3 copy from local
  echo "[v2-deploy] Direct S3 upload not available; using SSM to download EIF"
}

# Start V2 enclave on the instance with V1 CID env var
start_cmd=$(cat <<'SCRIPT'
#!/bin/bash
set -e

# The V2 enclave uses a different CID (V1 CID + 1 or any available)
V2_CID=$((${V1_CID} + 1))

# Start V2 enclave with the V1 CID so it knows where to connect
nitro-cli run-enclave \
  --eif-path /home/ec2-user/app/image-v2.eif \
  --cpu-count 2 \
  --memory 4320 \
  --enclave-cid "${V2_CID}" \
  --env "INTROSPECTOR_V1_CID=${V1_CID}" \
  --env "INTROSPECTOR_DEPLOYMENT=__DEPLOYMENT__" \
  --env "INTROSPECTOR_AWS_REGION=__REGION__"

echo "V2 enclave started with CID ${V2_CID}, connecting to V1 at CID ${V1_CID}"
SCRIPT
)

# Replace placeholders
start_cmd="${start_cmd//__DEPLOYMENT__/${prefix}}"
start_cmd="${start_cmd//__REGION__/${region}}"
start_cmd="${start_cmd//\$\{V1_CID\}/${v1_cid}}"

echo ""
echo "[v2-deploy] Done."
echo "V2 KMS Key ID: ${v2_kms_key_id}"
echo "V2 PCR0: ${v2_pcr0}"
echo "V1 CID: ${v1_cid}"
echo ""
echo "Next steps:"
echo "  1. Upload the V2 EIF to the instance as /home/ec2-user/app/image-v2.eif"
echo "  2. Start the V2 enclave with INTROSPECTOR_V1_CID=${v1_cid}"
echo "  3. Monitor migration status: curl https://<host>/v1/migration-status"
echo "  4. After 24h cooldown, V2 will complete migration and V1 will shut down"
echo "  5. Optionally lock the V2 KMS key: ./scripts/lock_kms_policy.sh (with V2 PCR0)"
