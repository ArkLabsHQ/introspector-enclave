package sdk

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// selfApplyKMSPolicy applies the PCR0-restricted KMS key policy from inside
// the enclave. The enclave reads its own PCR0 from NSM hardware (unforgeable),
// derives its role ARN and account ID via STS, and calls PutKeyPolicy to
// restrict Decrypt to its own attestation identity.
//
// This is idempotent: if the policy already contains the correct PCR0, or if
// the key is locked (no PutKeyPolicy permission), the function returns nil.
func selfApplyKMSPolicy(ctx context.Context) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	kmsClient := kms.NewFromConfig(awsCfg)
	stsClient := sts.NewFromConfig(awsCfg)

	keyID, err := getKMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get KMS key ID: %w", err)
	}

	// Check if key is already locked (no PutKeyPolicy in current policy).
	currentPolicy, err := kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		// If we can't read the policy, the key may be locked. Skip silently.
		log.Printf("kms_policy: cannot read current policy (key may be locked): %v", err)
		return nil
	}
	if currentPolicy.Policy == nil || !strings.Contains(*currentPolicy.Policy, "PutKeyPolicy") {
		log.Println("kms_policy: key is locked, skipping self-apply")
		return nil
	}

	// Get own PCR0 from NSM hardware.
	pcr0 := getPCR0()
	if pcr0 == "" {
		return fmt.Errorf("could not read PCR0 from NSM")
	}

	// Check if policy already has this PCR0 (idempotent on reboot).
	if strings.Contains(*currentPolicy.Policy, pcr0) {
		log.Printf("kms_policy: policy already contains PCR0 %s..., skipping", pcr0[:16])
		return nil
	}

	// Get caller identity for role ARN and account ID.
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("sts get-caller-identity: %w", err)
	}

	roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
	if err != nil {
		return fmt.Errorf("parse role ARN: %w", err)
	}

	policy := buildKMSPolicy(roleARN, pcr0)

	// Retry with backoff to handle IAM propagation delay on fresh deploy.
	// BypassPolicyLockoutSafetyCheck is required because we're removing
	// PutKeyPolicy from everyone — the key becomes immutably locked.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		_, err = kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
			KeyId:                          aws.String(keyID),
			Policy:                         aws.String(policy),
			BypassPolicyLockoutSafetyCheck: true,
		})
		if err == nil {
			log.Printf("kms_policy: applied PCR0-restricted policy (PCR0=%s...)", pcr0[:16])
			return nil
		}
		lastErr = err
		log.Printf("kms_policy: PutKeyPolicy attempt %d failed: %v", attempt+1, err)
	}

	return fmt.Errorf("kms put-key-policy after retries: %w", lastErr)
}

// assumedRoleARNToRoleARN converts an STS assumed-role ARN to an IAM role ARN.
//
//	arn:aws:sts::123456789012:assumed-role/MyRole/i-abc123
//	→ arn:aws:iam::123456789012:role/MyRole
func assumedRoleARNToRoleARN(arn string) (string, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ARN: %s", arn)
	}
	resource := parts[5] // assumed-role/ROLE_NAME/SESSION_NAME
	segments := strings.SplitN(resource, "/", 3)
	if len(segments) < 2 || segments[0] != "assumed-role" {
		return "", fmt.Errorf("not an assumed-role ARN: %s", arn)
	}
	roleName := segments[1]
	account := parts[4]
	partition := parts[1]
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, account, roleName), nil
}

// buildKMSPolicy builds a locked KMS key policy: Decrypt is restricted to the
// enclave's PCR0 via attestation, Encrypt is unrestricted for the EC2 role,
// and ScheduleKeyDeletion is allowed for old-key cleanup during migration.
// No PutKeyPolicy is granted to anyone — the key is immutably locked to this PCR0.
func buildKMSPolicy(ec2RoleARN, pcr0 string) string {
	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnclaveDecryptWithAttestation",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": %q
        }
      }
    },
    {
      "Sid": "EnclaveEncrypt",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:Encrypt",
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyDeletion",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*"
    }
  ]
}`, ec2RoleARN, pcr0, ec2RoleARN, ec2RoleARN)
}
