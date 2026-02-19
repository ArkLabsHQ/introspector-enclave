package introspector_enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func deployCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deploy",
		Short: "Deploy or upgrade the enclave",
		Long: `Deploy a new EIF to a running enclave instance.

Fresh deploy: CDK deploy → apply KMS policy → wait for instance.
Upgrade (unlocked key): Update KMS policy → upload new EIF → restart.
Upgrade (locked key): Create temp KMS key → export via enclave API → restart.

Requires 'enclave build' to have been run first (enclave/artifacts/pcr.json and enclave/artifacts/image.eif).`,
		RunE: runDeploy,
	}
}

func runDeploy(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validateSDK(); err != nil {
		return err
	}
	if err := cfg.validateAccount(); err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	// Step 1: Read PCR0 from build artifacts.
	pcr0, err := readPCR0(root)
	if err != nil {
		return err
	}
	fmt.Printf("[deploy] PCR0 from build: %s\n", pcr0)

	// Step 2: Detect upgrade mode.
	// An upgrade is when the instance is already running with initialized secrets.
	stack := cfg.stackName()
	outputsPath := filepath.Join(root, "enclave", "cdk-outputs.json")

	isUpgrade := false
	var instanceID string

	if _, err := os.Stat(outputsPath); err == nil {
		outputs, err := loadCDKOutputs(root)
		if err == nil {
			instanceID = outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
			if instanceID != "" {
				state, stateErr := ac.getInstanceState(ctx, instanceID)
				if stateErr == nil && state == "running" && len(cfg.Secrets) > 0 {
					cipher, _ := ac.getParameter(ctx, cfg.ssmParam(cfg.Secrets[0].Name+"/Ciphertext"))
					if cipher != "" && cipher != "UNSET" {
						isUpgrade = true
					}
				}
			}
		}
	}

	if isUpgrade {
		fmt.Printf("\n[deploy] Upgrade mode: existing enclave on %s\n\n", instanceID)

		outputs, err := loadCDKOutputs(root)
		if err != nil {
			return err
		}

		// Read current KMS key ID from SSM (may differ from CDK output after migration).
		kmsKeyID, _ := ac.getParameter(ctx, cfg.ssmParam("KMSKeyID"))
		if kmsKeyID == "" {
			kmsKeyID = outputs.getOutput(stack, "KMSKeyID", "KmsKeyId", "KMS Key ID")
		}

		ec2RoleARN := outputs.getOutput(stack, "EC2InstanceRoleARN")
		if kmsKeyID == "" || ec2RoleARN == "" {
			return fmt.Errorf("missing KMSKeyID or EC2InstanceRoleARN from CDK outputs")
		}

		return deployUpgrade(ctx, ac, cfg, root, pcr0, instanceID, kmsKeyID, ec2RoleARN)
	}

	fmt.Printf("\n[deploy] Fresh deploy\n\n")
	return deployFresh(ctx, ac, cfg, root, pcr0)
}

// deployFresh handles first-time deployment: CDK deploy → KMS policy → wait for instance.
func deployFresh(ctx context.Context, ac *awsClients, cfg *Config, root, pcr0 string) error {
	// Synthesize and deploy the CDK stack.
	if err := runCDKDeploy(cfg, root); err != nil {
		return err
	}

	// Read outputs.
	outputs, err := loadCDKOutputs(root)
	if err != nil {
		return err
	}

	stack := cfg.stackName()
	kmsKeyID := outputs.getOutput(stack, "KMSKeyID", "KmsKeyId", "KMS Key ID")
	if kmsKeyID == "" {
		return fmt.Errorf("KMSKeyID not found in cdk-outputs.json for %s", stack)
	}
	ec2RoleARN := outputs.getOutput(stack, "EC2InstanceRoleARN")
	if ec2RoleARN == "" {
		return fmt.Errorf("EC2InstanceRoleARN not found in cdk-outputs.json for %s", stack)
	}
	instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	if instanceID == "" {
		return fmt.Errorf("InstanceID not found in cdk-outputs.json for %s", stack)
	}

	// Wait for KMS key to be enabled.
	fmt.Printf("[deploy] Waiting for KMS key %s to be enabled...\n", kmsKeyID)
	for i := 0; i < 60; i++ {
		keyState, err := ac.getKeyState(ctx, kmsKeyID)
		if err == nil && keyState == "Enabled" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Apply KMS policy with PCR0.
	if err := applyKMSPolicy(ctx, ac, kmsKeyID, pcr0, ec2RoleARN, cfg.Account); err != nil {
		return err
	}

	// Wait for instance to be ready.
	fmt.Printf("[deploy] Waiting for instance %s to be ready...\n", instanceID)
	if err := ac.waitInstanceReady(ctx, instanceID); err != nil {
		return fmt.Errorf("waiting for instance: %w", err)
	}

	elasticIP := outputs.getOutput(stack, "ElasticIP", "Elastic IP")

	fmt.Println()
	fmt.Println("[deploy] Done.")
	fmt.Printf("  Instance ID: %s\n", instanceID)
	fmt.Printf("  KMS Key ID:  %s\n", kmsKeyID)
	fmt.Printf("  Elastic IP:  %s\n", elasticIP)
	fmt.Printf("  PCR0:        %s\n", pcr0)
	fmt.Println()

	if cfg.LockKMS {
		return lockKMSKey(ctx, ac, cfg, kmsKeyID, pcr0, ec2RoleARN, instanceID)
	}
	return nil
}

// deployUpgrade handles upgrading an existing enclave. Detects locked/unlocked key
// and uses the appropriate upgrade path.
func deployUpgrade(ctx context.Context, ac *awsClients, cfg *Config, root, pcr0, instanceID, kmsKeyID, ec2RoleARN string) error {
	// Create S3 bucket for EIF transfer (idempotent).
	eifBucket := cfg.eifBucket()
	ac.ensureBucket(ctx, eifBucket)

	// Grant EC2 role read access to the bucket.
	bucketPolicy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": %q},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::%s/*"
  }]
}`, ec2RoleARN, eifBucket)

	if err := ac.putBucketPolicy(ctx, eifBucket, bucketPolicy); err != nil {
		return fmt.Errorf("set bucket policy: %w", err)
	}

	// Upload new EIF.
	eifPath := filepath.Join(root, "enclave", "artifacts", "image.eif")
	if _, err := os.Stat(eifPath); os.IsNotExist(err) {
		return fmt.Errorf("enclave/artifacts/image.eif not found. Run 'enclave build' first.")
	}

	fmt.Printf("[deploy] Uploading new EIF to s3://%s/image.eif ...\n", eifBucket)
	if err := ac.uploadFile(ctx, eifBucket, "image.eif", eifPath); err != nil {
		return fmt.Errorf("upload EIF to S3: %w", err)
	}

	if isKeyLocked(ctx, ac, kmsKeyID) {
		return deployUpgradeLocked(ctx, ac, cfg, pcr0, instanceID, kmsKeyID, ec2RoleARN, eifBucket)
	}
	return deployUpgradeUnlocked(ctx, ac, cfg, pcr0, instanceID, kmsKeyID, ec2RoleARN, eifBucket)
}

// deployUpgradeUnlocked handles upgrade when the KMS key is unlocked:
// store old PCR0 → update KMS policy → download EIF on host → restart.
func deployUpgradeUnlocked(ctx context.Context, ac *awsClients, cfg *Config, pcr0, instanceID, kmsKeyID, ec2RoleARN, eifBucket string) error {
	fmt.Println("[deploy] KMS key is unlocked — updating policy with new PCR0")

	// Ask old enclave to store its PCR0 + attestation proof in SSM.
	// The enclave itself generates the NSM attestation document (unforgeable by host).
	fmt.Println("[deploy] Asking old enclave to store its PCR0 attestation proof...")
	prepareUpgradeCmd := `curl -sf -k -X POST https://127.0.0.1:443/v1/prepare-upgrade`
	if err := ac.runOnHost(ctx, instanceID, "prepare-upgrade (store PCR0 attestation)", []string{prepareUpgradeCmd}); err != nil {
		fmt.Println("[deploy] Warning: could not store PCR0 attestation (chain will show genesis)")
	}

	// Apply KMS policy with new PCR0 BEFORE restarting the enclave.
	if err := applyKMSPolicy(ctx, ac, kmsKeyID, pcr0, ec2RoleARN, cfg.Account); err != nil {
		return err
	}

	// Download new EIF, stop old enclave, restart watchdog.
	if err := restartEnclaveOnHost(ctx, ac, cfg, instanceID, eifBucket); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("[deploy] Upgrade complete.")
	fmt.Printf("  Instance ID: %s\n", instanceID)
	fmt.Printf("  KMS Key ID:  %s\n", kmsKeyID)
	fmt.Printf("  PCR0:        %s\n", pcr0)

	if cfg.LockKMS {
		return lockKMSKey(ctx, ac, cfg, kmsKeyID, pcr0, ec2RoleARN, instanceID)
	}
	return nil
}

// deployUpgradeLocked handles migration when the KMS key is locked:
// create temp KMS key → export signing key from old enclave → restart with new key.
func deployUpgradeLocked(ctx context.Context, ac *awsClients, cfg *Config, pcr0, instanceID, kmsKeyID, ec2RoleARN, eifBucket string) error {
	fmt.Println("[deploy] KMS key is locked — using temporary key migration")

	// Step 1: Create new KMS key for the new enclave version.
	newKMSKeyID, err := ac.createKey(ctx,
		fmt.Sprintf("%s migration key for PCR0 %s...", cfg.Name, pcr0[:16]))
	if err != nil {
		return fmt.Errorf("create migration KMS key: %w", err)
	}
	fmt.Printf("[deploy] Created new KMS key: %s\n", newKMSKeyID)

	// Step 2: Apply policy allowing new enclave to Decrypt.
	if err := applyKMSPolicy(ctx, ac, newKMSKeyID, pcr0, ec2RoleARN, cfg.Account); err != nil {
		return fmt.Errorf("apply policy to new KMS key: %w", err)
	}

	// Step 3: Store migration parameters in SSM.
	ssmParams := map[string]string{
		"MigrationKMSKeyID":    newKMSKeyID,
		"MigrationOldKMSKeyID": kmsKeyID,
	}
	for param, value := range ssmParams {
		if err := ac.putParameter(ctx, cfg.ssmParam(param), value); err != nil {
			return fmt.Errorf("store %s in SSM: %w", param, err)
		}
	}
	fmt.Println("[deploy] Migration KMS key IDs stored in SSM")

	// Step 4: Call old enclave's export endpoint via SSM.
	fmt.Println("[deploy] Calling old enclave's export endpoint...")
	exportCmd := `curl -sf -k -X POST https://127.0.0.1:443/v1/export-key`

	if err := ac.runOnHost(ctx, instanceID, "export secrets from old enclave", []string{exportCmd}); err != nil {
		fmt.Println("[deploy] Export failed, cleaning up")
		ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
		return fmt.Errorf("export secrets from old enclave: %w", err)
	}

	// Step 5: Wait for per-secret migration ciphertexts to appear in SSM.
	fmt.Println("[deploy] Waiting for migration ciphertexts...")
	maxWait := 60
	allFound := false
	for elapsed := 0; elapsed < maxWait; elapsed += 3 {
		found := 0
		for _, secret := range cfg.Secrets {
			ct, _ := ac.getParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
			if ct != "" && ct != "UNSET" {
				found++
			}
		}
		if found == len(cfg.Secrets) {
			allFound = true
			fmt.Printf("[deploy] All %d migration ciphertexts stored in SSM\n", found)
			break
		}
		time.Sleep(3 * time.Second)
		fmt.Printf("[deploy] Waiting... (%d/%d secrets, %ds/%ds)\n", found, len(cfg.Secrets), elapsed+3, maxWait)
	}

	if !allFound {
		ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
		return fmt.Errorf("timed out waiting for migration ciphertexts")
	}

	// Step 6: Copy each migration ciphertext to its permanent location.
	for _, secret := range cfg.Secrets {
		migCipher, _ := ac.getParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
		if err := ac.putParameter(ctx, cfg.ssmParam(secret.Name+"/Ciphertext"), migCipher); err != nil {
			return fmt.Errorf("copy migration ciphertext for %s: %w", secret.Name, err)
		}
	}
	fmt.Printf("[deploy] Copied %d migration ciphertexts to permanent locations\n", len(cfg.Secrets))

	// Step 7: Update KMSKeyID to the new key.
	if err := ac.putParameter(ctx, cfg.ssmParam("KMSKeyID"), newKMSKeyID); err != nil {
		return fmt.Errorf("update KMSKeyID: %w", err)
	}
	fmt.Printf("[deploy] Updated KMSKeyID to %s\n", newKMSKeyID)

	// Step 8: Stop old enclave, update EIF, restart watchdog.
	if err := restartEnclaveOnHost(ctx, ac, cfg, instanceID, eifBucket); err != nil {
		return err
	}

	// Step 9: Clean up migration SSM params.
	ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
	for _, secret := range cfg.Secrets {
		ac.resetParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
	}

	fmt.Println()
	fmt.Println("[deploy] Locked-key migration complete.")
	fmt.Printf("  Instance ID:  %s\n", instanceID)
	fmt.Printf("  New KMS Key:  %s\n", newKMSKeyID)
	fmt.Printf("  Old KMS Key:  %s (scheduled for deletion by new enclave on boot)\n", kmsKeyID)
	fmt.Printf("  PCR0:         %s\n", pcr0)

	if cfg.LockKMS {
		return lockKMSKey(ctx, ac, cfg, newKMSKeyID, pcr0, ec2RoleARN, instanceID)
	}
	return nil
}

// restartEnclaveOnHost downloads the new EIF from S3, replaces the EIF the watchdog
// uses (enclave.eif, matching EIF_PATH in /etc/environment), and restarts the watchdog.
// The watchdog's enclave name comes from ENCLAVE_NAME in /etc/environment (default "app").
func restartEnclaveOnHost(ctx context.Context, ac *awsClients, cfg *Config, instanceID, eifBucket string) error {
	return ac.runOnHost(ctx, instanceID, "stop enclave, update EIF, restart watchdog", []string{
		"set -e",
		fmt.Sprintf("aws s3 cp s3://%s/image.eif /tmp/new-enclave.eif --region %s", eifBucket, cfg.Region),
		`nitro-cli terminate-enclave --enclave-name "${ENCLAVE_NAME:-app}" 2>/dev/null || true`,
		"cp /tmp/new-enclave.eif /home/ec2-user/app/server/enclave.eif",
		"chown ec2-user:ec2-user /home/ec2-user/app/server/enclave.eif",
		"systemctl restart enclave-watchdog",
	})
}

// --- KMS policy functions ---

// applyKMSPolicy applies a KMS key policy that allows the enclave (with matching PCR0) to Decrypt
// and allows the account root to administer (but not Decrypt) the key.
func applyKMSPolicy(ctx context.Context, ac *awsClients, keyID, pcr0, ec2RoleARN, account string) error {
	fmt.Printf("[deploy] Applying KMS key policy with PCR0: %s\n", pcr0)

	accountRoot := fmt.Sprintf("arn:aws:iam::%s:root", account)

	policy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable decrypt from enclave with attestation",
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
      "Sid": "Enable encrypt from enclave",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": "kms:Encrypt",
      "Resource": "*"
    },
    {
      "Sid": "Enable key administration (no decrypt)",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
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
}`, ec2RoleARN, pcr0, ec2RoleARN, accountRoot)

	return ac.putKeyPolicy(ctx, keyID, policy, false)
}

// isKeyLocked checks if a KMS key policy lacks PutKeyPolicy (meaning it's locked).
func isKeyLocked(ctx context.Context, ac *awsClients, keyID string) bool {
	policy, err := ac.getKeyPolicy(ctx, keyID)
	if err != nil {
		return true // assume locked on error
	}
	return !strings.Contains(policy, "PutKeyPolicy")
}

// lockKMSKey locks the KMS key so only the enclave with matching PCR0 can Decrypt.
// Waits for the enclave to be healthy first.
func lockKMSKey(ctx context.Context, ac *awsClients, cfg *Config, keyID, pcr0, ec2RoleARN, instanceID string) error {
	fmt.Println("[deploy] Waiting for enclave to be healthy before locking KMS key...")

	maxWait := 120
	healthy := false
	for elapsed := 0; elapsed < maxWait; elapsed += 5 {
		err := ac.runOnHost(ctx, instanceID, "health check",
			[]string{"curl -sf -k https://127.0.0.1:443/v1/enclave-info > /dev/null"})
		if err == nil {
			fmt.Println("[deploy] Enclave is healthy")
			healthy = true
			break
		}
		time.Sleep(5 * time.Second)
	}

	if !healthy {
		fmt.Printf("[deploy] WARNING: Enclave did not become healthy within %ds\n", maxWait)
		fmt.Println("[deploy] Skipping KMS lock. Run 'enclave lock' manually.")
		return fmt.Errorf("enclave not healthy after %ds", maxWait)
	}

	policy := fmt.Sprintf(`{
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

	fmt.Printf("[deploy] Locking KMS key %s to PCR0 %s...\n", keyID, pcr0[:16])

	if err := ac.putKeyPolicy(ctx, keyID, policy, true); err != nil {
		return fmt.Errorf("lock KMS key: %w", err)
	}

	fmt.Println("[deploy] KMS key locked. Only this enclave image can decrypt.")
	return nil
}

// --- File helpers ---

// readPCR0 reads the PCR0 value from artifacts/pcr.json.
func readPCR0(root string) (string, error) {
	pcrPath := filepath.Join(root, "enclave", "artifacts", "pcr.json")
	data, err := os.ReadFile(pcrPath)
	if err != nil {
		return "", fmt.Errorf("enclave/artifacts/pcr.json not found. Run 'enclave build' first.")
	}
	var pcrs PCRValues
	if err := json.Unmarshal(data, &pcrs); err != nil {
		return "", fmt.Errorf("parse pcr.json: %w", err)
	}
	if pcrs.PCR0 == "" {
		return "", fmt.Errorf("PCR0 is empty in artifacts/pcr.json")
	}
	return pcrs.PCR0, nil
}

// --- Config helpers ---

// ssmParam returns the full SSM parameter path for a given parameter name.
func (c *Config) ssmParam(name string) string {
	return fmt.Sprintf("/%s/%s/%s", c.Prefix, c.Name, name)
}

// eifBucket returns the S3 bucket name used for EIF transfers during upgrades.
func (c *Config) eifBucket() string {
	return fmt.Sprintf("%s-%s-eif-%s-%s", c.Prefix, c.Name, c.Account, c.Region)
}
