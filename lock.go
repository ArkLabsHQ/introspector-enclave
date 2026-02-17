package introspector_enclave

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the KMS key (irreversible)",
		Long: `Irreversibly locks the KMS key policy so only the current enclave image can decrypt.

WARNING: This cannot be undone. After locking, deploying a new enclave version
requires the temporary KMS key migration path (handled automatically by 'enclave deploy').`,
		RunE: runLock,
	}
}

func runLock(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
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

	pcr0, err := readPCR0(root)
	if err != nil {
		return err
	}

	fmt.Println("[lock] Locking KMS key (irreversible)")
	return lockKMSKey(ctx, ac, cfg, kmsKeyID, pcr0, ec2RoleARN, instanceID)
}
