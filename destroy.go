package introspector_enclave

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func destroyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Tear down the CDK stack",
		Long:  "Destroys all AWS infrastructure created by 'enclave deploy'.",
		RunE:  runDestroy,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation prompt")
	return cmd
}

func runDestroy(cmd *cobra.Command, args []string) error {
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

	force, _ := cmd.Flags().GetBool("force")
	if !force {
		fmt.Printf("This will destroy stack %s in %s. Continue? [y/N] ", cfg.stackName(), cfg.Region)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(answer)) != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	fmt.Printf("[destroy] Destroying stack %s\n", cfg.stackName())

	// Schedule KMS key deletion via the EC2 instance before tearing down the
	// stack. The locked key policy only grants ScheduleKeyDeletion to the EC2
	// instance role, so we must do this while the instance is still running.
	if err := scheduleKeyDeletionViaInstance(cfg, root); err != nil {
		fmt.Printf("[destroy] Warning: could not schedule KMS key deletion: %v\n", err)
		fmt.Println("[destroy] The key will be retained as an orphan. Continuing with stack deletion.")
	}

	// Synthesize so CDK knows the stack definition.
	if err := synthCDKStack(cfg, root); err != nil {
		return err
	}

	env := cfg.configEnv()
	return runCmd("cdk", []string{
		"destroy", "--force",
		"--app", filepath.Join(root, "enclave", "cdk.out"),
	}, root, env)
}

// scheduleKeyDeletionViaInstance uses SSM to run ScheduleKeyDeletion on the
// EC2 instance, which has the necessary permission in the locked KMS key policy.
func scheduleKeyDeletionViaInstance(cfg *Config, root string) error {
	ctx := context.Background()

	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return fmt.Errorf("create AWS clients: %w", err)
	}

	outputs, err := loadCDKOutputs(root)
	if err != nil {
		return err
	}

	stack := cfg.stackName()
	instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	if instanceID == "" {
		return fmt.Errorf("InstanceID not found in cdk-outputs.json")
	}

	// Get KMS key ID from SSM (may differ from CDK output after migration).
	kmsKeyID, _ := ac.getParameter(ctx, cfg.ssmParam("KMSKeyID"))
	if kmsKeyID == "" {
		kmsKeyID = outputs.getOutput(stack, "KMSKeyID", "KmsKeyId", "KMS Key ID")
	}
	if kmsKeyID == "" {
		return fmt.Errorf("KMSKeyID not found")
	}

	fmt.Printf("[destroy] Scheduling KMS key %s for deletion via instance %s\n", kmsKeyID, instanceID)

	deleteCmd := fmt.Sprintf(
		"aws kms schedule-key-deletion --key-id %s --pending-window-in-days 7 --region %s",
		kmsKeyID, cfg.Region,
	)

	return ac.runOnHost(ctx, instanceID, "schedule KMS key deletion", []string{deleteCmd})
}
