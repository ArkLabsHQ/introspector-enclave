package introspector_enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show enclave instance and KMS status",
		Long:  "Queries AWS for instance state, enclave health, and KMS key status.",
		RunE:  runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) error {
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

	outputs, err := loadCDKOutputs(root)
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	stack := cfg.stackName()
	instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	kmsKeyID := outputs.getOutput(stack, "KMSKeyID", "KmsKeyId", "KMS Key ID")
	elasticIP := outputs.getOutput(stack, "ElasticIP", "Elastic IP")

	fmt.Println("Enclave Status")
	fmt.Println("==============")
	fmt.Printf("  Stack:       %s\n", stack)
	fmt.Printf("  Region:      %s\n", cfg.Region)
	fmt.Printf("  Instance ID: %s\n", instanceID)
	fmt.Printf("  Elastic IP:  %s\n", elasticIP)
	fmt.Printf("  KMS Key ID:  %s\n", kmsKeyID)
	fmt.Println()

	// Query instance state.
	if instanceID != "" {
		state, err := ac.getInstanceState(ctx, instanceID)
		if err != nil {
			fmt.Printf("  Instance State: (error: %v)\n", err)
		} else {
			fmt.Printf("  Instance State: %s\n", state)
		}
	}

	// Query KMS key state.
	if kmsKeyID != "" {
		keyState, err := ac.getKeyState(ctx, kmsKeyID)
		if err != nil {
			fmt.Printf("  KMS Key State:  (error: %v)\n", err)
		} else {
			fmt.Printf("  KMS Key State:  %s\n", keyState)
		}

		// Check if locked.
		policy, err := ac.getKeyPolicy(ctx, kmsKeyID)
		if err != nil {
			fmt.Printf("  KMS Locked:     (error: %v)\n", err)
		} else if strings.Contains(policy, "PutKeyPolicy") {
			fmt.Printf("  KMS Locked:     no\n")
		} else {
			fmt.Printf("  KMS Locked:     yes\n")
		}
	}

	// Query enclave info via SSM (best-effort).
	if instanceID != "" {
		fmt.Println()
		enclaveInfo := ac.runCommandOutput(ctx, instanceID,
			"curl -sf -k https://127.0.0.1:443/v1/enclave-info 2>/dev/null || echo '{}'")
		if enclaveInfo != "" && enclaveInfo != "{}" {
			var info map[string]interface{}
			if err := json.Unmarshal([]byte(enclaveInfo), &info); err == nil {
				fmt.Println("  Enclave Info:")
				if v, ok := info["version"]; ok {
					fmt.Printf("    Version:         %v\n", v)
				}
				if v, ok := info["previous_pcr0"]; ok {
					fmt.Printf("    Previous PCR0:   %v\n", v)
				}
			}
		} else {
			fmt.Println("  Enclave Info:   (not reachable)")
		}
	}

	return nil
}
