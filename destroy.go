package introspector_enclave

import (
	"bufio"
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
