package introspector_enclave

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const configTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: dev                     # Build version (baked into binary via ldflags)
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

app:
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # Go vendor hash (required)
  nix_sub_packages:              # Go sub-packages to build
    - "."
  binary_name: ""                # Output binary name (defaults to 'name')
  port: 7074                     # Port the app listens on inside the enclave

  # Environment variables baked into the EIF.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"
`

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Validate enclave.yaml or create a template",
		Long: `Reads and validates enclave.yaml in the current directory.
If no enclave.yaml exists, writes a commented template as a starting point.`,
		RunE: runInit,
	}
}

func runInit(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(cwd, configFile)

	// If enclave.yaml doesn't exist, write the template.
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, []byte(configTemplate), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
		fmt.Printf("Created %s template.\n", cfgPath)
		fmt.Println("Edit it with your app details, then run 'enclave init' again to validate.")
		return nil
	}

	// enclave.yaml exists — load and validate.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Validate app-specific fields for nix source.
	var errors []string
	if cfg.Name == "" {
		errors = append(errors, "'name' is required")
	}
	if cfg.App.Source == "nix" {
		if cfg.App.NixOwner == "" {
			errors = append(errors, "'app.nix_owner' is required")
		}
		if cfg.App.NixRepo == "" {
			errors = append(errors, "'app.nix_repo' is required")
		}
		if cfg.App.NixRev == "" {
			errors = append(errors, "'app.nix_rev' is required")
		}
		if cfg.App.NixHash == "" {
			errors = append(errors, "'app.nix_hash' is required")
		}
		if cfg.App.NixVendorHash == "" {
			errors = append(errors, "'app.nix_vendor_hash' is required")
		}
	}

	if len(errors) > 0 {
		fmt.Println("Validation errors:")
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
		return fmt.Errorf("enclave.yaml has %d validation error(s)", len(errors))
	}

	// Print summary.
	fmt.Println("enclave.yaml is valid.")
	fmt.Println()
	fmt.Printf("  Name:        %s\n", cfg.Name)
	fmt.Printf("  Version:     %s\n", cfg.Version)
	fmt.Printf("  Region:      %s\n", cfg.Region)
	fmt.Printf("  Account:     %s\n", cfg.Account)
	fmt.Printf("  Prefix:      %s\n", cfg.Prefix)
	fmt.Printf("  Instance:    %s\n", cfg.InstanceType)
	fmt.Println()
	fmt.Printf("  App Source:  %s\n", cfg.App.Source)
	fmt.Printf("  App Repo:    %s/%s\n", cfg.App.NixOwner, cfg.App.NixRepo)
	fmt.Printf("  App Rev:     %s\n", cfg.App.NixRev)
	fmt.Printf("  Binary:      %s\n", cfg.App.BinaryName)
	fmt.Printf("  Port:        %d\n", cfg.App.Port)
	if len(cfg.App.Env) > 0 {
		fmt.Printf("  Env vars:    %d\n", len(cfg.App.Env))
	}
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}
