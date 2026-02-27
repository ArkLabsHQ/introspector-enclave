package introspector_enclave

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate project scaffolding",
	}
	cmd.AddCommand(generateTemplateCmd())
	return cmd
}

func generateTemplateCmd() *cobra.Command {
	var golang bool

	cmd := &cobra.Command{
		Use:   "template [output-dir]",
		Short: "Generate a complete enclave app template",
		Long: `Generates a ready-to-use project template for building enclave apps.

The output directory will contain framework files, an example app,
enclave.yaml configuration, and GitHub Actions workflows.

Push the result to GitHub and mark it as a template repository
(Settings > General > Template repository).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !golang {
				return fmt.Errorf("specify a language: --golang")
			}

			outDir := "."
			if len(args) > 0 {
				outDir = args[0]
			}
			return runGenerateTemplate(outDir)
		},
	}

	cmd.Flags().BoolVar(&golang, "golang", false, "Generate a Go app template")
	return cmd
}

func runGenerateTemplate(outDir string) error {
	// Create output directory if needed.
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Write framework files (flake.nix, enclave/, .github/workflows/).
	for _, f := range getFrameworkFiles() {
		destPath := filepath.Join(outDir, f.RelPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
		}
		if err := os.WriteFile(destPath, []byte(f.Content), f.Mode); err != nil {
			return fmt.Errorf("write %s: %w", f.RelPath, err)
		}
		fmt.Printf("  %s\n", f.RelPath)
	}

	// Write enclave.yaml with nix_sub_packages: ["cmd"].
	cfg := golangConfigTemplate
	if sdkRev != "" {
		cfg = strings.Replace(cfg,
			`  rev: ""                        # SDK git commit SHA (required)`,
			fmt.Sprintf(`  rev: "%s"`, sdkRev), 1)
		cfg = strings.Replace(cfg,
			`  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)`,
			fmt.Sprintf(`  hash: "%s"`, sdkHash), 1)
		cfg = strings.Replace(cfg,
			`  vendor_hash: ""                # Go vendor hash (required)`,
			fmt.Sprintf(`  vendor_hash: "%s"`, sdkVendorHash), 1)
	}
	cfgPath := filepath.Join(outDir, "enclave", "enclave.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return fmt.Errorf("create enclave/ directory: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write enclave/enclave.yaml: %w", err)
	}
	fmt.Println("  enclave/enclave.yaml")

	// Write Go app files.
	templateFiles := []struct {
		relPath string
		content string
		mode    os.FileMode
	}{
		{"cmd/main.go", golangMainGo, 0644},
		{"go.mod", golangGoMod, 0644},
		{"README.md", templateReadme, 0644},
	}
	for _, f := range templateFiles {
		destPath := filepath.Join(outDir, f.relPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.relPath, err)
		}
		if err := os.WriteFile(destPath, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.relPath, err)
		}
		fmt.Printf("  %s\n", f.relPath)
	}

	fmt.Println()
	fmt.Println("Template generated. Next steps:")
	fmt.Println("  1. Edit enclave/enclave.yaml (set account, name, secrets)")
	fmt.Println("  2. Push to GitHub and mark as a template repository")
	fmt.Println("     (Settings > General > Template repository)")
	return nil
}

const golangConfigTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: dev                     # Build version (baked into binary via ldflags)
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

# SDK coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero SDK imports.
sdk:
  rev: ""                        # SDK git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a normal Go HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No SDK imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # Go vendor hash (required)
  nix_sub_packages:              # Go sub-packages to build
    - "cmd"
  binary_name: ""                # Output binary name (defaults to 'name')

  # Environment variables baked into the EIF.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"

# Secrets managed by KMS inside the enclave.
# Each secret is generated as 32 random bytes, encrypted with KMS,
# stored in SSM, and decrypted at boot via attestation.
# The decrypted value (hex-encoded) is set as the specified env var.
secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
  # - name: api_token
  #   env_var: APP_API_TOKEN
`

const golangMainGo = `package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("ENCLAVE_APP_PORT")
	if port == "" {
		port = "7074"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from the enclave!")
	})

	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
`

const golangGoMod = `module github.com/OWNER/REPO

go 1.22
`

const templateReadme = `# My Enclave App

A Go application that runs inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) using the [Introspector Enclave](https://github.com/ArkLabsHQ/introspector-enclave) framework.

## Prerequisites

- Go 1.22+
- Docker
- [Nix](https://nixos.org/)
- AWS CLI v2
- AWS CDK CLI (` + "`npm install -g aws-cdk`" + `)
- jq

## Quick Start

### 1. Install the enclave CLI

` + "```sh" + `
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
` + "```" + `

### 2. Configure

Edit ` + "`enclave/enclave.yaml`" + `:

- Set ` + "`account`" + ` to your AWS account ID
- Set ` + "`name`" + ` to your app name
- Configure ` + "`secrets`" + ` as needed

### 3. Set up app hashes

` + "```sh" + `
enclave setup
` + "```" + `

This auto-detects your GitHub remote and computes all Nix hashes.

### 4. Build

` + "```sh" + `
enclave build
` + "```" + `

Produces a reproducible EIF image with deterministic PCR0 measurements.

### 5. Deploy

` + "```sh" + `
enclave deploy
` + "```" + `

Creates the full AWS stack: VPC, EC2, KMS key, IAM roles, and secrets.

### 6. Verify

` + "```sh" + `
enclave verify
` + "```" + `

Verifies the running enclave's attestation document matches your local build.

## Writing Your App

Your app is a plain Go HTTP server. No SDK imports needed.

- Listen on ` + "`ENCLAVE_APP_PORT`" + ` (default 7074)
- Read secrets from environment variables (e.g. ` + "`APP_SIGNING_KEY`" + `)
- The enclave supervisor handles TLS, attestation, and response signing

See [Introspector Enclave documentation](https://github.com/ArkLabsHQ/introspector-enclave) for the full reference.
`
