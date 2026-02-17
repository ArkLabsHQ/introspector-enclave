# Introspector Enclave

A framework for running Go applications inside [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) with zero SDK imports. The enclave supervisor handles attestation, KMS secret management, PCR extension, and BIP-340 Schnorr response signing automatically. You write a plain Go HTTP server.

## Architecture

```
Client                                  AWS Services (KMS, SSM)
  |                                              ^
  | HTTPS (port 443)                             |
  v                                              |
EC2 Instance (m6i.xlarge, Amazon Linux 2023)     |
  |                                              |
  |  vsock:1024                          gvproxy (Docker)
  v                                       192.168.127.1
Nitro Enclave ---------------------------------->+
  ├── nitriding             (TLS :443 -> :7073)
  ├── enclave-supervisor    (reverse proxy :7073 -> :7074)
  │     ├── attestation key + Schnorr signing
  │     ├── KMS secret decryption
  │     ├── PCR extension endpoints
  │     └── management API (/health, /v1/enclave-info, ...)
  ├── your-app              (plain HTTP server :7074)
  └── viproxy               (IMDS forwarding -> vsock CID 3:8002)
```

### Boot Sequence

1. **nitriding** starts, sets up the TAP network interface via gvproxy, and terminates TLS on port 443
2. **enclave-supervisor** initializes:
   - Decrypts secrets from KMS using a Nitro attestation document (PCR0-bound)
   - Sets decrypted secrets as environment variables
   - Generates an ephemeral secp256k1 attestation key
   - Registers `SHA256(attestationPubkey)` with nitriding (embedded as `appKeyHash` in attestation UserData)
   - Starts the reverse proxy on port 7073 with Schnorr response signing
3. **your-app** is launched as a child process on port 7074, inheriting secret env vars

### Networking

The enclave uses [gvproxy](https://github.com/containers/gvisor-tap-vsock) for outbound connectivity:

- `192.168.127.1` - Gateway/DNS server (gvproxy)
- `192.168.127.2` - Enclave's virtual IP
- `127.0.0.1:80` - IMDS endpoint (via viproxy -> vsock CID 3:8002)

## Prerequisites

- Go 1.22+
- Docker (for reproducible EIF builds via pinned NixOS container)
- [Nix](https://nixos.org/) (for hash computation and local builds)
- AWS CLI v2 with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)
- `jq`

## Quick Start

### 1. Install the CLI

```sh
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
```

Or build from source with SDK hashes baked in:

```sh
make sdk-hashes REV=v1.0.0   # compute source hash
make vendor-hash              # compute vendor hash
make build                    # build CLI with hashes baked in
```

### 2. Initialize your project

In your Go app's repo root:

```sh
enclave init
```

This creates:
- `enclave/enclave.yaml` — main config file
- `flake.nix` — Nix build definition
- `enclave/start.sh` — enclave boot script
- `enclave/gvproxy/` — network proxy config
- `enclave/scripts/` — initialization scripts
- `enclave/systemd/` — service unit files
- `enclave/user_data/` — EC2 user data

If built with `make build`, the `sdk:` section is auto-populated with the correct hashes.

### 3. Set up app hashes

The `setup` command auto-detects your GitHub remote and computes all nix hashes:

```sh
enclave setup              # runs in Docker (recommended)
enclave setup --local      # uses local nix installation
```

This populates `nix_owner`, `nix_repo`, `nix_rev`, `nix_hash`, and `nix_vendor_hash` in `enclave/enclave.yaml` from your local git state.

### 4. Configure `enclave/enclave.yaml`

After `enclave setup`, review and fill in remaining fields:

```yaml
name: my-app                     # app name
region: us-east-1                # AWS region
account: "123456789012"          # your AWS account ID

sdk:
  rev: "v1.0.0"                  # auto-populated by 'make build'
  hash: "sha256-..."
  vendor_hash: "sha256-..."

app:
  nix_owner: my-org              # auto-populated by 'enclave setup'
  nix_repo: my-app
  nix_rev: "abc123..."
  nix_hash: "sha256-..."
  nix_vendor_hash: "sha256-..."
  nix_sub_packages:
    - "cmd"                      # Go sub-package with main()
  binary_name: my-app

  env:
    MY_APP_PORT: "7074"
    MY_APP_DATADIR: "/app/data"

secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
```

Your app is a plain Go HTTP server — no SDK imports needed:

```go
package main

import (
    "net/http"
    "os"
)

func main() {
    port := os.Getenv("ENCLAVE_APP_PORT") // default 7074
    signingKey := os.Getenv("APP_SIGNING_KEY") // decrypted by supervisor

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello from the enclave"))
    })
    http.ListenAndServe(":"+port, nil)
}
```

### 5. Validate config

```sh
enclave init
```

Running `init` again when `enclave.yaml` already exists validates all fields and prints a summary.

### 6. Build the enclave image

```sh
enclave build              # build EIF via Docker + Nix (reproducible)
enclave build --local      # build EIF using local Nix installation
```

Outputs `artifacts/image.eif` and `artifacts/pcr.json` with PCR0, PCR1, PCR2 measurements.

### 7. Deploy

```sh
enclave deploy             # deploy CDK stack (VPC, EC2, KMS, IAM, secrets)
```

### 8. Verify

```sh
enclave verify             # verify attestation document + PCR0 match
```

## Updating Your App

When you push new code to your app repo:

```sh
# 1. Commit and push your changes
git add . && git commit -m "update" && git push

# 2. Re-run setup to update hashes
enclave setup

# 3. Rebuild and redeploy
enclave build
enclave deploy
```

## SDK Release Workflow

SDK hashes are computed per release tag and baked into CLI builds via ldflags. This lets `enclave init` auto-populate the `sdk:` section.

```sh
# 1. Compute source hash (from local git tree, no network auth needed)
make sdk-hashes REV=HEAD

# 2. Compute vendor hash (runs a test Nix build to get the expected hash)
make vendor-hash

# 3. Commit the hashes
git add sdk-hashes.json
git commit -m "adding nix hashes"

# 4. Tag the release and push
git tag v1.0.0
git push && git push --tags
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build `enclave-cli` with SDK hashes from `sdk-hashes.json` baked in via ldflags |
| `make sdk-hashes REV=<tag>` | Compute Nix source hash for a git ref and write `sdk-hashes.json` |
| `make vendor-hash` | Compute Go vendor hash via test Nix build and update `sdk-hashes.json` |
| `make help` | Show all targets |

### CI Verification

The `.github/workflows/sdk-hashes.yml` workflow runs on tag push (`v*`) to verify that `sdk-hashes.json` matches the computed hashes and that `enclave-supervisor` builds successfully.

## CLI Commands

| Command | Description |
|---------|-------------|
| `enclave init` | Scaffold enclave project or validate existing config |
| `enclave setup` | Auto-populate app nix hashes from git remote |
| `enclave setup --local` | Same as above, using local Nix instead of Docker |
| `enclave build` | Build EIF image (reproducible, via Docker + Nix) |
| `enclave build --local` | Build EIF using local Nix instead of Docker |
| `enclave deploy` | Deploy CDK stack (VPC, EC2, KMS, IAM, secrets) |
| `enclave verify` | Verify attestation document and PCR0 against local build |
| `enclave status` | Show deployment status |
| `enclave lock` | Irreversible KMS lockdown (PCR0-only decrypt) |
| `enclave destroy` | Tear down the CDK stack |

## API Endpoints

The supervisor exposes management endpoints alongside proxied requests to your app. All responses include Schnorr signature headers.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Supervisor health check (ready/degraded) |
| GET | `/v1/enclave-info` | Build + runtime metadata (version, attestation key, previous PCR0) |
| POST | `/v1/export-key` | Re-encrypt signing key for KMS migration |
| POST | `/v1/extend-pcr` | Extend a PCR register (16-31) with custom data |
| POST | `/v1/lock-pcr` | Lock a PCR register (16-31) to prevent further extension |
| GET | `/enclave/attestation` | Nitro attestation document (served by nitriding) |
| `*` | `/*` | All other requests proxied to your app on port 7074 |

### Response Signing

Every response includes:
- `X-Attestation-Signature`: BIP-340 Schnorr signature over `SHA256(response_body)`
- `X-Attestation-Pubkey`: compressed public key of the ephemeral attestation key

Clients verify the signature, then confirm the pubkey hash matches `appKeyHash` in the attestation document's UserData.

### PCR Extension

Your app can extend PCR registers 16-31 via HTTP without importing the SDK:

```sh
# Extend PCR 16 with custom data (base64-encoded)
curl -X POST http://127.0.0.1:7073/v1/extend-pcr \
  -d '{"pcr": 16, "data": "base64encodeddata"}'

# Lock PCR 16 to prevent further extension
curl -X POST http://127.0.0.1:7073/v1/lock-pcr \
  -d '{"pcr": 16}'
```

## Security Model

### Secret Lifecycle

1. On first deploy, the CLI generates 32 random bytes per secret, encrypts them with KMS (attaching a Nitro attestation document), and stores the ciphertext in SSM Parameter Store
2. On boot, the supervisor loads ciphertexts from SSM and decrypts via KMS (which validates PCR0)
3. Decrypted values are set as environment variables — plaintext only exists in enclave memory
4. SSM parameter path: `/{prefix}/{appName}/{secretName}/Ciphertext`

### KMS Policy

The deploy command applies a KMS key policy where:
- The **admin statement** explicitly excludes `kms:Decrypt` and `kms:CreateGrant` — nobody outside the enclave can decrypt
- The **enclave statement** allows `kms:Decrypt` only when `kms:RecipientAttestation:PCR0` matches the enclave measurement

### Irreversible KMS Lockdown

For maximum security, the `lock` command applies an **irreversible** policy using `--bypass-policy-lockout-safety-check`:

- Removes all admin access (no `kms:PutKeyPolicy`, no `kms:ScheduleKeyDeletion`)
- Only the enclave with the exact PCR0 can call `kms:Decrypt`
- **This cannot be undone.** Not even the AWS root account can modify the policy afterward.

```sh
enclave lock
```

### Key Migration

When deploying a new enclave version (different PCR0) after locking the KMS key, the signing key is migrated automatically:

1. A new KMS key is created with a policy allowing the new PCR0 to decrypt
2. The old enclave's `POST /v1/export-key` re-encrypts the key with the new KMS key
3. The ciphertext is stored in SSM, the old enclave is stopped, and the new one boots with the new KMS key
4. The old locked KMS key is scheduled for deletion (7-day pending window)

### PCR0 Attestation Chain

Each enclave version records its predecessor's PCR0, creating a verifiable upgrade chain:

```
Genesis -> PCR0_v1 (previous_pcr0=genesis)
        -> PCR0_v2 (previous_pcr0=PCR0_v1)
        -> PCR0_v3 (previous_pcr0=PCR0_v2)
```

Exposed via `GET /v1/enclave-info`.

## Reproducible Build

The enclave image is built entirely with [Nix](https://nixos.org/) using [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) inside a pinned Docker container, producing a byte-identical EIF on every build. This guarantees identical PCR0 measurements, enabling anyone to verify that the running enclave matches the published source code.

## Project Structure

```
.
├── cmd/enclave/main.go          # CLI entry point
├── config.go                    # Config loading + validation
├── build.go                     # EIF build orchestration
├── setup.go                     # Auto-populate app nix hashes
├── deploy.go                    # CDK deploy + secret provisioning
├── verify.go                    # Attestation verification
├── cdk.go                       # AWS CDK stack definition (Go)
├── init.go                      # Scaffold command + config template
├── framework_files.go           # Framework files as Go string constants
├── version.go                   # SDK hash vars (set via ldflags)
├── Makefile                     # Build + hash computation targets
├── sdk-hashes.json              # Cached SDK Nix hashes
├── sdk/                         # SDK module (built as enclave-supervisor)
│   ├── enclave.go               # Init, attestation key, signing middleware, routes
│   ├── kms_ssm.go               # KMS encrypt/decrypt, SSM storage
│   ├── imds.go                  # IMDS credential fetching
│   ├── migrate.go               # Key migration via vsock
│   └── cmd/enclave-supervisor/
│       └── main.go              # Standalone supervisor binary
└── .github/workflows/
    └── sdk-hashes.yml           # CI: verify SDK hashes on tag push
```

## Configuration Reference

### `enclave/enclave.yaml`

| Field | Description | Default |
|-------|-------------|---------|
| `name` | App name (used in stack name, EIF) | (required) |
| `version` | Build version | `dev` |
| `region` | AWS region | (required) |
| `account` | AWS account ID | (required for deploy) |
| `prefix` | Deployment prefix (stack = `{prefix}Nitro{name}`) | `dev` |
| `instance_type` | EC2 instance type | `m6i.xlarge` |
| `nix_image` | Docker image for builds | `nixos/nix:2.24.9` |
| `sdk.rev` | SDK git commit SHA or tag | (required for build) |
| `sdk.hash` | Nix source hash (SRI) | (required for build) |
| `sdk.vendor_hash` | Go vendor hash (SRI) | (required for build) |
| `app.source` | Build source type | `nix` |
| `app.nix_owner` | GitHub owner | (auto by `setup`) |
| `app.nix_repo` | GitHub repo | (auto by `setup`) |
| `app.nix_rev` | Git commit SHA | (auto by `setup`) |
| `app.nix_hash` | Nix source hash (SRI) | (auto by `setup`) |
| `app.nix_vendor_hash` | Go vendor hash (SRI) | (auto by `setup`) |
| `app.nix_sub_packages` | Go sub-packages to build | `["."]` |
| `app.binary_name` | Output binary name | `{name}` |
| `app.env` | Environment variables baked into EIF | `{}` |
| `secrets[].name` | Secret name (SSM path component) | (required) |
| `secrets[].env_var` | Env var for decrypted value | (required) |

### Environment Variables (Runtime)

| Variable | Description | Default |
|----------|-------------|---------|
| `ENCLAVE_APP_PORT` | Port your app listens on | `7074` |
| `ENCLAVE_PROXY_PORT` | Supervisor proxy port | `7073` |
| `APP_BINARY_NAME` | User app binary name | `app` |
| `ENCLAVE_DEPLOYMENT` | Deployment name for SSM paths | `dev` |
| `ENCLAVE_KMS_KEY_ID` | KMS key ID override | (auto from SSM) |
| `ENCLAVE_AWS_REGION` | AWS region for KMS/SSM | `us-east-1` |
