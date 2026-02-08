# Nitro Introspector Enclave

A skeleton implementation of an Ark transaction-signing service running inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/). The enclave isolates the signing key so it is never exposed to the host instance. Key material is encrypted with AWS KMS and can only be decrypted by an enclave whose attestation document matches a pre-configured PCR0 hash.

> **Note:** This is a skeleton. All signing endpoints echo their inputs back unchanged. Replace the stub handlers in `main.go` with real signing logic to make it production-ready.

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
  ├── nitriding        (TLS termination + TAP interface setup)
  ├── introspector     (HTTP API, port 7073)
  └── viproxy          (IMDS forwarding → vsock CID 3:8002)
```

**Networking:**

The enclave uses [gvproxy](https://github.com/containers/gvisor-tap-vsock) for outbound network connectivity:

- `192.168.127.1` - Gateway/DNS server (gvproxy)
- `192.168.127.2` - Enclave's virtual IP for inbound connections
- `127.0.0.1:80` - IMDS endpoint (via viproxy → vsock CID 3:8002)

The enclave's `/etc/resolv.conf` is configured to use `192.168.127.1` for DNS resolution, enabling calls to AWS services (KMS, SSM) through gvproxy.

**Key flow:**

1. On boot the enclave calls KMS `Decrypt` with a Nitro attestation document attached.
2. KMS validates the attestation (PCR0) and returns the decrypted signing key.
3. The introspector HTTP server starts and exposes the API behind nitriding.

## Project Structure

```
.
├── main.go                        # HTTP server and KMS key loading
├── internal/config/               # Configuration (env vars via viper)
├── api-spec/
│   ├── protobuf/                  # gRPC/protobuf service definitions
│   └── openapi/                   # Generated OpenAPI spec
├── cdk/
│   └── main.go                    # AWS CDK infrastructure (VPC, EC2, KMS, IAM)
├── cmd/
│   ├── watchdog/                  # Enclave lifecycle supervisor
│   └── introspector-client/       # Test client with attestation verification
├── flake.nix                      # Nix flake for reproducible enclave image
├── enclave/
│   ├── start.sh                   # Entrypoint (nitriding + viproxy + app)
│   ├── gvproxy/                   # Network proxy for vsock forwarding
│   └── systemd/                   # Service units for EC2 host
├── scripts/                       # Deployment and key setup scripts
└── user_data/                     # EC2 cloud-init user data
```

## API Endpoints

All endpoints are served behind [nitriding](https://github.com/brave/nitriding-daemon) on port 443.

| Method | Path                | Description                                |
|--------|---------------------|--------------------------------------------|
| GET    | `/v1/info`          | Returns signer public key and version      |
| POST   | `/v1/tx`            | Submit Ark + checkpoint transactions       |
| POST   | `/v1/intent`        | Submit a signed intent proof               |
| POST   | `/v1/finalization`  | Submit forfeits and commitment for signing |

Request and response schemas are defined in `api-spec/protobuf/introspector/v1/service.proto`.

## Prerequisites

- [Nix](https://nixos.org/download/) (with flakes enabled)
- Go 1.25.5+
- Docker
- AWS CLI v2 configured with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)
- An AWS account with permissions for EC2, KMS, SSM, ECR, VPC, and IAM
- `jq`, `openssl`, `xxd`

## Deployment

### 1. Set environment variables

```sh
export CDK_DEPLOY_REGION=us-east-1
export CDK_DEPLOY_ACCOUNT=<your-account-id>
export CDK_PREFIX=dev  # optional, defaults to "dev"
```

### 2. Full deploy (infrastructure + key setup)

```sh
./scripts/deploy_introspector.sh
```

This script:

- Builds the enclave image with Nix (`nix build .#enclave-image`)
- Deploys the CDK stack (VPC, EC2, KMS key, ECR images, systemd services)
- Waits for the EC2 instance and enclave to come up
- Generates a random 32-byte signing key
- Encrypts it with KMS and stores the ciphertext in SSM
- Applies a KMS key policy restricting decryption to the enclave's PCR0

### 3. Key setup only (stack already deployed)

```sh
./scripts/setup_keys.sh
```

## Local Development

For local testing without a Nitro Enclave, set the secret key directly:

```sh
export INTROSPECTOR_SECRET_KEY=<64-char-hex-private-key>
export INTROSPECTOR_NO_TLS=true
go run .
```

The server listens on port 7073 by default. Override with `INTROSPECTOR_PORT`.

## Test Client

The included client verifies the enclave's attestation document before submitting a transaction:

```sh
go run ./cmd/introspector-client \
  -base-url https://<enclave-host> \
  -expected-pcr0 <hex> \
  -ark-tx <payload> \
  -checkpoint-tx <payload>
```

Use `-insecure` to skip TLS verification during development.

## Reproducible Build Verification

The enclave image is built with [Nix](https://nixos.org/) using `dockerTools.buildImage`, which produces a byte-identical Docker image on every build. This eliminates non-determinism from Docker layer ordering and guarantees identical PCR0 measurements.

### Build the EIF (reproducible, via Docker)

Build the enclave EIF image and output its PCR values:

```sh
./scripts/build_eif.sh
```

Override defaults with `VERSION` and `AWS_REGION` environment variables.

### Build the enclave image

```sh
VERSION=dev AWS_REGION=us-east-1 nix build --impure .#enclave-image
```

This produces a Docker image tarball at `./result`. Load it with:

```sh
docker load < result
```

### Verify a running enclave

The client builds the Docker image locally with Nix, then runs `nitro-cli build-enclave` **remotely on the EC2 instance** via SSM to derive the PCR0. This ensures the EIF is built with Amazon's official `nitro-cli` package (whose bundled kernel/init blobs determine the PCR0), matching what the deployment uses.

```sh
go run ./cmd/introspector-client \
  --base-url https://<enclave-host> \
  --verify-build \
  --instance-id <ec2-instance-id> \
  --s3-bucket <bucket-for-image-upload> \
  --repo-path /path/to/introspector-enclave \
  --build-version dev \
  --build-region us-east-1 \
  --insecure
```

This will:
1. Run `nix build .#enclave-image` locally to produce a deterministic Docker image tarball
2. Upload the tarball to S3 so the EC2 instance can fetch it
3. Run an SSM command on the instance to download the image, load it into Docker, and run `nitro-cli build-enclave` to derive PCR0
4. Fetch the attestation document from the running enclave
5. Verify the attestation signature, nonce, and PCR0 match
6. Clean up the S3 object

The `--build-version` flag must match the `VERSION` used by the operator (the CDK deployment uses the `CDK_PREFIX` value, which defaults to `dev`).

### Using the deploy script

```sh
VERIFY_BUILD=1 BUILD_VERSION=dev INSECURE_TLS=1 ./scripts/deploy_and_call.sh
```

The script auto-detects the S3 bucket from the CDK assets bucket (`cdk-hnb659fds-assets-<account>-<region>`). Override with `S3_BUCKET` if needed.

### Prerequisites for build verification

`--verify-build` requires `nix` and `aws` CLI in PATH locally. The `nitro-cli` is **not** needed locally -- it runs on the EC2 instance via SSM. The instance must have SSM agent running and the `aws-nitro-enclaves-cli` package installed (both are configured by the CDK stack's user data).

## Configuration

All configuration is via environment variables prefixed with `INTROSPECTOR_`:

| Variable                                   | Description                            | Default    |
|--------------------------------------------|----------------------------------------|------------|
| `INTROSPECTOR_SECRET_KEY`                  | Signing key (hex). Set by KMS at boot. | (required) |
| `INTROSPECTOR_PORT`                        | HTTP listen port                       | `7073`     |
| `INTROSPECTOR_NO_TLS`                      | Disable TLS (required for skeleton)    | `false`    |
| `INTROSPECTOR_LOG_LEVEL`                   | Log verbosity level                    | `debug`    |
| `INTROSPECTOR_SECRET_KEY_CIPHERTEXT`       | Base64 KMS ciphertext (direct)         | (from SSM) |
| `INTROSPECTOR_SECRET_KEY_CIPHERTEXT_PARAM` | SSM parameter name for ciphertext      | `/<deployment>/NitroIntrospector/SecretKeyCiphertext` |
| `INTROSPECTOR_DEPLOYMENT`                  | Deployment name for SSM paths          | `dev`      |
| `INTROSPECTOR_KMS_KEY_ID`                  | KMS key ID override                    | (auto)     |

## Watchdog

The watchdog (`cmd/watchdog`) runs on the EC2 host as a systemd service. It starts the Nitro Enclave via `nitro-cli` and polls its status, restarting the enclave if it exits.

| Variable                | Description                 | Default                                        |
|-------------------------|-----------------------------|-------------------------------------------------|
| `ENCLAVE_NAME`          | Enclave name                | `app`                                           |
| `EIF_PATH`              | Path to enclave image file  | `/home/ec2-user/app/server/signing_server.eif`  |
| `CPU_COUNT`             | vCPUs allocated to enclave  | `2`                                             |
| `MEMORY_MIB`            | Memory allocated (MiB)      | `4320`                                          |
| `ENCLAVE_CID`           | vsock CID                   | `16`                                            |
| `DEBUG_MODE`            | Enable debug console        | `false`                                         |
| `POLL_INTERVAL_SECONDS` | Health check interval (s)   | `5`                                             |
