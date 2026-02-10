# Introspector Enclave

An [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) wrapper for the [Ark introspector](https://github.com/ArkLabsHQ/introspector) signing oracle. The enclave isolates the signing key so it is never exposed to the host instance. Key material is generated inside the enclave, encrypted with AWS KMS, and can only be decrypted by an enclave whose attestation document matches a pre-configured PCR0 measurement.

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
  ├── nitriding             (TLS termination + attestation)
  ├── introspector-init     (KMS decrypt + PCR16 binding + attestation key + supervisor)
  ├── introspector          (upstream signing service, port 7074)
  └── viproxy               (IMDS forwarding -> vsock CID 3:8002)
```

### Boot Sequence

1. **nitriding** starts and sets up the TAP network interface via gvproxy
2. **introspector-init** runs as the app command (supervisor mode):
   - Decrypts the signing key from KMS using a Nitro attestation document (PCR0-bound)
   - Derives the compressed public key and extends PCR16 with `SHA256(compressedPubkey)`, then locks it
   - Generates an ephemeral attestation key and registers `SHA256(attestationPubkey)` with nitriding via `POST /enclave/hash` (embedded as `appKeyHash` in attestation UserData)
   - Starts the upstream **introspector** as a child process on port 7074
   - Runs a reverse proxy on port 7073 that signs all responses with the attestation key
3. **introspector** (upstream) serves the full gRPC + HTTP signing API on port 7074, reading `INTROSPECTOR_SECRET_KEY` from the environment

### Networking

The enclave uses [gvproxy](https://github.com/containers/gvisor-tap-vsock) for outbound network connectivity:

- `192.168.127.1` - Gateway/DNS server (gvproxy)
- `192.168.127.2` - Enclave's virtual IP for inbound connections
- `127.0.0.1:80` - IMDS endpoint (via viproxy -> vsock CID 3:8002)

## Security Model

### Key Lifecycle

1. On first boot, the enclave generates a random 32-byte signing key **inside the enclave**
2. The key is encrypted with KMS (attaching a Nitro attestation document) and stored as ciphertext in SSM Parameter Store
3. On subsequent boots, the ciphertext is loaded from SSM and decrypted via KMS (which validates the attestation PCR0)
4. The plaintext key only ever exists inside the enclave memory

### KMS Policy

The deploy script applies a KMS key policy where:

- The **admin statement** explicitly excludes `kms:Decrypt` and `kms:CreateGrant` -- nobody outside the enclave can decrypt
- The **enclave statement** allows `kms:Decrypt` only when `kms:RecipientAttestation:PCR0` matches the enclave measurement

### Irreversible KMS Lockdown

For maximum security, `scripts/lock_kms_policy.sh` applies an **irreversible** policy using `--bypass-policy-lockout-safety-check`:

- Removes all admin access (no `kms:PutKeyPolicy`, no `kms:ScheduleKeyDeletion`)
- Only the enclave with the exact PCR0 can call `kms:Decrypt`
- **This cannot be undone.** Not even the AWS root account can modify the policy afterward.

```sh
# After building and deploying:
./scripts/lock_kms_policy.sh
```

### Pubkey Attestation via PCR16

The signing public key is cryptographically bound to the enclave's attestation document via PCR16:

1. `introspector-init` computes `SHA256(compressedPubkey)`, extends PCR16 with that hash, and locks PCR16
2. The resulting PCR16 value is `SHA384(zeros_48 || SHA256(pubkey))` (standard PCR extension starting from 48 zero bytes)
3. Clients fetch the attestation document and `/v1/info` pubkey, then verify that `SHA384(zeros_48 || SHA256(pubkey))` matches `PCRs[16]`

This ensures the pubkey returned by the API genuinely belongs to the attested enclave, using a first-class PCR value rather than application-level UserData.

### Ephemeral Attestation Key (appKeyHash)

Each enclave boot generates a fresh secp256k1 keypair (the "attestation key") for signing API responses. This provides per-response authentication independent of TLS:

1. A random 32-byte private key is generated at boot using `crypto/rand`
2. `SHA256(compressedAttestationPubkey)` is registered with nitriding via `POST /enclave/hash`, which embeds it as `appKeyHash` in the attestation document's UserData
3. Every HTTP response from the reverse proxy includes:
   - `X-Attestation-Signature`: BIP-340 Schnorr signature over `SHA256(response_body)`
   - `X-Attestation-Pubkey`: compressed public key of the attestation key
4. Clients verify the signature, then confirm the pubkey hash matches the `appKeyHash` in the attestation document's UserData

The attestation key uses nitriding's built-in `appKeyHash` mechanism rather than a PCR register. This is compatible with nitriding's horizontal scaling (leader-worker key sync), where the leader generates the attestation key and distributes it to workers via `PUT/GET /enclave/state`. All instances in a fleet share the same attestation key and produce identical attestation documents.

The UserData format is: `[0x12, 0x20, tlsKeyHash:32] ++ [0x12, 0x20, appKeyHash:32]` (68 bytes, multihash-prefixed SHA-256 hashes). The `appKeyHash` is at bytes 36-68.

## Project Structure

```
.
├── enclave/
│   ├── main.go                    # introspector-init: supervisor + migration + PCR16 binding + attestation key + response signing
│   ├── kms_ssm.go                 # KMS encrypt/decrypt with attestation, SSM storage
│   ├── migration.go               # Migration state types and SSM operations
│   ├── migration_server.go        # Vsock HTTP server for V1-V2 migration protocol
│   ├── config.go                  # Configuration (env vars via viper)
│   ├── imds.go                    # IMDS credential fetching via viproxy
│   ├── start.sh                   # Entrypoint (viproxy + nitriding + introspector-init)
│   ├── enclave_init.sh            # Host-side script to start the enclave via nitro-cli
│   ├── gvproxy/                   # Network proxy for vsock forwarding
│   ├── systemd/                   # Service units for EC2 host
│   └── user_data/                 # EC2 cloud-init user data
├── builder/
│   ├── flake.nix                  # Nix flake: reproducible EIF build
│   └── main.go                    # AWS CDK infrastructure (VPC, EC2, KMS, IAM)
├── client/
│   └── main.go                    # Attestation verification client (PCR0 + PCR16 + appKeyHash + response sigs)
├── scripts/
│   ├── build_eif.sh               # Build EIF reproducibly via Docker + Nix
│   ├── deploy.sh                  # CDK deploy + KMS policy setup
│   ├── deploy_v2.sh               # V2 migration deployment
│   ├── call.sh                    # Verify attestation + pubkey binding
│   └── lock_kms_policy.sh         # Irreversible KMS lockdown (PCR0-only decrypt)
└── cdk.json                       # CDK app entry point
```

## API Endpoints

All endpoints are served behind [nitriding](https://github.com/brave/nitriding-daemon) on port 443 with automatic TLS.

| Method | Path                       | Description                                      |
|--------|----------------------------|--------------------------------------------------|
| GET    | `/enclave/attestation`     | Nitro attestation document (nitriding)            |
| GET    | `/v1/info`                 | Returns signer public key and version             |
| POST   | `/v1/tx`                   | Submit Ark + checkpoint transactions for signing  |
| POST   | `/v1/intent`               | Submit a signed intent proof                      |
| POST   | `/v1/finalization`         | Submit forfeits and commitment for signing        |
| GET    | `/v1/migration-status`     | Migration state (cooldown, V2 PCR0, completion)   |
| GET    | `/v1/enclave-info`         | Build + runtime metadata (version, previous PCR0, maintainer, attestation key)|

All responses include `X-Attestation-Signature` (BIP-340 Schnorr over SHA256(body)) and `X-Attestation-Pubkey` (compressed pubkey) headers for per-response authentication.

Request and response schemas are defined in `api-spec/protobuf/introspector/v1/service.proto`.

## Prerequisites

- Docker (for reproducible EIF builds via pinned NixOS container)
- AWS CLI v2 configured with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)
- Go 1.25+
- An AWS account with permissions for EC2, KMS, SSM, ECR, VPC, and IAM
- `jq`

## Deployment

### 1. Set environment variables

```sh
export CDK_DEPLOY_REGION=us-east-1
export CDK_DEPLOY_ACCOUNT=<your-account-id>
export CDK_PREFIX=dev  # optional, defaults to "dev"
```

### 2. Build the enclave image

```sh
./scripts/build_eif.sh
```

This builds the EIF reproducibly inside a pinned NixOS Docker container (`nixos/nix:2.24.9`) and outputs `artifacts/image.eif` and `artifacts/pcr.json` with the PCR measurements.

### 3. Deploy infrastructure + apply KMS policy

```sh
./scripts/deploy.sh
```

This script:

- Reads PCR0 from `artifacts/pcr.json` (build step must be run first)
- Deploys the CDK stack (VPC, EC2, KMS key, ECR images, systemd services)
- Applies a KMS key policy restricting decryption to the enclave's PCR0
- Waits for the EC2 instance to be ready

### 4. Verify the enclave

```sh
INSECURE_TLS=1 ./scripts/call.sh
```

This verifies the enclave's attestation document and pubkey binding via PCR16. Use `INSECURE_TLS=1` because the enclave's self-signed TLS cert won't have IP SANs (trust comes from attestation, not TLS).

### 5. (Optional) Lock the KMS key permanently

```sh
./scripts/lock_kms_policy.sh
```

**Warning:** This is irreversible. After locking, no one can modify the key policy or decrypt outside the enclave with the matching PCR0.

## Software Migration

When the KMS key is locked to a specific PCR0, updating the enclave software requires migrating the signing key to a new enclave with a different PCR0. The migration protocol transfers the key trustlessly with a mandatory 24-hour cooldown and optional maintainer authorization.

### Protocol

```
V1 Enclave (PCR0_v1, locked KMS)         V2 Enclave (PCR0_v2, own KMS key)
────────────────────────────              ────────────────────────────────
Running, serving API                      Deployed in parallel

T+0:  V2 connects via vsock ──────────────► sends attestation + KMS key ID
                                            + maintainer signature (if configured)
      V1 validates attestation ◄──────────
      V1 verifies maintainer signature
      V1 records attestation chain in SSM
      /v1/migration-status shows pending

T+24h: Cooldown expires
       V2 requests completion ────────────►
       V1 re-encrypts key under V2 KMS key
       V1 stores V2 ciphertext in SSM
       V1 shuts down                       V2 reads ciphertext, decrypts via own KMS
                                           V2 serves API with same signing pubkey
```

### Maintainer Key Authorization

When `MAINTAINER_PUBKEY` is set at build time, migration requires a Schnorr signature from the maintainer key (32-byte x-only pubkey, BIP-340). The signature covers:

```
message = SHA256(target_pcr0_hex + ":" + activation_time_decimal)
```

Where `target_pcr0_hex` is the lowercase hex PCR0 of V2 and `activation_time_decimal` is the Unix timestamp for the earliest migration completion (must be >= now + 24h).

The maintainer key can be:
- A single secp256k1 key
- A MuSig or FROST aggregate key (for multi-party authorization)

Without `MAINTAINER_PUBKEY`, any V2 enclave deployed on the same host can initiate migration (suitable for development but not production).

### Attestation Chain

Each enclave build embeds `PREVIOUS_PCR0` via `-ldflags`, creating an immutable chain:

```
Genesis → PCR0_v1 (PREVIOUS_PCR0=genesis)
       → PCR0_v2 (PREVIOUS_PCR0=PCR0_v1)
       → PCR0_v3 (PREVIOUS_PCR0=PCR0_v2)
```

The chain is recorded in migration state and exposed via `/v1/enclave-info`. Clients can verify the full upgrade lineage by checking that each version's `PREVIOUS_PCR0` matches its predecessor.

### Migration Steps

1. **Update the code** and rebuild the EIF:
   ```sh
   PREVIOUS_PCR0=<current_pcr0> MAINTAINER_PUBKEY=<hex> ./scripts/build_eif.sh
   ```

2. **Re-deploy the CDK stack** (adds V2 KMS key and migration SSM parameters):
   ```sh
   ./scripts/deploy.sh
   ```

3. **Sign the migration** (if maintainer key is configured):
   ```sh
   # Sign: SHA256("<v2_pcr0>:<activation_timestamp>")
   # Store signature and activation time:
   export MAINTAINER_SIG=<schnorr_sig_hex>
   export MIGRATION_ACTIVATION_TIME=<unix_timestamp>
   ```

4. **Deploy V2** alongside the running V1 enclave:
   ```sh
   ./scripts/deploy_v2.sh
   ```

5. **Monitor migration** status (24h cooldown):
   ```sh
   cd client && go run . --base-url https://<host> --insecure --check-migration
   ```

6. After 24h (or the maintainer-specified activation time), V2 completes the migration and V1 shuts down.

7. **(Optional) Lock the V2 KMS key:**
   ```sh
   ./scripts/lock_kms_policy.sh  # with V2 PCR0 in artifacts/pcr.json
   ```

### Architecture

The init binary runs as a **supervisor** rather than exec'ing the upstream binary:

- Starts the upstream introspector as a child process on port 7074
- Runs a reverse proxy on port 7073 that adds `/v1/migration-status` and `/v1/enclave-info`
- Hosts a **vsock migration server** on port 9999 for V1-V2 communication
- On migration completion, signals the child process to shut down

V2 is detected by the `INTROSPECTOR_V1_CID` environment variable. When set, the init binary connects to V1's migration server instead of loading the key from KMS.

### Migration SSM Parameters

| Parameter | Description |
|-----------|-------------|
| `/<deployment>/NitroIntrospector/MigrationState` | JSON migration state (target PCR0, chain, timestamps) |
| `/<deployment>/NitroIntrospector/V2SecretKeyCiphertext` | V2-encrypted signing key ciphertext |
| `/<deployment>/NitroIntrospector/V2KMSKeyID` | KMS key ID for V2 enclave |
| `/<deployment>/NitroIntrospector/MaintainerSig` | Schnorr signature for migration authorization |
| `/<deployment>/NitroIntrospector/MigrationActivationTime` | Maintainer-specified activation timestamp |

## Reproducible Build

The enclave image is built entirely with [Nix](https://nixos.org/) using [monzo/aws-nitro-util](https://github.com/monzo/aws-nitro-util) inside a pinned Docker container, producing a byte-identical EIF on every build. This guarantees identical PCR0 measurements across builds, enabling anyone to verify that the running enclave matches the published source code.

### Nix packages

| Package                | Description                                    |
|------------------------|------------------------------------------------|
| `introspector-init`    | KMS decrypt + PCR16 binding + supervisor + migration |
| `introspector-upstream`| Upstream signing service (pinned commit)       |
| `nitriding`            | TLS termination + attestation daemon           |
| `viproxy`              | IMDS forwarding for enclave                    |
| `eif`                  | Complete enclave image (default)               |
Use `-insecure` to skip TLS verification during development.

## Reproducible Build Verification

The enclave image is built with [Nix](https://nixos.org/) using `dockerTools.buildImage`, which produces a byte-identical Docker image on every build. This eliminates non-determinism from Docker layer ordering and guarantees identical PCR0 measurements.

### Build the EIF (reproducible, via Docker)

Build the enclave EIF image and output its PCR values:

```sh
./scripts/build_eif.sh
```

Override defaults with environment variables: `VERSION`, `AWS_REGION`, `PREVIOUS_PCR0`, `MAINTAINER_PUBKEY`.

### Verify a running enclave

The client can build the EIF locally via Docker and compare PCR0 against the running enclave's attestation:

```sh
cd client && go run . \
  --base-url https://<enclave-ip> \
  --verify-build \
  --repo-path /path/to/introspector-enclave \
  --build-version dev \
  --build-region us-east-1 \
  --insecure
```

## Client

The included client (`client/`) verifies the enclave's attestation document and pubkey binding:

```sh
cd client && go run . \
  --base-url https://<enclave-ip> \
  --expected-pcr0 <hex> \
  --insecure
```

The client:

1. Fetches the attestation document with a random nonce
2. Verifies the attestation signature and PCR0
3. Fetches `/v1/info` and verifies `SHA384(zeros_48 || SHA256(pubkey))` matches attestation `PCRs[16]`
4. Fetches `/v1/enclave-info` and verifies `SHA256(attestationPubkey)` matches the `appKeyHash` in the attestation document's UserData
5. Verifies the `X-Attestation-Signature` header on the response against the attestation key

Use `--insecure` to skip TLS verification (trust comes from attestation). Use `--verify-pubkey=false` to skip step 3. Use `--verify-attestation-key=false` to skip steps 4-5.

## Configuration

All configuration is via environment variables prefixed with `INTROSPECTOR_`:

| Variable                                   | Description                            | Default    |
|--------------------------------------------|----------------------------------------|------------|
| `INTROSPECTOR_SECRET_KEY`                  | Signing key (hex). Set by KMS at boot. | (required) |
| `INTROSPECTOR_PORT`                        | HTTP listen port                       | `7073`     |
| `INTROSPECTOR_NO_TLS`                      | Disable TLS (nitriding handles TLS)    | `true`     |
| `INTROSPECTOR_LOG_LEVEL`                   | Log verbosity level                    | `debug`    |
| `INTROSPECTOR_SECRET_KEY_CIPHERTEXT`       | Base64 KMS ciphertext (direct)         | (from SSM) |
| `INTROSPECTOR_SECRET_KEY_CIPHERTEXT_PARAM` | SSM parameter name for ciphertext      | `/<deployment>/NitroIntrospector/SecretKeyCiphertext` |
| `INTROSPECTOR_DEPLOYMENT`                  | Deployment name for SSM paths          | `dev`      |
| `INTROSPECTOR_KMS_KEY_ID`                  | KMS key ID override                    | (auto)     |
| `INTROSPECTOR_NITRIDING_INT_PORT`          | Nitriding internal port                | `8080`     |
| `INTROSPECTOR_AWS_REGION`                  | AWS region for KMS/SSM                 | `us-east-1`|
| `INTROSPECTOR_V1_CID`                     | V1 enclave vsock CID (V2 migration mode) | (unset)  |
| `INTROSPECTOR_PROXY_PORT`                 | Reverse proxy listen port              | `7073`     |

## Watchdog

The enclave watchdog runs on the EC2 host as a systemd service (`enclave-watchdog.service`). It starts the Nitro Enclave via `nitro-cli` and restarts it if it exits.

| Variable                | Description                 | Default                                |
|-------------------------|-----------------------------|----------------------------------------|
| `ENCLAVE_NAME`          | Enclave name                | `app`                                  |
| `EIF_PATH`              | Path to enclave image file  | `/home/ec2-user/app/image.eif`         |
| `CPU_COUNT`             | vCPUs allocated to enclave  | `2`                                    |
| `MEMORY_MIB`            | Memory allocated (MiB)      | `4320`                                 |
| `ENCLAVE_CID`           | vsock CID                   | `16`                                   |
| `DEBUG_MODE`            | Enable debug console        | `false`                                |
| `POLL_INTERVAL_SECONDS` | Health check interval (s)   | `5`                                    |
