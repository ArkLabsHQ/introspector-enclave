package introspector_enclave

import "os"

// frameworkFile describes a template file to scaffold during `enclave init`.
type frameworkFile struct {
	RelPath string      // path relative to user's project root
	Mode    os.FileMode // file permissions
	Content string      // file content
}

// frameworkFiles returns the list of framework files to scaffold.
// These are required by CDK deploy (cdk.go) and Nix build (flake.nix).
func getFrameworkFiles() []frameworkFile {
	return []frameworkFile{
		{
			RelPath: "flake.nix",
			Mode:    0644,
			Content: frameworkFlakeNix,
		},
		{
			RelPath: "enclave/start.sh",
			Mode:    0755,
			Content: frameworkStartSh,
		},
		{
			RelPath: "enclave/gvproxy/Dockerfile",
			Mode:    0644,
			Content: frameworkGvproxyDockerfile,
		},
		{
			RelPath: "enclave/gvproxy/start.sh",
			Mode:    0755,
			Content: frameworkGvproxyStartSh,
		},
		{
			RelPath: "enclave/scripts/enclave_init.sh",
			Mode:    0755,
			Content: frameworkEnclaveInitSh,
		},
		{
			RelPath: "enclave/systemd/enclave-watchdog.service",
			Mode:    0644,
			Content: frameworkWatchdogService,
		},
		{
			RelPath: "enclave/systemd/enclave-imds-proxy.service",
			Mode:    0644,
			Content: frameworkIMDSProxyService,
		},
		{
			RelPath: "enclave/systemd/gvproxy.service",
			Mode:    0644,
			Content: frameworkGvproxyService,
		},
		{
			RelPath: "enclave/user_data/user_data",
			Mode:    0644,
			Content: frameworkUserData,
		},
	}
}

// EIF entrypoint — starts viproxy, nitriding, and the app binary.
const frameworkStartSh = `#!/bin/sh

set -e

# Start viproxy for IMDS access before nitriding sets up full networking
if [ "${ENCLAVE_VIPROXY_ENABLED:-true}" = "true" ]; then
  VIPROXY_IN_ADDRS="${ENCLAVE_VIPROXY_IN_ADDRS:-127.0.0.1:80}"
  VIPROXY_OUT_ADDRS="${ENCLAVE_VIPROXY_OUT_ADDRS:-3:8002}"
  IN_ADDRS="${VIPROXY_IN_ADDRS}" OUT_ADDRS="${VIPROXY_OUT_ADDRS}" /app/proxy &
  if [ -z "${AWS_EC2_METADATA_SERVICE_ENDPOINT:-}" ]; then
    export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:80"
  fi
fi

export ENCLAVE_NO_TLS=true

# The AWS SDK needs a region. Inside the enclave, IMDS region detection
# may fail, so we set it explicitly from the deployment config.
if [ -z "${AWS_DEFAULT_REGION:-}" ]; then
  export AWS_DEFAULT_REGION="${ENCLAVE_AWS_REGION:-us-east-1}"
fi
APP_PORT="${ENCLAVE_PROXY_PORT:-7073}"
NITRIDING_EXT_PORT="${ENCLAVE_NITRIDING_EXT_PORT:-443}"
NITRIDING_INT_PORT="${ENCLAVE_NITRIDING_INT_PORT:-8080}"
NITRIDING_PROM_PORT="${ENCLAVE_NITRIDING_PROM_PORT:-9090}"
NITRIDING_PROM_NS="${ENCLAVE_NITRIDING_PROM_NAMESPACE:-enclave}"
NITRIDING_FQDN="${ENCLAVE_NITRIDING_FQDN:-localhost}"

NITRIDING_ARGS="-fqdn ${NITRIDING_FQDN} \
  -ext-pub-port ${NITRIDING_EXT_PORT} \
  -intport ${NITRIDING_INT_PORT} \
  -appwebsrv http://127.0.0.1:${APP_PORT} \
  -prometheus-namespace ${NITRIDING_PROM_NS} \
  -prometheus-port ${NITRIDING_PROM_PORT}"

if [ "${ENCLAVE_NITRIDING_DEBUG:-false}" = "true" ]; then
  NITRIDING_ARGS="${NITRIDING_ARGS} -debug"
fi

# Configure DNS to use gvproxy gateway
echo "nameserver 192.168.127.1" > /etc/resolv.conf

# Start nitriding in background (it will set up networking via gvproxy)
exec /app/nitriding ${NITRIDING_ARGS} -appcmd "/app/enclave-supervisor"
`

// Gvproxy Docker image — builds gvproxy binary for forwarding ports into the enclave.
const frameworkGvproxyDockerfile = `# Gvproxy container for forwarding HTTP ports into the enclave.
FROM golang:1.25.5 AS builder

ARG GVPROXY_VERSION=v0.7.4
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go install github.com/containers/gvisor-tap-vsock/cmd/gvproxy@${GVPROXY_VERSION}

FROM alpine:3.20

RUN apk update && apk upgrade
RUN apk --no-cache add curl

WORKDIR /app

COPY --from=builder /go/bin/gvproxy /app/gvproxy
COPY enclave/gvproxy/start.sh /app/start.sh

CMD ["/app/start.sh"]
`

// Gvproxy entrypoint — starts gvproxy and sets up port forwarding.
const frameworkGvproxyStartSh = `#!/usr/bin/env sh
# Based on the gvproxy wrapper from the Nitro Enclave reference project.

set -e
set -x

VSOCK_SOCKET="${GVPROXY_SOCKET:-/tmp/network.sock}"
FORWARD_PORTS="${GVPROXY_FORWARD_PORTS:-${ENCLAVE_PORT:-7073}}"

setup_forward() {
  local_port=$1
  remote_port=$2
  curl --unix-socket "${VSOCK_SOCKET}" http:/unix/services/forwarder/expose \
    -X POST \
    -d "{\"local\":\":${local_port}\",\"remote\":\"192.168.127.2:${remote_port}\"}"
}

# Avoid "address already in use" if the socket is left behind.
if [ -S "${VSOCK_SOCKET}" ]; then
  rm -f "${VSOCK_SOCKET}"
fi

# Start gvproxy in the background.
/app/gvproxy -listen vsock://:1024 -listen unix://"${VSOCK_SOCKET}" &
GVPROXY_PID=$!

# Wait for gvproxy to start.
sleep 5

for port in ${FORWARD_PORTS}; do
  setup_forward "${port}" "${port}"
done

wait "${GVPROXY_PID}"
`

// Host-side script — starts the Nitro Enclave and polls until it exits.
const frameworkEnclaveInitSh = `#!/bin/sh
# Starts the Nitro Enclave and polls until it exits.
# Designed to run under systemd with Restart=always.
set -eu

NITRO_CLI="${NITRO_CLI_PATH:-/usr/bin/nitro-cli}"
ENCLAVE_NAME="${ENCLAVE_NAME:-app}"
EIF_PATH="${EIF_PATH:-/home/ec2-user/app/server/signing_server.eif}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MIB="${MEMORY_MIB:-4320}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
POLL_INTERVAL="${POLL_INTERVAL_SECONDS:-5}"
DEBUG_FLAG=""

if [ "${DEBUG_MODE:-false}" = "true" ]; then
  DEBUG_FLAG="--debug-mode"
fi

echo "starting enclave '${ENCLAVE_NAME}'"

$NITRO_CLI run-enclave \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MIB" \
  --eif-path "$EIF_PATH" \
  --enclave-cid "$ENCLAVE_CID" \
  --enclave-name "$ENCLAVE_NAME" \
  $DEBUG_FLAG

# Poll until the enclave stops running.
while $NITRO_CLI describe-enclaves \
  | grep -q "\"EnclaveName\": \"${ENCLAVE_NAME}\""; do
  sleep "$POLL_INTERVAL"
done

echo "enclave '${ENCLAVE_NAME}' is no longer running"
`

// Systemd unit — enclave lifecycle watchdog.
const frameworkWatchdogService = `#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
[Unit]
Description=Nitro Enclaves Init Service
After=network-online.target
DefaultDependencies=no
Requires=nitro-enclaves-allocator.service
After=nitro-enclaves-allocator.service

[Service]
EnvironmentFile=/etc/environment
Type=simple
StandardOutput=journal
StandardError=journal
ExecStart=/home/ec2-user/app/enclave_init.sh
ExecStop=/usr/bin/nitro-cli terminate-enclave --enclave-name app
Restart=always

[Install]
WantedBy=multi-user.target
`

// Systemd unit — vsock proxy for IMDS access from inside the enclave.
const frameworkIMDSProxyService = `#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
[Unit]
Description=Nitro Enclaves vsock IMDS Proxy
After=network-online.target
DefaultDependencies=no

[Service]
Type=simple
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vsock-proxy-imds
ExecStart=/bin/bash -ce "exec /usr/bin/vsock-proxy 8002 169.254.169.254 80 \
                --config /etc/nitro_enclaves/vsock-proxy.yaml \
                -w 5"
Restart=always
TimeoutSec=0

[Install]
WantedBy=multi-user.target
`

// Systemd unit — gvproxy Docker container for outbound networking.
const frameworkGvproxyService = `[Unit]
Description=Start gvproxy docker container on boot
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/docker run --restart=unless-stopped -d --name gvproxy \
  --privileged --security-opt seccomp=unconfined \
  -e GVPROXY_FORWARD_PORTS="443 7073 9090" \
  -p 443:443 -p 7073:7073 -p 9090:9090 \
  gvproxy:latest
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

// EC2 user_data cloud-init — installs dependencies, downloads EIF, configures services.
// Template variables (e.g. ${__REGION__}) are resolved by CDK Fn::Sub at deploy time.
const frameworkUserData = `Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
bootcmd:
  - [ dnf, install, aws-nitro-enclaves-cli, aws-nitro-enclaves-cli-devel, htop, git, jq, unzip, -y ]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash

exec > >(tee /var/log/user-data.log | logger -t user-data -s 2>/dev/console) 2>&1

set -x
set +e

usermod -aG docker ec2-user
usermod -aG ne ec2-user

ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
CPU_KEY=cpu_count
DEFAULT_MEM=6144
DEFAULT_CPU=2

sed -r "s/^(\s*$MEM_KEY\s*:\s*).*/\1$DEFAULT_MEM/" -i "$ALLOCATOR_YAML"
sed -r "s/^(\s*$CPU_KEY\s*:\s*).*/\1$DEFAULT_CPU/" -i "$ALLOCATOR_YAML"

VSOCK_PROXY_YAML=/etc/nitro_enclaves/vsock-proxy.yaml
cat <<EOF > $VSOCK_PROXY_YAML
allowlist:
- {address: kms.${__REGION__}.amazonaws.com, port: 443}
- {address: kms-fips.${__REGION__}.amazonaws.com, port: 443}
- {address: ssm.${__REGION__}.amazonaws.com, port: 443}
- {address: ssm-fips.${__REGION__}.amazonaws.com, port: 443}
- {address: sts.${__REGION__}.amazonaws.com, port: 443}
- {address: 169.254.169.254, port: 80}

EOF

systemctl enable --now docker
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now nitro-enclaves-vsock-proxy.service

cd /home/ec2-user

if [[ ! -d ./app/server ]]; then
  mkdir -p ./app/server
  chown -R ec2-user:ec2-user ./app
fi

# Download pre-built EIF from S3 (built reproducibly with Nix)
aws s3 cp ${__EIF_S3_URL__} /home/ec2-user/app/server/enclave.eif
chmod 644 /home/ec2-user/app/server/enclave.eif
chown ec2-user:ec2-user /home/ec2-user/app/server/enclave.eif

# Pull gvproxy image for outbound networking
ACCOUNT_ID=$( aws sts get-caller-identity | jq -r '.Account' )
REGION=$(TOKEN=` + "`" + `curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` + "`" + ` && curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/placement/region)
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
docker pull ${__GVPROXY_IMAGE_URI__}
docker tag ${__GVPROXY_IMAGE_URI__} gvproxy:latest

aws s3 cp ${__ENCLAVE_INIT_S3_URL__} /home/ec2-user/app/enclave_init.sh
chmod +x /home/ec2-user/app/enclave_init.sh

aws s3 cp ${__ENCLAVE_INIT_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-watchdog.service
aws s3 cp ${__IMDS_SYSTEMD_S3_URL__} /etc/systemd/system/enclave-imds-proxy.service
aws s3 cp ${__GVPROXY_SYSTEMD_S3_URL__} /etc/systemd/system/gvproxy.service

cat <<EOF >> /etc/environment
ENCLAVE_APP_NAME=${__APP_NAME__}
EIF_PATH=/home/ec2-user/app/server/enclave.eif
ENCLAVE_NITRIDING_ENABLED=true
ENCLAVE_NITRIDING_FQDN=example.com
ENCLAVE_KMS_KEY_ID=${__KMS_KEY_ID__}
ENCLAVE_DEPLOYMENT=${__DEV_MODE__}
ENCLAVE_AWS_REGION=${__REGION__}
EOF

systemctl enable --now enclave-watchdog.service
systemctl enable --now enclave-imds-proxy.service
systemctl enable --now gvproxy.service
--//--
`

// Nix flake for reproducible EIF builds.
const frameworkFlakeNix = `{
  description = "Nitro Enclave - reproducible build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        nitro = aws-nitro-util.lib.` + "${system}" + `;

        # Read build config generated by ` + "`" + `enclave build` + "`" + ` from enclave.yaml.
        # BUILD_CONFIG_PATH is set by the CLI; defaults to /src/build-config.json (Docker).
        # Requires --impure flag (already set by the CLI).
        configPath = let p = builtins.getEnv "BUILD_CONFIG_PATH"; in
          if p != "" then p else "/src/build-config.json";
        buildCfg = builtins.fromJSON (builtins.readFile configPath);
        appCfg = buildCfg.app;
        sdkCfg = buildCfg.sdk;

        # Fall back to env vars for backwards compatibility.
        version = buildCfg.version;
        region = buildCfg.region;
        deployment = buildCfg.prefix;

        # Enclave supervisor — built from the SDK repo.
        # Handles attestation, secrets, PCR extension, reverse proxy with
        # signing middleware. The user's app is just a plain HTTP server.
        enclave-supervisor = pkgs.buildGoModule {
          pname = "enclave-supervisor";
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector-enclave";
            rev = sdkCfg.rev;
            hash = sdkCfg.hash;
          };

          sourceRoot = "source/sdk";
          vendorHash = sdkCfg.vendor_hash;
          subPackages = [ "cmd/enclave-supervisor" ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "github.com/ArkLabsHQ/introspector-enclave/sdk.Version=` + "${version}" + `"
          ];
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;
        };

        # User's app — fetched from GitHub. No SDK dependency needed.
        upstream-app = pkgs.buildGoModule {
          pname = appCfg.binary_name;
          version = buildCfg.version;

          src = pkgs.fetchFromGitHub {
            owner = appCfg.nix_owner;
            repo = appCfg.nix_repo;
            rev = appCfg.nix_rev;
            hash = appCfg.nix_hash;
          };

          vendorHash = appCfg.nix_vendor_hash;

          subPackages = appCfg.nix_sub_packages;
          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;

          postInstall = ''
            # Rename whatever was built to the configured binary name.
            for f in $out/bin/*; do
              if [ "$(basename "$f")" != "` + "${appCfg.binary_name}" + `" ]; then
                mv "$f" "$out/bin/` + "${appCfg.binary_name}" + `"
              fi
            done
          '';
        };

        # Nitriding TLS termination daemon.
        nitriding = pkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = pkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        # Viproxy for IMDS forwarding inside the enclave.
        viproxy = pkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = pkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        # Assemble the /app directory with all binaries and scripts.
        appDir = pkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ` + "${upstream-app}" + `/bin/` + "${appCfg.binary_name}" + ` $out/app/` + "${appCfg.binary_name}" + `
          cp ` + "${enclave-supervisor}" + `/bin/enclave-supervisor $out/app/enclave-supervisor
          cp ` + "${nitriding}" + `/bin/nitriding $out/app/nitriding
          cp ` + "${viproxy}" + `/bin/proxy $out/app/proxy
          install -m 0755 ` + "${./enclave/start.sh}" + ` $out/app/start.sh
        '';

        # Complete rootfs for the enclave.
        enclaveRootfs = pkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            pkgs.busybox    # provides /bin/sh and basic utils
            pkgs.cacert     # TLS CA certificates
          ];
          pathsToLink = [ "/" ];
        };

        # Secrets config JSON baked into the EIF for runtime discovery.
        secretsCfgJson = builtins.toJSON (buildCfg.secrets or []);

        # Environment variables for the enclave.
        # Standard vars + all app-specific vars from build-config.json.
        enclaveEnv = let
          appEnvLines = builtins.concatStringsSep "\n"
            (builtins.map (k: "` + "${k}" + `=` + "${builtins.getAttr k appCfg.env}" + `")
              (builtins.attrNames appCfg.env));
        in ''
          PATH=/app:/bin:/usr/bin
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
          AWS_REGION=` + "${region}" + `
          ENCLAVE_APP_NAME=` + "${buildCfg.name}" + `
          ENCLAVE_SECRETS_CONFIG=` + "${secretsCfgJson}" + `
          ENCLAVE_DEPLOYMENT=` + "${deployment}" + `
          ` + "${appEnvLines}" + `
        '';

        # Build EIF using monzo/aws-nitro-util (reproducible, no Docker).
        eif = nitro.buildEif {
          name = "` + "${buildCfg.name}" + `-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

      in
      {
        packages = {
          inherit upstream-app enclave-supervisor nitriding viproxy eif;
          default = eif;
        };
      }
    );
}
`
