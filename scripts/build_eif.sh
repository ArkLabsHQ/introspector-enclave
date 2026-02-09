#!/usr/bin/env bash
# Builds the enclave EIF reproducibly using a pinned NixOS Docker image.
# Outputs artifacts/image.eif and artifacts/pcr.json.
#
# Usage:
#   ./scripts/build_eif.sh
#   VERSION=v1.0 AWS_REGION=us-east-1 ./scripts/build_eif.sh
#
# Requires: docker
set -euo pipefail

NIX_IMAGE="${NIX_IMAGE:-nixos/nix:2.24.9}"
VERSION="${VERSION:-dev}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Resolve repo root (script may be called from any directory)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v docker &>/dev/null; then
  echo "docker not found in PATH" >&2
  exit 1
fi

# Clean stale artifacts
rm -rf "${REPO_ROOT}/artifacts"
mkdir -p "${REPO_ROOT}/artifacts"

echo "[build] Building EIF with ${NIX_IMAGE} (VERSION=${VERSION}, AWS_REGION=${AWS_REGION})..."

# Build inside Docker, then copy outputs from nix store to the mounted /src/artifacts.
# The nix store only exists inside the container, so we must copy before it exits.
docker run --rm \
  -v "${REPO_ROOT}:/src" \
  -w /src \
  -e VERSION="${VERSION}" \
  -e AWS_REGION="${AWS_REGION}" \
  "${NIX_IMAGE}" \
  sh -c '
    git config --global --add safe.directory /src
    nix build --impure --extra-experimental-features "nix-command flakes" ./builder#eif
    cp result/image.eif /src/artifacts/image.eif
    cp result/pcr.json /src/artifacts/pcr.json
  '

if [[ ! -f "${REPO_ROOT}/artifacts/pcr.json" ]]; then
  echo "[build] ERROR: artifacts/pcr.json not found after build" >&2
  exit 1
fi

echo "[build] EIF built successfully"
echo "[build] PCR0: $(jq -r '.PCR0' "${REPO_ROOT}/artifacts/pcr.json")"
echo "[build] PCR1: $(jq -r '.PCR1' "${REPO_ROOT}/artifacts/pcr.json")"
echo "[build] PCR2: $(jq -r '.PCR2' "${REPO_ROOT}/artifacts/pcr.json")"
