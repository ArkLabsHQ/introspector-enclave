#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-dev}"
AWS_REGION="${AWS_REGION:-us-east-1}"
NIX_IMAGE="${NIX_IMAGE:-nixos/nix:2.24.9}"

docker run --rm \
  -v "$(pwd)":/src -w /src \
  -e VERSION -e AWS_REGION \
  "$NIX_IMAGE" \
  sh -c 'git config --global --add safe.directory /src && nix build --impure --extra-experimental-features "nix-command flakes" .#eif && cat result/pcr.json'
