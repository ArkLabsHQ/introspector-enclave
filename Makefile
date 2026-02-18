REPO_OWNER := ArkLabsHQ
REPO_NAME  := introspector-enclave
HASHES_FILE := sdk-hashes.json
NIX_IMAGE   := nixos/nix:2.24.9

# Default REV to latest tag, or HEAD if no tags exist.
REV ?= $(shell git describe --tags --abbrev=0 2>/dev/null || git rev-parse HEAD)
# Set LOCAL=1 to use local nix instead of Docker container.
LOCAL ?=

# Read cached hashes from sdk-hashes.json (if it exists).
SDK_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
SDK_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
SDK_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE).sdkRev=$(SDK_REV) \
           -X $(MODULE).sdkHash=$(SDK_HASH) \
           -X $(MODULE).sdkVendorHash=$(SDK_VENDOR_HASH)

.PHONY: build install sdk-hashes help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with SDK hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cmd/enclave

install: ## Install the enclave CLI to $GOPATH/bin with SDK hashes baked in
	go install -ldflags '$(LDFLAGS)' ./cmd/enclave

sdk-hashes: ## Tag REV, compute source+vendor hashes, commit (LOCAL=1 to skip Docker)
	@if [ "$(REV)" = "$$(git describe --tags --abbrev=0 2>/dev/null || git rev-parse HEAD)" ] && ! git tag -l "$(REV)" | grep -q .; then \
	  echo "Error: REV=$(REV) looks like a default — pass an explicit REV=vX.Y.Z"; exit 1; \
	fi
	@# Step 1: Create the tag if it doesn't exist yet.
	@if git tag -l "$(REV)" | grep -q .; then \
	  echo "[sdk-hashes] Tag $(REV) already exists"; \
	else \
	  echo "[sdk-hashes] Creating tag $(REV)..." && \
	  git tag "$(REV)"; \
	fi
	@# Step 2: Compute source hash from the tagged tree.
	@echo "[sdk-hashes] Computing source hash..."
	@TMPDIR=$$(mktemp -d) && \
	git archive --format=tar.gz --prefix=source/ $(REV) | tar xz -C "$$TMPDIR" && \
	if [ -n "$(LOCAL)" ]; then \
	  SOURCE_HASH=$$(nix hash path "$$TMPDIR/source"); \
	else \
	  SOURCE_HASH=$$(docker run --rm -v "$$TMPDIR:/work:ro" $(NIX_IMAGE) \
	    nix --extra-experimental-features nix-command hash path /work/source); \
	fi && \
	rm -rf "$$TMPDIR" && \
	echo '{"rev":"$(REV)","hash":"'$$SOURCE_HASH'","vendor_hash":""}' | jq '.' > $(HASHES_FILE) && \
	echo "  Source hash: $$SOURCE_HASH"
	@# Step 3: Compute vendor hash via a failing nix build.
	@echo "[sdk-hashes] Computing vendor hash (this does a trial nix build)..."
	@NIX_EXPR='let pkgs = import <nixpkgs> {}; in pkgs.buildGoModule { pname = "enclave-supervisor"; version = "dev"; src = ./.; subPackages = ["cmd/enclave-supervisor"]; vendorHash = ""; doCheck = false; }' && \
	if [ -n "$(LOCAL)" ]; then \
	  OUTPUT=$$(cd sdk && nix build --impure \
	    --extra-experimental-features 'nix-command flakes' \
	    --expr "$$NIX_EXPR" 2>&1); \
	else \
	  OUTPUT=$$(docker run --rm -e NIX_PATH=nixpkgs=channel:nixos-25.05 -v "$(CURDIR):/src" -w /src/sdk $(NIX_IMAGE) \
	    sh -c "git config --global --add safe.directory /src && \
	    nix build --impure --extra-experimental-features 'nix-command flakes' \
	    --expr '$$NIX_EXPR'" 2>&1); \
	fi; \
	EXPECTED=$$(echo "$$OUTPUT" | grep 'got:' | awk '{print $$2}') && \
	if [ -n "$$EXPECTED" ]; then \
	  jq --arg vh "$$EXPECTED" '.vendor_hash = $$vh' $(HASHES_FILE) > $(HASHES_FILE).tmp && \
	  mv $(HASHES_FILE).tmp $(HASHES_FILE) && \
	  echo "  Vendor hash: $$EXPECTED"; \
	else \
	  echo "Error: could not extract vendor hash from nix build output." && \
	  echo "$$OUTPUT" | tail -20; \
	  exit 1; \
	fi
	@# Step 4: Commit sdk-hashes.json.
	@echo "[sdk-hashes] Committing sdk-hashes.json..."
	@git add $(HASHES_FILE) && \
	git commit -m "sdk hashes for $(REV)" && \
	echo "" && \
	echo "[sdk-hashes] Done." && \
	echo "  Push with: git push && git push --tags"
