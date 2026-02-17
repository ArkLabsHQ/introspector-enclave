REPO_OWNER := ArkLabsHQ
REPO_NAME  := introspector-enclave
HASHES_FILE := sdk-hashes.json

# Default REV to latest tag, or HEAD if no tags exist.
REV ?= $(shell git describe --tags --abbrev=0 2>/dev/null || git rev-parse HEAD)

# Read cached hashes from sdk-hashes.json (if it exists).
SDK_REV        = $(shell jq -r '.rev'         $(HASHES_FILE) 2>/dev/null)
SDK_HASH       = $(shell jq -r '.hash'        $(HASHES_FILE) 2>/dev/null)
SDK_VENDOR_HASH = $(shell jq -r '.vendor_hash' $(HASHES_FILE) 2>/dev/null)

MODULE  := github.com/ArkLabsHQ/introspector-enclave

LDFLAGS := -X $(MODULE).sdkRev=$(SDK_REV) \
           -X $(MODULE).sdkHash=$(SDK_HASH) \
           -X $(MODULE).sdkVendorHash=$(SDK_VENDOR_HASH)

.PHONY: build sdk-hashes help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build the enclave CLI with SDK hashes baked in
	go build -ldflags '$(LDFLAGS)' -o enclave-cli ./cmd/enclave

sdk-hashes: ## Compute SDK nix hashes for REV (default: latest tag)
	@echo "Computing hashes for $(REV)..."
	@SOURCE_HASH=$$(nix hash to-sri sha256:$$(nix-prefetch-url --unpack --type sha256 \
	  "https://github.com/$(REPO_OWNER)/$(REPO_NAME)/archive/$(REV).tar.gz" 2>/dev/null)) && \
	echo '{"rev":"$(REV)","hash":"'$$SOURCE_HASH'","vendor_hash":""}' | jq '.' > $(HASHES_FILE) && \
	echo "Source hash: $$SOURCE_HASH" && \
	echo "" && \
	echo "sdk-hashes.json written with empty vendor_hash." && \
	echo "To get the vendor hash:" && \
	echo "  1. Set vendor_hash to \"\" in a test flake and run nix build" && \
	echo "  2. Nix will print the expected hash — paste it into sdk-hashes.json" && \
	echo "  3. Or run: make vendor-hash"

vendor-hash: ## Compute vendor hash by doing a test Nix build (requires sdk-hashes.json)
	@echo "Building enclave-supervisor to compute vendor hash..."
	@echo "This will fail once to reveal the expected hash, then update sdk-hashes.json."
	@EXPECTED=$$(cd sdk && nix build --impure \
	  --extra-experimental-features 'nix-command flakes' \
	  --expr 'let pkgs = import <nixpkgs> {}; in pkgs.buildGoModule { \
	    pname = "enclave-supervisor"; version = "dev"; \
	    src = ./.; subPackages = ["cmd/enclave-supervisor"]; \
	    vendorHash = ""; env.CGO_ENABLED = "0"; doCheck = false; }' \
	  2>&1 | grep 'got:' | awk '{print $$2}') && \
	if [ -n "$$EXPECTED" ]; then \
	  jq --arg vh "$$EXPECTED" '.vendor_hash = $$vh' $(HASHES_FILE) > $(HASHES_FILE).tmp && \
	  mv $(HASHES_FILE).tmp $(HASHES_FILE) && \
	  echo "Vendor hash: $$EXPECTED" && \
	  echo "sdk-hashes.json updated."; \
	else \
	  echo "Could not extract vendor hash. Check nix build output manually."; \
	  exit 1; \
	fi
