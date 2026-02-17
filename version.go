package introspector_enclave

// These variables are set at build time via ldflags:
//
//	go build -ldflags "-X github.com/ArkLabsHQ/introspector-enclave.sdkRev=..."
//
// Release builds (via Makefile / CI) populate these from sdk-hashes.json.
// Development builds leave them empty — the user fills in sdk: manually.
var (
	sdkRev        string // SDK git commit SHA or tag
	sdkHash       string // Nix source hash (SRI format, e.g. sha256-...)
	sdkVendorHash string // Go vendor hash (SRI format, e.g. sha256-...)
)
