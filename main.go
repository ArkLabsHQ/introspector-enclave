package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"syscall"

	"github.com/ArkLabsHQ/introspector/internal/config"
	log "github.com/sirupsen/logrus"
)

var Version = "dev"

const introspectorBin = "/app/introspector"

func main() {
	log.Infof("introspector-init %s starting", Version)

	// 1. Decrypt the signing key from KMS (with attestation).
	if err := waitForSecretKeyFromKMS(context.Background()); err != nil {
		log.Fatalf("failed to load secret key from KMS: %s", err)
	}

	// 2. Validate the key and derive the public key.
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	pubkeyBytes := cfg.SecretKey.PubKey().SerializeCompressed()

	// 3. Register the signing pubkey hash with nitriding so it is included in
	// attestation documents (UserData field). Clients can then verify that
	// the attested enclave holds this exact key.
	if err := registerPubkeyWithNitriding(pubkeyBytes); err != nil {
		log.Warnf("failed to register pubkey with nitriding (may not be running): %s", err)
	}
	signalNitridingReady()

	// 4. Exec the real introspector binary, replacing this process.
	// The upstream binary reads INTROSPECTOR_SECRET_KEY from the environment
	// (already set by waitForSecretKeyFromKMS) and serves the full signing API.
	log.Infof("exec %s", introspectorBin)
	err = syscall.Exec(introspectorBin, []string{"introspector"}, os.Environ())
	// syscall.Exec only returns on error.
	log.Fatalf("exec %s: %s", introspectorBin, err)
}

// nitridingIntPort returns the nitriding internal port (default 8080).
func nitridingIntPort() string {
	if p := os.Getenv("INTROSPECTOR_NITRIDING_INT_PORT"); p != "" {
		return p
	}
	return "8080"
}

// registerPubkeyWithNitriding POSTs SHA256(compressedPubkey) to nitriding's
// /enclave/hash endpoint.  Nitriding includes this hash in the UserData field
// of all subsequent attestation documents, binding the enclave identity to the
// signing key.
func registerPubkeyWithNitriding(compressedPubkey []byte) error {
	hash := sha256.Sum256(compressedPubkey)
	body := base64.StdEncoding.EncodeToString(hash[:])

	url := fmt.Sprintf("http://127.0.0.1:%s/enclave/hash", nitridingIntPort())
	resp, err := http.Post(url, "application/octet-stream", bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("POST /enclave/hash: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /enclave/hash returned %d", resp.StatusCode)
	}

	log.Infof("registered pubkey hash with nitriding (sha256: %s)", hex.EncodeToString(hash[:]))
	return nil
}

// signalNitridingReady tells nitriding the application is ready to serve.
func signalNitridingReady() {
	url := fmt.Sprintf("http://127.0.0.1:%s/enclave/ready", nitridingIntPort())
	resp, err := http.Get(url)
	if err != nil {
		log.Warnf("failed to signal readiness to nitriding: %s", err)
		return
	}
	defer resp.Body.Close()
	log.Info("signaled readiness to nitriding")
}
