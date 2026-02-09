package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
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
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	pubkeyBytes := cfg.SecretKey.PubKey().SerializeCompressed()

	// 3. Extend PCR16 with the signing pubkey hash, making the key binding a
	// first-class PCR value in the attestation document rather than parsing it
	// out of nitriding's internal UserData serialization format.
	if err := extendPCR16WithPubkey(pubkeyBytes); err != nil {
		log.Fatalf("failed to extend PCR16 with pubkey hash: %s", err)
	}

	// 4. Exec the real introspector binary, replacing this process.
	// The upstream binary reads INTROSPECTOR_SECRET_KEY from the environment
	// (already set by waitForSecretKeyFromKMS) and serves the full signing API.
	log.Infof("exec %s", introspectorBin)
	err = syscall.Exec(introspectorBin, []string{"introspector"}, os.Environ())
	// syscall.Exec only returns on error.
	log.Fatalf("exec %s: %s", introspectorBin, err)
}

// extendPCR16WithPubkey extends PCR16 with SHA256(compressedPubkey) and locks it.
// The resulting PCR16 value is SHA384(zeros48 || SHA256(pubkey)), which clients
// can verify directly from the attestation document's PCRs[16] field.
func extendPCR16WithPubkey(compressedPubkey []byte) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

	hash := sha256.Sum256(compressedPubkey)

	resp, err := session.Send(&request.ExtendPCR{
		Index: 16,
		Data:  hash[:],
	})
	if err != nil {
		return fmt.Errorf("ExtendPCR(16): %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(16): NSM error: %s", resp.Error)
	}

	resp, err = session.Send(&request.LockPCR{
		Index: 16,
	})
	if err != nil {
		return fmt.Errorf("LockPCR(16): %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(16): NSM error: %s", resp.Error)
	}

	log.Infof("extended and locked PCR16 with pubkey hash (sha256: %s)", hex.EncodeToString(hash[:]))
	return nil
}
