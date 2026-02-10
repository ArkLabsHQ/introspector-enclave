package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	log "github.com/sirupsen/logrus"
)

var Version = "dev"

// PreviousPCR0 is set at build time via -ldflags to the PCR0 of the previous
// enclave version. This creates an immutable attestation chain: each binary
// knows its predecessor, and clients can verify the full upgrade lineage.
// Set to "genesis" for the very first enclave build.
var PreviousPCR0 = "genesis"

// MaintainerPubkey is set at build time via -ldflags to the hex-encoded
// x-only (32-byte) Schnorr public key of the maintainer(s) authorized to
// approve software migrations. Can be a single key or a MuSig/FROST aggregate.
// If empty, migration authorization signatures are not required (unsafe for production).
var MaintainerPubkey = ""

// attestationKey is an ephemeral secp256k1 key generated fresh each boot.
// Its public key hash is registered with nitriding via POST /enclave/hash,
// embedding it as appKeyHash in the attestation document's UserData.
// This provides per-response authentication independent of TLS and is
// compatible with nitriding's horizontal scaling (leader-worker key sync).
var attestationKey *btcec.PrivateKey

const introspectorBin = "/app/introspector"

func main() {
	log.Infof("introspector-init %s starting (previous_pcr0=%s, maintainer=%s)",
		Version, truncateHex(PreviousPCR0), truncateHex(MaintainerPubkey))

	// V2 migration boot path: if INTROSPECTOR_V1_CID is set, this enclave
	// is V2 and must obtain the signing key from V1 via the migration protocol.
	if v1CIDStr := os.Getenv("INTROSPECTOR_V1_CID"); v1CIDStr != "" {
		v1CID, err := strconv.ParseUint(v1CIDStr, 10, 32)
		if err != nil {
			log.Fatalf("invalid INTROSPECTOR_V1_CID: %s", err)
		}
		log.Infof("V2 mode: migrating key from V1 enclave (CID %d)", v1CID)
		if err := connectToV1Migration(context.Background(), uint32(v1CID)); err != nil {
			log.Fatalf("V2 migration failed: %s", err)
		}
		log.Info("V2 migration complete, generating attestation key")
		if err := generateAttestationKey(); err != nil {
			log.Fatalf("failed to generate attestation key: %s", err)
		}
		runSupervisor(nil) // No migration server for V2
		return
	}

	// V1 boot path: decrypt key from KMS and run as supervisor with migration server.
	if err := waitForSecretKeyFromKMS(context.Background()); err != nil {
		log.Fatalf("failed to load secret key from KMS: %s", err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	pubkeyBytes := cfg.SecretKey.PubKey().SerializeCompressed()

	if err := extendPCR16WithPubkey(pubkeyBytes); err != nil {
		log.Fatalf("failed to extend PCR16 with pubkey hash: %s", err)
	}

	// Generate ephemeral attestation key and bind into PCR17.
	if err := generateAttestationKey(); err != nil {
		log.Fatalf("failed to generate attestation key: %s", err)
	}

	// Extract raw secret key bytes for the migration server.
	secretKeyBytes := cfg.SecretKey.Serialize()

	runSupervisor(secretKeyBytes)
}

// runSupervisor starts the upstream introspector as a child process behind a
// reverse proxy, and optionally runs the migration vsock server.
// If secretKey is nil, no migration server is started (V2 mode).
func runSupervisor(secretKey []byte) {
	// The upstream introspector listens on an internal port (7074).
	// Our reverse proxy listens on the configured port (7073) and
	// adds /v1/migration-status before forwarding to upstream.
	upstreamPort := "7074"
	os.Setenv("INTROSPECTOR_PORT", upstreamPort)

	migrationDone := make(chan struct{})

	// Start migration vsock server (V1 only).
	if secretKey != nil {
		go startMigrationServer(secretKey, migrationDone)
	}

	// Start the reverse proxy that intercepts /v1/migration-status.
	proxyPort := os.Getenv("INTROSPECTOR_PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "7073"
	}
	go startReverseProxy(proxyPort, upstreamPort)

	// Start upstream introspector as child process.
	cmd := exec.Command(introspectorBin)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start %s: %s", introspectorBin, err)
	}
	log.Infof("started upstream introspector (PID %d) on port %s", cmd.Process.Pid, upstreamPort)

	// Wait for either: child exit, migration completion, or SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	select {
	case <-migrationDone:
		log.Info("migration complete, shutting down V1")
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		os.Exit(0)
	case err := <-cmdDone:
		if err != nil {
			log.Fatalf("introspector exited with error: %s", err)
		}
		log.Info("introspector exited cleanly")
	case sig := <-sigCh:
		log.Infof("received signal %s, shutting down", sig)
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}
}

// startReverseProxy runs an HTTP proxy on proxyPort that:
// - Handles /v1/migration-status locally
// - Forwards everything else to the upstream introspector on upstreamPort
func startReverseProxy(proxyPort, upstreamPort string) {
	upstream, _ := url.Parse("http://127.0.0.1:" + upstreamPort)
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/migration-status", handleMigrationStatus)
	mux.HandleFunc("GET /v1/enclave-info", handleEnclaveInfo)

	// Forward everything else to upstream.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	// Wrap all responses with attestation signature.
	var handler http.Handler = mux
	handler = attestationSigningMiddleware(handler)

	log.Infof("reverse proxy listening on :%s -> upstream :%s", proxyPort, upstreamPort)
	if err := http.ListenAndServe(":"+proxyPort, handler); err != nil {
		log.Fatalf("reverse proxy: %s", err)
	}
}

func handleMigrationStatus(w http.ResponseWriter, r *http.Request) {
	awsCfg, err := loadAWSConfigWithIMDS(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("load AWS config: %v", err), http.StatusInternalServerError)
		return
	}
	ssmClient := ssm.NewFromConfig(awsCfg)
	state, err := loadMigrationState(r.Context(), ssmClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("load migration state: %v", err), http.StatusInternalServerError)
		return
	}

	resp := struct {
		State           *MigrationState `json:"state"`
		CooldownExpired bool            `json:"cooldown_expired,omitempty"`
	}{
		State: state,
	}
	if state != nil && state.CompletedAt == 0 {
		resp.CooldownExpired = isCooldownExpired(state)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleEnclaveInfo returns build-time and runtime metadata about this enclave,
// including the attestation chain, maintainer key, and ephemeral attestation key.
func handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		Version            string `json:"version"`
		PreviousPCR0       string `json:"previous_pcr0"`
		MaintainerPubkey   string `json:"maintainer_pubkey,omitempty"`
		AttestationPubkey  string `json:"attestation_pubkey,omitempty"`
	}{
		Version:          Version,
		PreviousPCR0:     PreviousPCR0,
		MaintainerPubkey: MaintainerPubkey,
	}
	if attestationKey != nil {
		resp.AttestationPubkey = hex.EncodeToString(
			attestationKey.PubKey().SerializeCompressed())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// truncateHex returns the first 16 chars of a hex string with "..." appended,
// or the original string if shorter. Used for log output.
func truncateHex(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}

// extendPCR16WithPubkey extends PCR16 with SHA256(compressedPubkey) and locks it.
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

// generateAttestationKey creates an ephemeral secp256k1 keypair for signing
// API responses. The public key hash is registered with nitriding via
// POST /enclave/hash, which embeds it as appKeyHash in the attestation
// document's UserData. This is compatible with nitriding's horizontal
// scaling (leader-worker key sync).
func generateAttestationKey() error {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate random bytes: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	if privKey == nil {
		return fmt.Errorf("invalid secp256k1 key from random bytes")
	}
	attestationKey = privKey

	// Register SHA256(compressed attestation pubkey) with nitriding as appKeyHash.
	pubkeyBytes := privKey.PubKey().SerializeCompressed()
	hash := sha256.Sum256(pubkeyBytes)
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])

	nitridingPort := os.Getenv("INTROSPECTOR_NITRIDING_INT_PORT")
	if nitridingPort == "" {
		nitridingPort = "8080"
	}
	nitridingURL := fmt.Sprintf("http://127.0.0.1:%s/enclave/hash", nitridingPort)

	resp, err := http.Post(nitridingURL, "text/plain", strings.NewReader(hashB64))
	if err != nil {
		return fmt.Errorf("POST /enclave/hash: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST /enclave/hash status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	log.Infof("generated attestation key, registered with nitriding (pubkey: %s, sha256: %s)",
		hex.EncodeToString(pubkeyBytes),
		hex.EncodeToString(hash[:]))
	return nil
}

// signResponse signs the response body with the attestation key using BIP-340
// Schnorr signatures and adds the signature as an X-Attestation-Signature header.
// The signed message is SHA256(response_body).
func signResponse(body []byte) string {
	if attestationKey == nil {
		return ""
	}
	msgHash := sha256.Sum256(body)
	sig, err := schnorr.Sign(attestationKey, msgHash[:])
	if err != nil {
		log.Warnf("attestation sign failed: %v", err)
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// attestationSigningMiddleware wraps an http.Handler to sign all responses
// with the ephemeral attestation key.
func attestationSigningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attestationKey == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Buffer the response to sign it.
		rec := &responseRecorder{
			headers: w.Header(),
			body:    &bytes.Buffer{},
			status:  http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		// Sign the response body.
		body := rec.body.Bytes()
		if sig := signResponse(body); sig != "" {
			w.Header().Set("X-Attestation-Signature", sig)
			w.Header().Set("X-Attestation-Pubkey",
				hex.EncodeToString(attestationKey.PubKey().SerializeCompressed()))
		}

		// Write the buffered response.
		w.WriteHeader(rec.status)
		w.Write(body)
	})
}

// responseRecorder captures HTTP response data for signing.
type responseRecorder struct {
	headers http.Header
	body    *bytes.Buffer
	status  int
}

func (r *responseRecorder) Header() http.Header { return r.headers }
func (r *responseRecorder) WriteHeader(code int) { r.status = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// Ensure responseRecorder satisfies io.ReaderFrom for efficient proxying.
func (r *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(r.body, src)
}
