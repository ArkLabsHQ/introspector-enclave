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
	"strings"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

var Version = "dev"

// PreviousPCR0 is the PCR0 of the previous enclave version, forming an
// attestation chain. Set at runtime during migration (fetched from the old
// enclave's attestation document), or defaults to "genesis" for first boot.
var PreviousPCR0 = "genesis"

// attestationKey is an ephemeral secp256k1 key generated fresh each boot.
// Its public key hash is registered with nitriding via POST /enclave/hash,
// embedding it as appKeyHash in the attestation document's UserData.
var attestationKey *btcec.PrivateKey

// secretsDefs holds the configured secrets, loaded from ENCLAVE_SECRETS_CONFIG.
var secretsDefs []SecretDef

// initError captures any initialization error so it can be surfaced
// via /v1/enclave-info instead of crashing the process.
var initError string

// SecretDef defines a secret managed by KMS inside the enclave.
type SecretDef struct {
	Name   string `json:"name"`
	EnvVar string `json:"env_var"`
}

// loadSecretsConfig parses the ENCLAVE_SECRETS_CONFIG env var (JSON array).
func loadSecretsConfig() ([]SecretDef, error) {
	raw := os.Getenv("ENCLAVE_SECRETS_CONFIG")
	if raw == "" {
		return nil, nil
	}
	var secrets []SecretDef
	if err := json.Unmarshal([]byte(raw), &secrets); err != nil {
		return nil, fmt.Errorf("parse ENCLAVE_SECRETS_CONFIG: %w", err)
	}
	return secrets, nil
}

// appBinary returns the path to the upstream app binary.
// Reads APP_BINARY_NAME from the environment (set via enclave.yaml env config),
// falling back to "app" for a generic default.
func appBinary() string {
	if name := os.Getenv("APP_BINARY_NAME"); name != "" {
		return "/app/" + name
	}
	return "/app/app"
}

func main() {
	if err := initEnclave(); err != nil {
		initError = err.Error()
	}
	runSupervisor()
}

// initEnclave performs all initialization steps, returning the first error
// encountered. Non-fatal steps (migration) are best-effort.
func initEnclave() error {
	secrets, err := loadSecretsConfig()
	if err != nil {
		return fmt.Errorf("load secrets config: %w", err)
	}
	secretsDefs = secrets

	// Generate ephemeral attestation key and register with nitriding ASAP.
	// Only needs crypto/rand + localhost POST to nitriding (no AWS deps).
	if err := generateAttestationKey(); err != nil {
		return fmt.Errorf("generate attestation key: %w", err)
	}

	if len(secrets) > 0 {
		if err := waitForSecretsFromKMS(context.Background(), secrets); err != nil {
			return fmt.Errorf("load secrets from KMS: %w", err)
		}

		if err := extendPCRsWithSecretPubkeys(secrets); err != nil {
			return fmt.Errorf("extend PCRs with secret pubkeys: %w", err)
		}
	}

	// Best-effort migration check.
	if pcr0, err := readMigrationPreviousPCR0(context.Background()); err == nil {
		PreviousPCR0 = pcr0
	}

	deleteOldKMSKey(context.Background())
	return nil
}

// runSupervisor starts the upstream app as a child process behind a
// reverse proxy that signs all responses with the attestation key.
func runSupervisor() {
	upstreamPort := "7074"
	os.Setenv("ENCLAVE_UPSTREAM_PORT", upstreamPort)

	proxyPort := os.Getenv("ENCLAVE_PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "7073"
	}
	go startReverseProxy(proxyPort, upstreamPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// If init failed, don't start the upstream app — just keep the
	// reverse proxy alive so /v1/enclave-info can serve the error.
	if initError != "" {
		<-sigCh
		return
	}

	bin := appBinary()
	cmd := exec.Command(bin)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout

	// Capture stderr so we can surface the app's error via /v1/enclave-info.
	var stderrBuf bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	if err := cmd.Start(); err != nil {
		initError = fmt.Sprintf("failed to start %s: %s", bin, err)
		fmt.Fprintf(os.Stderr, "%s\n", initError)
		<-sigCh
		return
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	select {
	case err := <-cmdDone:
		if err != nil {
			stderr := strings.TrimSpace(stderrBuf.String())
			if len(stderr) > 512 {
				stderr = stderr[len(stderr)-512:]
			}
			if stderr != "" {
				initError = fmt.Sprintf("upstream app exited: %s: %s", err, stderr)
			} else {
				initError = fmt.Sprintf("upstream app exited: %s", err)
			}
			fmt.Fprintf(os.Stderr, "%s\n", initError)
			// Keep reverse proxy alive so /v1/enclave-info can report the error.
			<-sigCh
		}
	case <-sigCh:
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}
}

// startReverseProxy runs an HTTP proxy on proxyPort that:
// - Handles management endpoints locally (/v1/enclave-info, /v1/export-key, /v1/lock-pcr)
// - Forwards everything else to the upstream app on upstreamPort
func startReverseProxy(proxyPort, upstreamPort string) {
	upstream, _ := url.Parse("http://127.0.0.1:" + upstreamPort)
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/enclave-info", handleEnclaveInfo)
	mux.HandleFunc("POST /v1/export-key", handleExportKey)
	mux.HandleFunc("POST /v1/lock-pcr", handleLockPCR)

	// Forward everything else to upstream.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	// Wrap all responses with attestation signature.
	var handler http.Handler = mux
	handler = attestationSigningMiddleware(handler)

	if err := http.ListenAndServe(":"+proxyPort, handler); err != nil {
		fmt.Fprintf(os.Stderr, "reverse proxy: %s\n", err)
		os.Exit(1)
	}
}

// handleEnclaveInfo returns build-time and runtime metadata about this enclave,
// including any initialization error so callers can diagnose issues.
func handleEnclaveInfo(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		Version           string `json:"version"`
		PreviousPCR0      string `json:"previous_pcr0"`
		AttestationPubkey string `json:"attestation_pubkey,omitempty"`
		Error             string `json:"error,omitempty"`
	}{
		Version:      Version,
		PreviousPCR0: PreviousPCR0,
		Error:        initError,
	}
	if attestationKey != nil {
		resp.AttestationPubkey = hex.EncodeToString(
			attestationKey.PubKey().SerializeCompressed())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleLockPCR locks a user-defined PCR (16-32) to prevent further extension.
func handleLockPCR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PCR uint `json:"pcr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.PCR < 16 || req.PCR > 31 {
		http.Error(w, "pcr must be in range [16, 31]", http.StatusBadRequest)
		return
	}

	if err := lockPCR(req.PCR); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"pcr":%d,"status":"locked"}`, req.PCR)
}

// extendPCR extends a PCR with the given data via the NSM.
func extendPCR(index uint, data []byte) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

	resp, err := session.Send(&request.ExtendPCR{
		Index: uint16(index),
		Data:  data,
	})
	if err != nil {
		return fmt.Errorf("ExtendPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("ExtendPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// lockPCR locks a PCR to prevent further extension.
func lockPCR(index uint) error {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

	resp, err := session.Send(&request.LockPCR{
		Index: uint16(index),
	})
	if err != nil {
		return fmt.Errorf("LockPCR(%d): %w", index, err)
	}
	if resp.Error != "" {
		return fmt.Errorf("LockPCR(%d): NSM error: %s", index, resp.Error)
	}
	return nil
}

// extendPCRsWithSecretPubkeys derives the secp256k1 compressed public key for
// each secret and extends PCR (16 + index) with SHA256(compressed_pubkey).
// This binds the secret key identities into the attestation document so that
// verifiers can confirm which keys the enclave holds without revealing the
// private keys themselves.
func extendPCRsWithSecretPubkeys(secrets []SecretDef) error {
	for i, s := range secrets {
		pcrIndex := uint(16) + uint(i)
		if pcrIndex > 31 {
			return fmt.Errorf("secret %q: PCR index %d exceeds 31", s.Name, pcrIndex)
		}

		secretHex := os.Getenv(s.EnvVar)
		if secretHex == "" {
			return fmt.Errorf("secret %q env var %s is empty", s.Name, s.EnvVar)
		}

		secretBytes, err := hex.DecodeString(secretHex)
		if err != nil {
			return fmt.Errorf("decode secret %q hex: %w", s.Name, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(secretBytes)
		if privKey == nil {
			return fmt.Errorf("secret %q: invalid secp256k1 private key", s.Name)
		}

		pubkeyBytes := privKey.PubKey().SerializeCompressed()
		hash := sha256.Sum256(pubkeyBytes)

		if err := extendPCR(pcrIndex, hash[:]); err != nil {
			return fmt.Errorf("extend PCR%d with secret %q pubkey: %w", pcrIndex, s.Name, err)
		}

	}
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

	nitridingPort := os.Getenv("ENCLAVE_NITRIDING_INT_PORT")
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

func (r *responseRecorder) Header() http.Header  { return r.headers }
func (r *responseRecorder) WriteHeader(code int) { r.status = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// Ensure responseRecorder satisfies io.ReaderFrom for efficient proxying.
func (r *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(r.body, src)
}
