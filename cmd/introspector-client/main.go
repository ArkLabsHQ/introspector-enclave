package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hf/nitrite"
)

type attestationResponse struct {
	Document string `json:"document"`
}

type getInfoResponse struct {
	SignerPubkey string `json:"signer_pubkey"`
	Version      string `json:"version"`
}

type submitTxRequest struct {
	ArkTx         string   `json:"ark_tx"`
	CheckpointTxs []string `json:"checkpoint_txs"`
}

// nitroBuildOutput matches the pcr.json format from monzo/aws-nitro-util.
type nitroBuildOutput struct {
	PCR0 string `json:"PCR0"`
	PCR1 string `json:"PCR1"`
	PCR2 string `json:"PCR2"`
}

func main() {
	baseURL := flag.String("base-url", "", "Base URL for the enclave (e.g., https://host)")
	arkTx := flag.String("ark-tx", "", "Ark transaction payload")
	checkpointTx := flag.String("checkpoint-tx", "", "Checkpoint transaction payload")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	expectedPCR0 := flag.String("expected-pcr0", "", "Expected PCR0 hex (optional)")
	verifyBuild := flag.Bool("verify-build", false, "Build enclave EIF locally with Nix and derive expected PCR0")
	repoPath := flag.String("repo-path", ".", "Path to source repository (used with --verify-build)")
	buildVersion := flag.String("build-version", "", "VERSION for nix build (used with --verify-build)")
	buildRegion := flag.String("build-region", "", "AWS_REGION for nix build (used with --verify-build)")
	verifyPubkey := flag.Bool("verify-pubkey", true, "Verify that /v1/info pubkey matches attestation UserData hash")
	flag.Parse()

	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "base-url is required")
		os.Exit(1)
	}

	pcr0 := *expectedPCR0

	if *verifyBuild {
		if pcr0 != "" {
			fmt.Fprintln(os.Stderr, "warning: --expected-pcr0 overrides --verify-build")
		} else {
			derived, err := buildAndExtractPCR0(*repoPath, *buildVersion, *buildRegion)
			if err != nil {
				fmt.Fprintf(os.Stderr, "build verification failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("derived PCR0 from build: %s\n", derived)
			pcr0 = derived
		}
	}

	client := httpClient(*insecure)

	attestResult, err := verifyAttestation(client, *baseURL, pcr0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pre-request attestation failed: %v\n", err)
		os.Exit(1)
	}

	if *verifyPubkey {
		if err := verifyPubkeyBinding(client, *baseURL, attestResult); err != nil {
			fmt.Fprintf(os.Stderr, "pubkey binding verification failed: %v\n", err)
			os.Exit(1)
		}
	}

	if err := submitTx(client, *baseURL, *arkTx, *checkpointTx); err != nil {
		fmt.Fprintf(os.Stderr, "submit tx failed: %v\n", err)
		os.Exit(1)
	}
}

func buildAndExtractPCR0(repoPath, version, region string) (string, error) {
	if _, err := exec.LookPath("nix"); err != nil {
		return "", fmt.Errorf("nix not found in PATH: %w", err)
	}

	// Remove existing result symlink to ensure we don't read stale pcr.json.
	resultPath := repoPath + "/result"
	_ = os.Remove(resultPath)

	// Build the EIF locally with Nix (uses monzo/aws-nitro-util for reproducible builds).
	// Use --rebuild to force a fresh build and avoid cached results.
	fmt.Println("[verify] building EIF locally with nix (forcing rebuild)...")
	nixCmd := exec.Command("nix", "build", "--impure", "--rebuild", ".#eif")
	nixCmd.Dir = repoPath
	nixCmd.Stderr = os.Stderr

	env := os.Environ()
	if version != "" {
		env = append(env, "VERSION="+version)
	}
	if region != "" {
		env = append(env, "AWS_REGION="+region)
	}
	nixCmd.Env = env

	if err := nixCmd.Run(); err != nil {
		return "", fmt.Errorf("nix build failed: %w", err)
	}

	// Read PCR values from the build output.
	pcrPath := resultPath + "/pcr.json"
	pcrData, err := os.ReadFile(pcrPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", pcrPath, err)
	}

	var buildOutput nitroBuildOutput
	if err := json.Unmarshal(pcrData, &buildOutput); err != nil {
		return "", fmt.Errorf("parse pcr.json: %w", err)
	}

	pcr0 := buildOutput.PCR0
	if len(pcr0) != 96 {
		return "", fmt.Errorf("unexpected PCR0 length %d (expected 96 hex chars): %q", len(pcr0), pcr0)
	}

	fmt.Printf("[verify] EIF built successfully\n")
	fmt.Printf("[verify] PCR0: %s\n", pcr0)
	fmt.Printf("[verify] PCR1: %s\n", buildOutput.PCR1)
	fmt.Printf("[verify] PCR2: %s\n", buildOutput.PCR2)

	return pcr0, nil
}

func httpClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func verifyAttestation(client *http.Client, baseURL, expectedPCR0 string) (*nitrite.Result, error) {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	url := strings.TrimRight(baseURL, "/") + "/enclave/attestation?nonce=" + nonceHex
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("attestation status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	docB64 := strings.TrimSpace(string(payload))
	if strings.HasPrefix(docB64, "{") {
		var parsed attestationResponse
		if err := json.Unmarshal(payload, &parsed); err == nil && parsed.Document != "" {
			docB64 = parsed.Document
		}
	}

	docBytes, err := base64.StdEncoding.DecodeString(docB64)
	if err != nil {
		return nil, fmt.Errorf("decode attestation document: %w", err)
	}

	result, err := nitrite.Verify(docBytes, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if err != nil {
		if result != nil && result.SignatureOK {
			fmt.Fprintf(os.Stderr, "warning: attestation signature OK but validation error: %v\n", err)
		} else {
			return nil, err
		}
	}

	if result == nil || result.Document == nil {
		return nil, fmt.Errorf("attestation missing document")
	}

	expectedNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(result.Document.Nonce) == 0 {
		return nil, fmt.Errorf("attestation missing nonce")
	}
	if !bytes.Equal(result.Document.Nonce, expectedNonce) {
		return nil, fmt.Errorf("attestation nonce mismatch")
	}

	if expectedPCR0 != "" {
		pcr0, ok := result.Document.PCRs[0]
		if !ok {
			return nil, fmt.Errorf("attestation missing PCR0")
		}
		if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
			return nil, fmt.Errorf("PCR0 mismatch")
		}
	}

	fmt.Println("attestation verified")
	return result, nil
}

// verifyPubkeyBinding fetches the signer pubkey from /v1/info and verifies
// that its SHA256 hash matches the appKeyHash embedded in the attestation
// document's UserData field (set by nitriding from POST /enclave/hash).
//
// Nitriding's UserData format (AttestationHashes.Serialize()):
//
//	[0x12, 0x20, <tlsKeyHash:32 bytes>, 0x12, 0x20, <appKeyHash:32 bytes>]
//
// Total: 68 bytes.  The appKeyHash starts at offset 34.
func verifyPubkeyBinding(client *http.Client, baseURL string, attestResult *nitrite.Result) error {
	if attestResult == nil || attestResult.Document == nil {
		return fmt.Errorf("no attestation result to verify against")
	}

	userData := attestResult.Document.UserData
	// Nitriding serializes two multihash-prefixed SHA256 hashes: 2*(2+32) = 68 bytes
	if len(userData) < 68 {
		return fmt.Errorf("attestation UserData too short (%d bytes, expected >= 68); nitriding may not have received the app key hash", len(userData))
	}

	// Extract appKeyHash: skip multihash prefix (2 bytes) + tlsKeyHash (32 bytes) + multihash prefix (2 bytes)
	appKeyHash := userData[36:68]

	// Check that appKeyHash is not all zeros (meaning the app never registered a pubkey)
	allZero := true
	for _, b := range appKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("attestation appKeyHash is all zeros; enclave did not register its signing pubkey")
	}

	// Fetch the signer pubkey from /v1/info
	url := strings.TrimRight(baseURL, "/") + "/v1/info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create info request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch /v1/info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("/v1/info status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info getInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return fmt.Errorf("decode /v1/info: %w", err)
	}

	pubkeyBytes, err := hex.DecodeString(info.SignerPubkey)
	if err != nil {
		return fmt.Errorf("decode signer pubkey hex: %w", err)
	}

	// Compute SHA256 of the compressed public key and compare
	computedHash := sha256.Sum256(pubkeyBytes)
	if !bytes.Equal(computedHash[:], appKeyHash) {
		return fmt.Errorf("pubkey binding mismatch: SHA256(%s) = %s, but attestation appKeyHash = %s",
			info.SignerPubkey,
			hex.EncodeToString(computedHash[:]),
			hex.EncodeToString(appKeyHash))
	}

	fmt.Printf("pubkey binding verified: %s attested in enclave\n", info.SignerPubkey)
	return nil
}

func submitTx(client *http.Client, baseURL, arkTx, checkpointTx string) error {
	if arkTx == "" {
		arkTx = "demo-ark-tx"
	}
	if checkpointTx == "" {
		checkpointTx = "demo-checkpoint-tx"
	}

	body, err := json.Marshal(submitTxRequest{
		ArkTx:         arkTx,
		CheckpointTxs: []string{checkpointTx},
	})
	if err != nil {
		return err
	}

	url := strings.TrimRight(baseURL, "/") + "/v1/tx"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tx status %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Printf("tx response: %s\n", strings.TrimSpace(string(respBody)))
	return nil
}
