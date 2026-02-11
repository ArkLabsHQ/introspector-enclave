package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nitrite"
)

type attestationResponse struct {
	Document string `json:"document"`
}

type getInfoResponse struct {
	SignerPubkey string `json:"signerPubkey"`
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
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	expectedPCR0 := flag.String("expected-pcr0", "", "Expected PCR0 hex (optional)")
	verifyBuild := flag.Bool("verify-build", false, "Build enclave EIF locally with Nix and derive expected PCR0")
	repoPath := flag.String("repo-path", ".", "Path to source repository (used with --verify-build)")
	buildVersion := flag.String("build-version", "", "VERSION for nix build (used with --verify-build)")
	buildRegion := flag.String("build-region", "", "AWS_REGION for nix build (used with --verify-build)")
	verifyPubkey := flag.Bool("verify-pubkey", true, "Verify that /v1/info pubkey matches attestation PCR16 hash")
	verifyAttestationKey := flag.Bool("verify-attestation-key", true, "Verify attestation key via UserData appKeyHash and test response signature")
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

	if *verifyAttestationKey {
		if err := verifyAttestationKeyBinding(client, *baseURL, attestResult); err != nil {
			fmt.Fprintf(os.Stderr, "attestation key verification failed: %v\n", err)
			os.Exit(1)
		}
	}

	// if err := submitTx(client, *baseURL, *arkTx, *checkpointTx); err != nil {
	// 	fmt.Fprintf(os.Stderr, "submit tx failed: %v\n", err)
	// 	os.Exit(1)
	// }
}

func buildAndExtractPCR0(repoPath, version, region string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not found in PATH: %w", err)
	}

	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve repo path: %w", err)
	}

	// Clean stale artifacts.
	resultPath := absRepo + "/artifacts"
	_ = os.RemoveAll(resultPath)
	_ = os.MkdirAll(resultPath, 0o755)

	// Build the EIF reproducibly via pinned NixOS Docker image.
	// Copy outputs from nix store before the container exits (the store is ephemeral).
	fmt.Println("[verify] building EIF via NixOS Docker (reproducible)...")
	nixImage := os.Getenv("NIX_IMAGE")
	if nixImage == "" {
		nixImage = "nixos/nix:2.24.9"
	}
	if version == "" {
		version = "dev"
	}
	if region == "" {
		region = "us-east-1"
	}

	dockerCmd := exec.Command("docker", "run", "--rm",
		"-v", absRepo+":/src", "-w", "/src",
		"-e", "VERSION="+version,
		"-e", "AWS_REGION="+region,
		nixImage,
		"sh", "-c",
		"git config --global --add safe.directory /src && nix build --impure --extra-experimental-features 'nix-command flakes' ./builder#eif && cp result/image.eif /src/artifacts/image.eif && cp result/pcr.json /src/artifacts/pcr.json",
	)
	dockerCmd.Stdout = os.Stdout
	dockerCmd.Stderr = os.Stderr

	if err := dockerCmd.Run(); err != nil {
		return "", fmt.Errorf("docker nix build failed: %w", err)
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
// that its hash matches PCR16 in the attestation document.
//
// The enclave extends PCR16 with SHA256(compressedPubkey) and locks it.
// PCR extension: new = SHA384(old || data), starting from 48 zero bytes.
// So: PCR16 = SHA384(zeros_48 || SHA256(pubkey))
func verifyPubkeyBinding(client *http.Client, baseURL string, attestResult *nitrite.Result) error {
	if attestResult == nil || attestResult.Document == nil {
		return fmt.Errorf("no attestation result to verify against")
	}

	pcr16, ok := attestResult.Document.PCRs[16]
	if !ok || len(pcr16) == 0 {
		return fmt.Errorf("attestation missing PCR16; enclave did not extend PCR16 with pubkey hash")
	}

	// Check that PCR16 is not all zeros (meaning the enclave never extended it)
	allZero := true
	for _, b := range pcr16 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("attestation PCR16 is all zeros; enclave did not register its signing pubkey")
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

	// Compute expected PCR16: SHA384(zeros_48 || SHA256(pubkey))
	pubkeyHash := sha256.Sum256(pubkeyBytes)
	extendData := make([]byte, 48+len(pubkeyHash))
	// First 48 bytes are zeros (initial PCR16 value)
	copy(extendData[48:], pubkeyHash[:])
	expectedPCR16 := sha512.Sum384(extendData)

	if !bytes.Equal(expectedPCR16[:], pcr16) {
		return fmt.Errorf("PCR16 mismatch: expected SHA384(zeros48 || SHA256(%s)) = %s, got %s",
			info.SignerPubkey,
			hex.EncodeToString(expectedPCR16[:]),
			hex.EncodeToString(pcr16))
	}

	fmt.Printf("pubkey binding verified via PCR16: %s attested in enclave\n", info.SignerPubkey)
	return nil
}

// verifyAttestationKeyBinding verifies the enclave's ephemeral attestation key
// by checking that the pubkey from /v1/enclave-info matches the appKeyHash in
// the attestation document's UserData, then verifying a live response signature.
//
// UserData format (nitriding): [0x12, 0x20, tlsKeyHash:32] ++ [0x12, 0x20, appKeyHash:32]
// Total 68 bytes. appKeyHash is at bytes 36:68 (after the 2nd multihash prefix).
func verifyAttestationKeyBinding(client *http.Client, baseURL string, attestResult *nitrite.Result) error {
	if attestResult == nil || attestResult.Document == nil {
		return fmt.Errorf("no attestation result to verify against")
	}

	userData := attestResult.Document.UserData
	if len(userData) < 68 {
		fmt.Println("attestation key: UserData too short for appKeyHash (enclave may not support attestation key)")
		return nil
	}

	// Extract appKeyHash from UserData at offset 36 (after 2nd multihash prefix 0x12, 0x20).
	if userData[34] != 0x12 || userData[35] != 0x20 {
		return fmt.Errorf("UserData missing multihash prefix at offset 34 (got %02x %02x)", userData[34], userData[35])
	}
	appKeyHash := userData[36:68]

	// Check if appKeyHash is all zeros (no attestation key registered).
	allZero := true
	for _, b := range appKeyHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		fmt.Println("attestation key: appKeyHash is all zeros (attestation key not registered)")
		return nil
	}

	// Fetch enclave info to get the attestation pubkey.
	info, err := fetchEnclaveInfo(client, baseURL)
	if err != nil {
		return fmt.Errorf("fetch enclave info: %w", err)
	}
	if info.AttestationPubkey == "" {
		return fmt.Errorf("enclave reports no attestation pubkey but appKeyHash is set")
	}

	attestPubkeyBytes, err := hex.DecodeString(info.AttestationPubkey)
	if err != nil {
		return fmt.Errorf("decode attestation pubkey hex: %w", err)
	}

	// Verify: SHA256(attestation_pubkey) == appKeyHash from UserData
	expectedHash := sha256.Sum256(attestPubkeyBytes)
	if !bytes.Equal(expectedHash[:], appKeyHash) {
		return fmt.Errorf("appKeyHash mismatch: expected SHA256(%s) = %s, got %s",
			info.AttestationPubkey,
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(appKeyHash))
	}

	fmt.Printf("attestation key binding verified via appKeyHash: %s\n", info.AttestationPubkey)

	// Verify a live response signature from /v1/enclave-info.
	if err := verifyResponseSignature(client, baseURL, info.AttestationPubkey); err != nil {
		return fmt.Errorf("response signature verification: %w", err)
	}

	return nil
}

// verifyResponseSignature fetches /v1/enclave-info and verifies the
// X-Attestation-Signature header against the attestation pubkey.
func verifyResponseSignature(client *http.Client, baseURL, attestPubkeyHex string) error {
	infoURL := strings.TrimRight(baseURL, "/") + "/v1/enclave-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, infoURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	sigHex := resp.Header.Get("X-Attestation-Signature")
	if sigHex == "" {
		return fmt.Errorf("response missing X-Attestation-Signature header")
	}

	// Parse the x-only pubkey for Schnorr verification.
	pubkeyBytes, err := hex.DecodeString(attestPubkeyHex)
	if err != nil {
		return fmt.Errorf("decode pubkey: %w", err)
	}
	// The attestation pubkey is compressed (33 bytes). Extract x-only (32 bytes)
	// by dropping the prefix byte.
	if len(pubkeyBytes) == 33 {
		pubkeyBytes = pubkeyBytes[1:]
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("parse attestation pubkey: %w", err)
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature hex: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	msgHash := sha256.Sum256(body)
	if !sig.Verify(msgHash[:], pubkey) {
		return fmt.Errorf("signature verification failed")
	}

	fmt.Println("response signature verified (X-Attestation-Signature valid)")
	return nil
}

type enclaveInfoResponse struct {
	Version           string `json:"version"`
	PreviousPCR0      string `json:"previous_pcr0"`
	AttestationPubkey string `json:"attestation_pubkey,omitempty"`
}

func fetchEnclaveInfo(client *http.Client, baseURL string) (*enclaveInfoResponse, error) {
	infoURL := strings.TrimRight(baseURL, "/") + "/v1/enclave-info"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, infoURL, nil)
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
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var info enclaveInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode enclave info: %w", err)
	}
	return &info, nil
}

// func submitTx(client *http.Client, baseURL, arkTx, checkpointTx string) error {
// 	if arkTx == "" {
// 		arkTx = "demo-ark-tx"
// 	}
// 	if checkpointTx == "" {
// 		checkpointTx = "demo-checkpoint-tx"
// 	}

// 	body, err := json.Marshal(submitTxRequest{
// 		ArkTx:         arkTx,
// 		CheckpointTxs: []string{checkpointTx},
// 	})
// 	if err != nil {
// 		return err
// 	}

// 	url := strings.TrimRight(baseURL, "/") + "/v1/tx"
// 	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
// 	if err != nil {
// 		return err
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		payload, _ := io.ReadAll(resp.Body)
// 		return fmt.Errorf("tx status %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
// 	}

// 	respBody, _ := io.ReadAll(resp.Body)
// 	fmt.Printf("tx response: %s\n", strings.TrimSpace(string(respBody)))
// 	return nil
// }
