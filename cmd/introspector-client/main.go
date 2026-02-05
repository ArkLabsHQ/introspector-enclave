package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"time"

	"github.com/hf/nitrite"
)

type attestationResponse struct {
	Document string `json:"document"`
}

type submitTxRequest struct {
	ArkTx         string   `json:"ark_tx"`
	CheckpointTxs []string `json:"checkpoint_txs"`
}

type nitroBuildOutput struct {
	Measurements struct {
		PCR0 string `json:"PCR0"`
		PCR1 string `json:"PCR1"`
		PCR2 string `json:"PCR2"`
	} `json:"Measurements"`
}

func main() {
	baseURL := flag.String("base-url", "", "Base URL for the enclave (e.g., https://host)")
	arkTx := flag.String("ark-tx", "", "Ark transaction payload")
	checkpointTx := flag.String("checkpoint-tx", "", "Checkpoint transaction payload")
	insecure := flag.Bool("insecure", false, "Skip TLS verification")
	expectedPCR0 := flag.String("expected-pcr0", "", "Expected PCR0 hex (optional)")
	verifyBuild := flag.Bool("verify-build", false, "Build enclave from source with Nix and derive expected PCR0")
	repoPath := flag.String("repo-path", ".", "Path to source repository (used with --verify-build)")
	buildVersion := flag.String("build-version", "", "VERSION for nix build (used with --verify-build)")
	buildRegion := flag.String("build-region", "", "AWS_REGION for nix build (used with --verify-build)")
	instanceID := flag.String("instance-id", "", "EC2 instance ID for remote EIF build via SSM (used with --verify-build)")
	s3Bucket := flag.String("s3-bucket", "", "S3 bucket for uploading the image to the instance (used with --verify-build)")
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
			if *instanceID == "" || *s3Bucket == "" {
				fmt.Fprintln(os.Stderr, "--instance-id and --s3-bucket are required for --verify-build")
				os.Exit(1)
			}
			derived, err := buildAndExtractPCR0(*repoPath, *buildVersion, *buildRegion, *instanceID, *s3Bucket)
			if err != nil {
				fmt.Fprintf(os.Stderr, "build verification failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("derived PCR0 from build: %s\n", derived)
			pcr0 = derived
		}
	}

	client := httpClient(*insecure)

	if err := verifyAttestation(client, *baseURL, pcr0); err != nil {
		fmt.Fprintf(os.Stderr, "pre-request attestation failed: %v\n", err)
		os.Exit(1)
	}

	if err := submitTx(client, *baseURL, *arkTx, *checkpointTx); err != nil {
		fmt.Fprintf(os.Stderr, "submit tx failed: %v\n", err)
		os.Exit(1)
	}
}

func buildAndExtractPCR0(repoPath, version, region, instanceID, s3Bucket string) (string, error) {
	for _, cmd := range []string{"nix", "aws"} {
		if _, err := exec.LookPath(cmd); err != nil {
			return "", fmt.Errorf("%s not found in PATH: %w", cmd, err)
		}
	}

	ts := time.Now().UnixNano()
	imageTar := fmt.Sprintf("/tmp/enclave-verify-%d.tar.gz", ts)
	s3Key := fmt.Sprintf("introspector-verify/%d.tar.gz", ts)
	s3URI := fmt.Sprintf("s3://%s/%s", s3Bucket, s3Key)

	// Build the deterministic Docker image with Nix.
	fmt.Println("[verify] building enclave image with nix...")
	nixCmd := exec.Command("nix", "build", "--impure", ".#enclave-image", "-o", imageTar)
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
	defer os.Remove(imageTar)

	// Upload the image tarball to S3 so the instance can fetch it.
	fmt.Printf("[verify] uploading image to %s ...\n", s3URI)
	uploadCmd := exec.Command("aws", "s3", "cp", imageTar, s3URI, "--region", region)
	uploadCmd.Stderr = os.Stderr
	if err := uploadCmd.Run(); err != nil {
		return "", fmt.Errorf("s3 upload failed: %w", err)
	}
	defer func() {
		fmt.Println("[verify] cleaning up S3 object...")
		exec.Command("aws", "s3", "rm", s3URI, "--region", region).Run() //nolint:errcheck
	}()

	// Build EIF on the remote instance via SSM.
	// Download the image from S3, load into Docker, run nitro-cli build-enclave.
	fmt.Println("[verify] building EIF on remote instance via SSM...")

	script := strings.Join([]string{
		"set -e",
		"export NITRO_CLI_ARTIFACTS=/usr/share/nitro_enclaves/blobs",
		fmt.Sprintf("aws s3 cp %s /tmp/verify-image.tar.gz --region %s >/dev/null", s3URI, region),
		`docker load -i /tmp/verify-image.tar.gz >/dev/null`,
		`if ! nitro-cli build-enclave --docker-uri introspector-enclave:nix --output-file /tmp/verify.eif > /tmp/verify-build.json 2>/tmp/verify-build.log; then echo "nitro-cli build-enclave failed:" >&2; cat /tmp/verify-build.log >&2; exit 1; fi`,
		`jq -r '.Measurements.PCR0' /tmp/verify-build.json`,
		`rm -f /tmp/verify-image.tar.gz /tmp/verify.eif /tmp/verify-build.json /tmp/verify-build.log`,
		`docker rmi introspector-enclave:nix >/dev/null 2>&1 || true`,
	}, "; ")

	params := fmt.Sprintf(`{"commands":[%s]}`, strconv.Quote(script))

	sendCmd := exec.Command("aws", "ssm", "send-command",
		"--region", region,
		"--document-name", "AWS-RunShellScript",
		"--instance-ids", instanceID,
		"--parameters", params,
		"--timeout-seconds", "600",
		"--output", "json",
	)
	sendCmd.Stderr = os.Stderr
	sendOut, err := sendCmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssm send-command failed: %w", err)
	}

	var cmdResp struct {
		Command struct {
			CommandId string `json:"CommandId"`
		} `json:"Command"`
	}
	if err := json.Unmarshal(sendOut, &cmdResp); err != nil {
		return "", fmt.Errorf("parse ssm send-command response: %w", err)
	}
	commandID := cmdResp.Command.CommandId
	fmt.Printf("[verify] SSM command ID: %s\n", commandID)

	// Poll for command completion.
	var stdout, stderr string
	for i := 0; i < 120; i++ {
		time.Sleep(5 * time.Second)

		getCmd := exec.Command("aws", "ssm", "get-command-invocation",
			"--region", region,
			"--instance-id", instanceID,
			"--command-id", commandID,
			"--output", "json",
		)
		getOut, err := getCmd.Output()
		if err != nil {
			// InvocationDoesNotExist means the command hasn't registered yet.
			continue
		}

		var inv struct {
			Status                string `json:"Status"`
			StandardOutputContent string `json:"StandardOutputContent"`
			StandardErrorContent  string `json:"StandardErrorContent"`
		}
		if err := json.Unmarshal(getOut, &inv); err != nil {
			continue
		}

		switch inv.Status {
		case "Success":
			stdout = inv.StandardOutputContent
			stderr = inv.StandardErrorContent
			goto done
		case "Failed", "TimedOut", "Cancelled":
			return "", fmt.Errorf("remote command %s: %s", inv.Status, inv.StandardErrorContent)
		case "Pending", "InProgress", "Delayed":
			if i%6 == 0 {
				fmt.Printf("[verify] waiting for remote EIF build (status: %s)...\n", inv.Status)
			}
		}
	}
	return "", fmt.Errorf("timed out waiting for remote EIF build")

done:
	if stderr != "" {
		fmt.Fprintf(os.Stderr, "[verify] remote stderr: %s\n", strings.TrimSpace(stderr))
	}

	// The last line of stdout is the PCR0 hex string.
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty output from remote EIF build")
	}
	pcr0 := strings.TrimSpace(lines[len(lines)-1])
	if len(pcr0) != 96 {
		return "", fmt.Errorf("unexpected PCR0 length %d (expected 96 hex chars): %q\nfull output: %s", len(pcr0), pcr0, stdout)
	}

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

func verifyAttestation(client *http.Client, baseURL, expectedPCR0 string) error {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	url := strings.TrimRight(baseURL, "/") + "/enclave/attestation?nonce=" + nonceHex
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("attestation status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
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
		return fmt.Errorf("decode attestation document: %w", err)
	}

	result, err := nitrite.Verify(docBytes, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if err != nil {
		if result != nil && result.SignatureOK {
			fmt.Fprintf(os.Stderr, "warning: attestation signature OK but validation error: %v\n", err)
		} else {
			return err
		}
	}

	if result == nil || result.Document == nil {
		return fmt.Errorf("attestation missing document")
	}

	expectedNonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	if len(result.Document.Nonce) == 0 {
		return fmt.Errorf("attestation missing nonce")
	}
	if !bytes.Equal(result.Document.Nonce, expectedNonce) {
		return fmt.Errorf("attestation nonce mismatch")
	}

	if expectedPCR0 != "" {
		pcr0, ok := result.Document.PCRs[0]
		if !ok {
			return fmt.Errorf("attestation missing PCR0")
		}
		if !strings.EqualFold(hex.EncodeToString(pcr0), expectedPCR0) {
			return fmt.Errorf("PCR0 mismatch")
		}
	}

	fmt.Println("attestation verified")
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
