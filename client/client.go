// Package client provides a verified HTTP client for AWS Nitro Enclaves.
//
// Every request first verifies the enclave's attestation document (PCR0,
// optional secret PCRs, attestation key binding) and then verifies the
// Schnorr response signature. This ensures the enclave is running the
// expected code and that responses haven't been tampered with.
//
// Usage:
//
//	c, err := client.New("https://1.2.3.4", client.Options{
//	    ExpectedPCR0: "79f5fb125b00ad80...",
//	    ExpectedPCRs: []string{"sha256-of-secret-pubkey"},
//	})
//	resp, err := c.Get(ctx, "/my-endpoint")
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Options configures the enclave client.
type Options struct {
	// ExpectedPCR0 is the hex-encoded PCR0 value to verify against.
	// This is the enclave's build measurement — it must match the
	// PCR0 from 'enclave build'.
	ExpectedPCR0 string

	// ExpectedPCRs is a list of hex-encoded SHA256 hashes of secret
	// compressed public keys, in the same order as secrets are defined
	// in enclave.yaml. Index 0 maps to PCR16, index 1 to PCR17, etc.
	// The enclave extends these PCRs with SHA256(compressed_pubkey)
	// at boot time.
	ExpectedPCRs []string

	// CacheTTL controls how long a verified attestation is cached.
	// Set to 0 to verify on every request. Default: 60s.
	CacheTTL time.Duration

	// InsecureTLS skips TLS certificate verification. Default: true.
	// Nitriding uses self-signed certificates, so this is typically needed.
	InsecureTLS *bool
}

// Response wraps an HTTP response with attestation verification metadata.
type Response struct {
	StatusCode        int
	Header            http.Header
	Body              []byte
	SignatureVerified bool
}

// AttestationResult contains the verified attestation state.
type AttestationResult struct {
	PCR0           string
	PCRs           map[uint]string
	AttestationKey string // hex-encoded compressed secp256k1 pubkey
	Verified       bool
	VerifiedAt     time.Time
}

// Client is a verified HTTP client for an AWS Nitro Enclave.
type Client struct {
	baseURL    string
	httpClient *http.Client
	opts       Options

	mu          sync.RWMutex
	cachedState *AttestationResult
}

// New creates a new enclave client that verifies attestation before
// making requests. The baseURL should be the HTTPS endpoint of the
// enclave (e.g. "https://1.2.3.4").
func New(baseURL string, opts Options) (*Client, error) {
	if opts.ExpectedPCR0 == "" {
		return nil, fmt.Errorf("ExpectedPCR0 is required")
	}

	if opts.CacheTTL == 0 {
		opts.CacheTTL = 60 * time.Second
	}

	insecure := true
	if opts.InsecureTLS != nil {
		insecure = *opts.InsecureTLS
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		opts: opts,
	}, nil
}

// Get makes a verified GET request to the enclave.
func (c *Client) Get(ctx context.Context, path string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// Post makes a verified POST request to the enclave.
func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(ctx, req)
}

// Do makes a verified HTTP request to the enclave. It:
//  1. Verifies attestation (PCR0, optional PCRs, key binding)
//  2. Executes the request
//  3. Verifies the response signature (Schnorr)
func (c *Client) Do(ctx context.Context, req *http.Request) (*Response, error) {
	// Step 1: Verify attestation (uses cache if valid).
	attestResult, err := c.ensureVerified(ctx)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Step 2: Execute the actual request.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Step 3: Verify response signature.
	sigVerified := false
	if attestResult.AttestationKey != "" {
		sigHex := resp.Header.Get("X-Attestation-Signature")
		if sigHex != "" {
			if err := verifySchnorrSignature(body, sigHex, attestResult.AttestationKey); err == nil {
				sigVerified = true
			}
		}
	}

	return &Response{
		StatusCode:        resp.StatusCode,
		Header:            resp.Header,
		Body:              body,
		SignatureVerified: sigVerified,
	}, nil
}

// VerifyAttestation manually triggers attestation verification,
// bypassing the cache. Returns the attestation result.
func (c *Client) VerifyAttestation(ctx context.Context) (*AttestationResult, error) {
	return c.verify(ctx)
}

// ensureVerified returns cached attestation or re-verifies.
func (c *Client) ensureVerified(ctx context.Context) (*AttestationResult, error) {
	c.mu.RLock()
	cached := c.cachedState
	c.mu.RUnlock()

	if cached != nil && cached.Verified && time.Since(cached.VerifiedAt) < c.opts.CacheTTL {
		return cached, nil
	}

	return c.verify(ctx)
}

// verify performs full attestation verification and caches the result.
func (c *Client) verify(ctx context.Context) (*AttestationResult, error) {
	// 1. Fetch and verify attestation document.
	nitResult, err := fetchAndVerifyAttestation(ctx, c.httpClient, c.baseURL, c.opts.ExpectedPCR0)
	if err != nil {
		return nil, err
	}

	// 2. Verify additional PCRs (secret pubkey hashes).
	pcrs := make(map[uint]string)
	for idx, pcrBytes := range nitResult.Document.PCRs {
		if len(pcrBytes) > 0 {
			pcrs[idx] = fmt.Sprintf("%x", pcrBytes)
		}
	}

	for i, expectedHash := range c.opts.ExpectedPCRs {
		pcrIndex := uint(16) + uint(i)
		actual, ok := pcrs[pcrIndex]
		if !ok {
			return nil, fmt.Errorf("PCR%d not found in attestation document", pcrIndex)
		}
		if !strings.EqualFold(actual, expectedHash) {
			return nil, fmt.Errorf("PCR%d mismatch: expected %s, got %s", pcrIndex, expectedHash, actual)
		}
	}

	// 3. Verify attestation key binding.
	attestKey, err := verifyKeyBinding(ctx, c.httpClient, c.baseURL, nitResult)
	if err != nil {
		return nil, fmt.Errorf("key binding verification: %w", err)
	}

	result := &AttestationResult{
		PCR0:           c.opts.ExpectedPCR0,
		PCRs:           pcrs,
		AttestationKey: attestKey,
		Verified:       true,
		VerifiedAt:     time.Now(),
	}

	c.mu.Lock()
	c.cachedState = result
	c.mu.Unlock()

	return result, nil
}

func (c *Client) url(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path
}
