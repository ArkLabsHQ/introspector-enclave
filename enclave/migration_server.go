package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	ssmclient "github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
)

// migrationServer handles migration requests from a V2 enclave over vsock.
type migrationServer struct {
	secretKey    []byte // raw 32-byte signing key
	done         chan struct{}
	awsCfg       aws.Config
	migrationCtx context.Context
}

type initiateRequest struct {
	AttestationDoc string `json:"attestation_doc"`
	V2KMSKeyID     string `json:"v2_kms_key_id"`

	// MaintainerSig is a hex-encoded Schnorr signature over
	// SHA256(target_pcr0_hex || activation_time_decimal) by the maintainer key.
	// Required when MaintainerPubkey is compiled into the binary.
	MaintainerSig string `json:"maintainer_sig,omitempty"`

	// ActivationTime is the Unix timestamp (seconds) for the earliest migration
	// completion, as signed by the maintainer. Must be >= now + MigrationCooldown.
	ActivationTime int64 `json:"activation_time,omitempty"`
}

type initiateResponse struct {
	CooldownSeconds int64 `json:"cooldown_seconds"`
	InitiatedAt     int64 `json:"initiated_at"`
}

type completeResponse struct {
	Completed bool `json:"completed"`
}

type statusResponse struct {
	State *MigrationState `json:"state"`
}

// startMigrationServer starts a vsock HTTP server for migration.
// It signals on the done channel when migration completes (V1 should shut down).
func startMigrationServer(secretKey []byte, done chan struct{}) {
	awsCfg, err := loadAWSConfigWithIMDS(context.Background())
	if err != nil {
		log.Errorf("migration server: failed to load AWS config: %s", err)
		return
	}

	srv := &migrationServer{
		secretKey:    secretKey,
		done:         done,
		awsCfg:       awsCfg,
		migrationCtx: context.Background(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/initiate-migration", srv.handleInitiate)
	mux.HandleFunc("POST /internal/complete-migration", srv.handleComplete)
	mux.HandleFunc("GET /internal/migration-status", srv.handleStatus)

	listener, err := vsock.Listen(MigrationVsockPort, nil)
	if err != nil {
		log.Errorf("migration server: vsock listen on port %d: %s", MigrationVsockPort, err)
		return
	}

	log.Infof("migration server listening on vsock port %d", MigrationVsockPort)
	httpServer := &http.Server{Handler: mux}
	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Errorf("migration server: %s", err)
	}
}

func (s *migrationServer) handleInitiate(w http.ResponseWriter, r *http.Request) {
	var req initiateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.AttestationDoc == "" || req.V2KMSKeyID == "" {
		http.Error(w, "attestation_doc and v2_kms_key_id are required", http.StatusBadRequest)
		return
	}

	// Decode and verify the V2 attestation document.
	docBytes, err := base64.StdEncoding.DecodeString(req.AttestationDoc)
	if err != nil {
		http.Error(w, "invalid base64 attestation_doc", http.StatusBadRequest)
		return
	}

	result, err := nitrite.Verify(docBytes, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})
	if err != nil {
		// Accept if signature is OK but cert chain has issues (e.g., debug mode).
		if result == nil || !result.SignatureOK {
			http.Error(w, fmt.Sprintf("attestation verification failed: %v", err), http.StatusForbidden)
			return
		}
		log.Warnf("migration: V2 attestation signature OK but validation warning: %v", err)
	}

	if result == nil || result.Document == nil {
		http.Error(w, "attestation missing document", http.StatusForbidden)
		return
	}

	// Extract V2 PCR0.
	pcr0, ok := result.Document.PCRs[0]
	if !ok || len(pcr0) == 0 {
		http.Error(w, "attestation missing PCR0", http.StatusForbidden)
		return
	}
	targetPCR0 := hex.EncodeToString(pcr0)

	// Verify maintainer authorization signature if MaintainerPubkey is configured.
	if err := verifyMaintainerAuthorization(targetPCR0, req.ActivationTime, req.MaintainerSig); err != nil {
		http.Error(w, fmt.Sprintf("maintainer authorization failed: %v", err), http.StatusForbidden)
		return
	}

	// Check no migration already pending.
	ssmClient := ssmclient.NewFromConfig(s.awsCfg)
	existing, err := loadMigrationState(s.migrationCtx, ssmClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("load migration state: %v", err), http.StatusInternalServerError)
		return
	}
	if existing != nil && existing.CompletedAt == 0 {
		http.Error(w, "migration already pending", http.StatusConflict)
		return
	}

	// Get V1's own PCR0 for the attestation chain.
	sourcePCR0 := s.getOwnPCR0()

	// Write migration state to SSM, including attestation chain metadata.
	now := time.Now().Unix()
	state := &MigrationState{
		TargetPCR0:   targetPCR0,
		V2KMSKeyID:   req.V2KMSKeyID,
		InitiatedAt:  now,
		SourcePCR0:   sourcePCR0,
		PreviousPCR0: PreviousPCR0,
	}
	if req.ActivationTime > 0 {
		state.ActivationTime = req.ActivationTime
	}
	if err := storeMigrationState(s.migrationCtx, ssmClient, state); err != nil {
		http.Error(w, fmt.Sprintf("store migration state: %v", err), http.StatusInternalServerError)
		return
	}

	log.Infof("migration initiated: V2 PCR0=%s, source=%s, previous=%s, cooldown=%s",
		targetPCR0[:16]+"...", sourcePCR0[:16]+"...", PreviousPCR0[:16]+"...", MigrationCooldown)

	resp := initiateResponse{
		CooldownSeconds: int64(MigrationCooldown.Seconds()),
		InitiatedAt:     now,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// verifyMaintainerAuthorization checks the Schnorr signature from the maintainer
// key over the migration authorization message. If MaintainerPubkey is not set
// (empty), authorization is skipped with a warning.
//
// The signed message is: SHA256(target_pcr0_hex || ":" || activation_time_decimal)
// where target_pcr0_hex is lowercase hex and activation_time_decimal is the
// Unix timestamp as a decimal string.
func verifyMaintainerAuthorization(targetPCR0 string, activationTime int64, signatureHex string) error {
	if MaintainerPubkey == "" {
		log.Warn("migration: MaintainerPubkey not configured, skipping authorization check (UNSAFE)")
		return nil
	}

	if signatureHex == "" {
		return fmt.Errorf("maintainer_sig is required when MaintainerPubkey is configured")
	}
	if activationTime == 0 {
		return fmt.Errorf("activation_time is required when MaintainerPubkey is configured")
	}

	// Activation time must be at least MigrationCooldown from now.
	earliest := time.Now().Add(MigrationCooldown)
	if time.Unix(activationTime, 0).Before(earliest) {
		return fmt.Errorf("activation_time %d is before minimum (%d = now + %s)",
			activationTime, earliest.Unix(), MigrationCooldown)
	}

	// Parse the maintainer public key.
	pubkeyBytes, err := hex.DecodeString(MaintainerPubkey)
	if err != nil {
		return fmt.Errorf("invalid MaintainerPubkey hex: %w", err)
	}
	pubkey, err := schnorr.ParsePubKey(pubkeyBytes)
	if err != nil {
		return fmt.Errorf("invalid MaintainerPubkey: %w", err)
	}

	// Build the message: SHA256(target_pcr0_hex + ":" + activation_time_decimal)
	msg := fmt.Sprintf("%s:%d", targetPCR0, activationTime)
	msgHash := sha256.Sum256([]byte(msg))

	// Parse and verify the signature.
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid maintainer_sig hex: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid maintainer_sig: %w", err)
	}

	if !sig.Verify(msgHash[:], pubkey) {
		return fmt.Errorf("maintainer signature verification failed")
	}

	log.Infof("migration: maintainer authorization verified (pubkey=%s..., activation=%s)",
		MaintainerPubkey[:16], time.Unix(activationTime, 0).Format(time.RFC3339))
	return nil
}

// getOwnPCR0 retrieves this enclave's PCR0 from a fresh attestation document.
func (s *migrationServer) getOwnPCR0() string {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Warnf("migration: could not get own PCR0: %v", err)
		return "unknown"
	}
	defer session.Close()

	doc, _, err := buildAttestationDocument(session)
	if err != nil {
		log.Warnf("migration: could not build attestation for own PCR0: %v", err)
		return "unknown"
	}

	pcr0, err := extractPCR0FromAttestation(doc)
	if err != nil {
		log.Warnf("migration: could not extract own PCR0: %v", err)
		return "unknown"
	}
	return pcr0
}

func (s *migrationServer) handleComplete(w http.ResponseWriter, r *http.Request) {
	ssmClient := ssmclient.NewFromConfig(s.awsCfg)

	// Load and validate migration state.
	state, err := loadMigrationState(s.migrationCtx, ssmClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("load migration state: %v", err), http.StatusInternalServerError)
		return
	}
	if state == nil {
		http.Error(w, "no migration pending", http.StatusBadRequest)
		return
	}
	if state.CompletedAt != 0 {
		http.Error(w, "migration already completed", http.StatusConflict)
		return
	}
	if !isCooldownExpired(state) {
		remaining := time.Until(time.Unix(state.InitiatedAt, 0).Add(MigrationCooldown))
		http.Error(w, fmt.Sprintf("cooldown not expired, %s remaining", remaining.Round(time.Second)), http.StatusTooEarly)
		return
	}

	// Re-encrypt the signing key under V2's KMS key.
	kmsClient := kms.NewFromConfig(s.awsCfg)
	ciphertextB64, err := encryptWithKMS(s.migrationCtx, kmsClient, state.V2KMSKeyID, s.secretKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("re-encrypt for V2: %v", err), http.StatusInternalServerError)
		return
	}

	// Store V2 ciphertext in SSM.
	if err := storeV2Ciphertext(s.migrationCtx, ssmClient, ciphertextB64); err != nil {
		http.Error(w, fmt.Sprintf("store V2 ciphertext: %v", err), http.StatusInternalServerError)
		return
	}

	// Mark migration as completed.
	state.CompletedAt = time.Now().Unix()
	if err := storeMigrationState(s.migrationCtx, ssmClient, state); err != nil {
		http.Error(w, fmt.Sprintf("update migration state: %v", err), http.StatusInternalServerError)
		return
	}

	log.Infof("migration completed: V2 PCR0=%s, V2 KMS key=%s", state.TargetPCR0[:16]+"...", state.V2KMSKeyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(completeResponse{Completed: true})

	// Signal main process to shut down.
	close(s.done)
}

func (s *migrationServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ssmClient := ssmclient.NewFromConfig(s.awsCfg)
	state, err := loadMigrationState(s.migrationCtx, ssmClient)
	if err != nil {
		http.Error(w, fmt.Sprintf("load migration state: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResponse{State: state})
}

// connectToV1Migration connects to V1's migration server over vsock and performs
// the V2 side of the migration protocol.
func connectToV1Migration(ctx context.Context, v1CID uint32) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}
	ssmClient := ssmclient.NewFromConfig(awsCfg)

	// Check if V1 already completed migration for us.
	v2Ciphertext, err := loadV2Ciphertext(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("check V2 ciphertext: %w", err)
	}
	if v2Ciphertext != "" {
		log.Info("V2: found existing V2 ciphertext, migration already completed by V1")
		return loadV2Key(ctx, awsCfg, v2Ciphertext)
	}

	// Build V2 attestation document.
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open NSM session: %w", err)
	}
	defer session.Close()

	attestationDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		return fmt.Errorf("build attestation: %w", err)
	}
	attestationB64 := base64.StdEncoding.EncodeToString(attestationDoc)

	// Get V2 KMS key ID from SSM.
	v2KMSKeyID, err := getV2KMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get V2 KMS key ID: %w", err)
	}

	// Connect to V1 via vsock.
	conn, err := vsock.Dial(v1CID, MigrationVsockPort, nil)
	if err != nil {
		return fmt.Errorf("vsock dial CID %d port %d: %w", v1CID, MigrationVsockPort, err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	// Step 1: Initiate migration.
	state, err := loadMigrationState(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("load migration state: %w", err)
	}

	if state == nil || state.InitiatedAt == 0 {
		// Load maintainer authorization from SSM (set by deploy_v2.sh).
		maintainerSig, activationTime, _ := loadMaintainerAuth(ctx, ssmClient)

		log.Info("V2: initiating migration with V1")
		if err := v2InitiateMigration(client, attestationB64, v2KMSKeyID, maintainerSig, activationTime); err != nil {
			return fmt.Errorf("initiate migration: %w", err)
		}
	} else {
		log.Infof("V2: migration already initiated at %s", time.Unix(state.InitiatedAt, 0))
	}

	// Step 2: Wait for cooldown.
	log.Infof("V2: waiting for %s cooldown", MigrationCooldown)
	for {
		state, err = loadMigrationState(ctx, ssmClient)
		if err != nil {
			return fmt.Errorf("poll migration state: %w", err)
		}
		if state != nil && state.CompletedAt != 0 {
			log.Info("V2: migration completed by V1")
			break
		}
		if state != nil && isCooldownExpired(state) {
			log.Info("V2: cooldown expired, requesting completion")
			// Reconnect for completion request.
			conn2, err := vsock.Dial(v1CID, MigrationVsockPort, nil)
			if err != nil {
				return fmt.Errorf("vsock dial for completion: %w", err)
			}
			client2 := &http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return conn2, nil
					},
				},
			}
			if err := v2CompleteMigration(client2); err != nil {
				return fmt.Errorf("complete migration: %w", err)
			}
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(30 * time.Second):
		}
	}

	// Step 3: Load V2 ciphertext and decrypt.
	v2Ciphertext, err = loadV2Ciphertext(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("load V2 ciphertext after completion: %w", err)
	}
	if v2Ciphertext == "" {
		return fmt.Errorf("V2 ciphertext empty after migration completion")
	}

	return loadV2Key(ctx, awsCfg, v2Ciphertext)
}

func v2InitiateMigration(client *http.Client, attestationB64, v2KMSKeyID, maintainerSig string, activationTime int64) error {
	reqBody := initiateRequest{
		AttestationDoc: attestationB64,
		V2KMSKeyID:     v2KMSKeyID,
		MaintainerSig:  maintainerSig,
		ActivationTime: activationTime,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := client.Post("http://vsock/internal/initiate-migration", "application/json",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("POST initiate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("initiate failed: status %d", resp.StatusCode)
	}

	var initResp initiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	log.Infof("V2: migration initiated, cooldown=%ds", initResp.CooldownSeconds)
	return nil
}

// loadMaintainerAuth loads the maintainer authorization signature and activation
// time from SSM parameters. These are set by deploy_v2.sh before starting V2.
func loadMaintainerAuth(ctx context.Context, ssmClient *ssmclient.Client) (string, int64, error) {
	deployment := getDeploymentName()

	sigParam := fmt.Sprintf("/%s/NitroIntrospector/MaintainerSig", deployment)
	sigOut, err := ssmClient.GetParameter(ctx, &ssmclient.GetParameterInput{
		Name:           aws.String(sigParam),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", 0, fmt.Errorf("load maintainer sig: %w", err)
	}

	sig := ""
	if sigOut.Parameter != nil && sigOut.Parameter.Value != nil {
		sig = *sigOut.Parameter.Value
		if sig == "UNSET" {
			sig = ""
		}
	}

	timeParam := fmt.Sprintf("/%s/NitroIntrospector/MigrationActivationTime", deployment)
	timeOut, err := ssmClient.GetParameter(ctx, &ssmclient.GetParameterInput{
		Name:           aws.String(timeParam),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return sig, 0, fmt.Errorf("load activation time: %w", err)
	}

	var activationTime int64
	if timeOut.Parameter != nil && timeOut.Parameter.Value != nil {
		val := *timeOut.Parameter.Value
		if val != "" && val != "UNSET" {
			fmt.Sscanf(val, "%d", &activationTime)
		}
	}

	return sig, activationTime, nil
}

func v2CompleteMigration(client *http.Client) error {
	resp, err := client.Post("http://vsock/internal/complete-migration", "application/json", nil)
	if err != nil {
		return fmt.Errorf("POST complete: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("complete failed: status %d", resp.StatusCode)
	}
	return nil
}

func loadV2Key(ctx context.Context, awsCfg aws.Config, ciphertextB64 string) error {
	kmsClient := kms.NewFromConfig(awsCfg)
	ssmClient := ssmclient.NewFromConfig(awsCfg)

	// Get V2 KMS key ID.
	v2KeyID, err := getV2KMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get V2 KMS key ID: %w", err)
	}

	// Decrypt using V2 KMS key with attestation.
	return decryptExistingKey(ctx, kmsClient, v2KeyID, ciphertextB64)
}

func getV2KMSKeyID(ctx context.Context, ssmClient *ssmclient.Client) (string, error) {
	deployment := getDeploymentName()
	paramName := fmt.Sprintf("/%s/NitroIntrospector/V2KMSKeyID", deployment)
	out, err := ssmClient.GetParameter(ctx, &ssmclient.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("V2 KMS key ID not found in SSM: %s", paramName)
	}
	return *out.Parameter.Value, nil
}
