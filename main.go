package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ArkLabsHQ/introspector/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	log "github.com/sirupsen/logrus"
)

var Version = "dev"

type getInfoResponse struct {
	SignerPubkey string `json:"signer_pubkey"`
	Version      string `json:"version"`
}

type submitTxRequest struct {
	ArkTx         string   `json:"ark_tx"`
	CheckpointTxs []string `json:"checkpoint_txs"`
}

type submitTxResponse struct {
	SignedArkTx         string   `json:"signed_ark_tx"`
	SignedCheckpointTxs []string `json:"signed_checkpoint_txs"`
}

type intentPayload struct {
	Proof   string `json:"proof"`
	Message string `json:"message"`
}

type submitIntentRequest struct {
	Intent intentPayload `json:"intent"`
}

type submitIntentResponse struct {
	SignedProof string `json:"signed_proof"`
}

type txTreeNode struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

type submitFinalizationRequest struct {
	SignedIntent intentPayload `json:"signed_intent"`
	Forfeits     []string      `json:"forfeits"`
	Connector    []txTreeNode  `json:"connector_tree"`
	VtxoTree     []txTreeNode  `json:"vtxo_tree"`
	CommitmentTx string        `json:"commitment_tx"`
}

type submitFinalizationResponse struct {
	SignedForfeits     []string `json:"signed_forfeits"`
	SignedCommitmentTx string   `json:"signed_commitment_tx"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	if err := waitForSecretKeyFromKMS(context.Background()); err != nil {
		log.Fatalf("failed to load secret key from KMS: %s", err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}
	if !cfg.NoTLS {
		log.Fatal("TLS is not supported in the skeleton server; set INTROSPECTOR_NO_TLS=true")
	}

	pubkeyHex := hex.EncodeToString(cfg.SecretKey.PubKey().SerializeCompressed())

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, getInfoResponse{
			SignerPubkey: pubkeyHex,
			Version:      Version,
		})
	})

	mux.HandleFunc("/v1/tx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req submitTxRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.ArkTx == "" || len(req.CheckpointTxs) == 0 {
			writeError(w, http.StatusBadRequest, "ark_tx and checkpoint_txs are required")
			return
		}

		writeJSON(w, http.StatusOK, submitTxResponse{
			SignedArkTx:         req.ArkTx,
			SignedCheckpointTxs: req.CheckpointTxs,
		})
	})

	mux.HandleFunc("/v1/intent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req submitIntentRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Intent.Proof == "" {
			writeError(w, http.StatusBadRequest, "intent.proof is required")
			return
		}
		writeJSON(w, http.StatusOK, submitIntentResponse{
			SignedProof: req.Intent.Proof,
		})
	})

	mux.HandleFunc("/v1/finalization", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req submitFinalizationRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.CommitmentTx == "" {
			writeError(w, http.StatusBadRequest, "commitment_tx is required")
			return
		}
		writeJSON(w, http.StatusOK, submitFinalizationResponse{
			SignedForfeits:     req.Forfeits,
			SignedCommitmentTx: req.CommitmentTx,
		})
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Infof("introspector skeleton listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func waitForSecretKeyFromKMS(ctx context.Context) error {
	interval := 5 * time.Second
	log.Info("waiting for secret key from KMS")
	for {
		if err := maybeLoadSecretKeyFromKMS(ctx); err == nil {
			if strings.TrimSpace(os.Getenv("INTROSPECTOR_SECRET_KEY")) != "" {
				return nil
			}
		} else {
			log.WithError(err).Warn("KMS decrypt failed; retrying")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func maybeLoadSecretKeyFromKMS(ctx context.Context) error {
	ciphertextB64, err := loadCiphertext(ctx)
	if err != nil {
		return err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("decode INTROSPECTOR_SECRET_KEY_CIPHERTEXT: %w", err)
	}

	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open nsm session: %w", err)
	}
	defer session.Close()

	attestationDoc, privateKey, err := buildAttestationDocument(session)
	if err != nil {
		return fmt.Errorf("build attestation document: %w", err)
	}

	awsCfg, err := awscfg.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	kmsClient := kms.NewFromConfig(awsCfg)
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}

	if keyID := strings.TrimSpace(os.Getenv("INTROSPECTOR_KMS_KEY_ID")); keyID != "" {
		input.KeyId = aws.String(keyID)
	}

	out, err := kmsClient.Decrypt(ctx, input)
	if err != nil {
		return fmt.Errorf("kms decrypt: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(privateKey, out.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}

	secretHex, err := normalizeSecretKey(plaintext)
	if err != nil {
		return fmt.Errorf("normalize secret key: %w", err)
	}

	if err := os.Setenv("INTROSPECTOR_SECRET_KEY", secretHex); err != nil {
		return fmt.Errorf("set INTROSPECTOR_SECRET_KEY: %w", err)
	}

	return nil
}

func loadCiphertext(ctx context.Context) (string, error) {
	if value := strings.TrimSpace(os.Getenv("INTROSPECTOR_SECRET_KEY_CIPHERTEXT")); value != "" {
		return value, nil
	}

	paramName := strings.TrimSpace(os.Getenv("INTROSPECTOR_SECRET_KEY_CIPHERTEXT_PARAM"))
	if paramName == "" {
		deployment := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT"))
		if deployment == "" {
			deployment = "dev"
		}
		paramName = fmt.Sprintf("/%s/NitroIntrospector/SecretKeyCiphertext", deployment)
	}

	awsCfg, err := awscfg.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil || strings.TrimSpace(*out.Parameter.Value) == "" {
		return "", fmt.Errorf("ssm parameter %s is empty", paramName)
	}
	return strings.TrimSpace(*out.Parameter.Value), nil
}

func buildAttestationDocument(session *nsm.Session) ([]byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(session, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(session, nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}

	resp, err := session.Send(&request.Attestation{
		Nonce:     nonce,
		PublicKey: publicKeyDER,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attestation request failed: %w", err)
	}
	if resp.Attestation == nil {
		return nil, nil, fmt.Errorf("attestation response missing document")
	}

	return resp.Attestation.Document, privateKey, nil
}

func normalizeSecretKey(plaintext []byte) (string, error) {
	candidate := strings.TrimSpace(string(plaintext))
	if len(candidate) == 64 {
		if _, err := hex.DecodeString(candidate); err == nil {
			return candidate, nil
		}
	}
	return hex.EncodeToString(plaintext), nil
}

func decodeJSON(r *http.Request, out any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}
