package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	log "github.com/sirupsen/logrus"
)

// attestationDocument represents the CBOR structure of a Nitro attestation document.
type attestationDocument struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// waitForSecretKeyFromKMS waits until the secret key is loaded from KMS.
func waitForSecretKeyFromKMS(ctx context.Context) error {
	interval := 5 * time.Second
	log.Info("initializing secret key via KMS")

	for {
		if err := initializeOrLoadSecretKey(ctx); err == nil {
			if strings.TrimSpace(os.Getenv("INTROSPECTOR_SECRET_KEY")) != "" {
				return nil
			}
		} else {
			log.WithError(err).Warn("KMS operation failed; retrying")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

// initializeOrLoadSecretKey checks SSM for existing ciphertext. If not found,
// generates a new key, encrypts with KMS, and stores in SSM.
// If found, decrypts using KMS with attestation.
// NOTE: KMS key policy must be configured EXTERNALLY with the PCR0 for decryption to work.
func initializeOrLoadSecretKey(ctx context.Context) error {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	kmsClient := kms.NewFromConfig(awsCfg)

	paramName := getSSMParamName()
	keyID, err := getKMSKeyID(ctx, ssmClient)
	if err != nil {
		return fmt.Errorf("get KMS key ID: %w", err)
	}
	if keyID == "" {
		return fmt.Errorf("KMS key ID is empty")
	}

	// Check if ciphertext already exists in SSM
	ciphertextB64, err := loadCiphertextFromSSM(ctx, ssmClient, paramName)
	if err != nil {
		return err
	}

	if ciphertextB64 == "" {
		// No existing key - generate new one, encrypt, store
		log.Info("no existing secret key found, generating new one")
		return generateAndStoreNewKey(ctx, kmsClient, ssmClient, keyID, paramName)
	}

	// Existing key found - decrypt it
	log.Info("found existing secret key ciphertext, decrypting")
	return decryptExistingKey(ctx, kmsClient, keyID, ciphertextB64)
}

// generateAndStoreNewKey generates a new secp256k1 key, encrypts it with KMS,
// extracts PCR0 from attestation (for external policy setup), and stores ciphertext in SSM.
func generateAndStoreNewKey(ctx context.Context, kmsClient *kms.Client, ssmClient *ssm.Client, keyID, paramName string) error {
	// Generate new secp256k1 private key (32 random bytes)
	privateKey, err := generateSecp256k1Key()
	if err != nil {
		return err
	}
	log.Info("generated new secp256k1 private key")

	// Encrypt with KMS (no attestation needed for encrypt)
	ciphertextB64, err := encryptWithKMS(ctx, kmsClient, keyID, privateKey)
	if err != nil {
		return err
	}
	log.Info("encrypted private key with KMS")

	// Get attestation document to extract PCR0
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open nsm session: %w", err)
	}
	defer session.Close()

	attestationDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		return err
	}

	// Extract PCR0 from attestation and log it for external policy setup
	pcr0, err := extractPCR0FromAttestation(attestationDoc)
	if err != nil {
		return err
	}
	log.Infof("PCR0 for KMS policy (apply externally): %s", pcr0)

	// NOTE: KMS key policy should be applied EXTERNALLY using this PCR0.
	// The enclave does not have permissions to modify the KMS key policy.
	// Use: aws kms put-key-policy --key-id <KEY_ID> --policy-name default --policy file://policy.json
	// where policy.json contains a condition for kms:RecipientAttestation:PCR0 = <PCR0>

	// Store ciphertext in SSM
	if err := storeCiphertextInSSM(ctx, ssmClient, paramName, ciphertextB64); err != nil {
		return err
	}

	// Set the secret key in environment
	secretHex := hex.EncodeToString(privateKey)
	if err := os.Setenv("INTROSPECTOR_SECRET_KEY", secretHex); err != nil {
		return fmt.Errorf("set INTROSPECTOR_SECRET_KEY: %w", err)
	}

	log.Info("successfully initialized new secret key")
	return nil
}

// decryptExistingKey decrypts the ciphertext from SSM using KMS with attestation.
func decryptExistingKey(ctx context.Context, kmsClient *kms.Client, keyID, ciphertextB64 string) error {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("open nsm session: %w", err)
	}
	defer session.Close()

	attestationDoc, rsaPrivateKey, err := buildAttestationDocument(session)
	if err != nil {
		return err
	}

	input := &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: ciphertext,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: kmstypes.KeyEncryptionMechanismRsaesOaepSha256,
		},
	}

	out, err := kmsClient.Decrypt(ctx, input)
	if err != nil {
		return fmt.Errorf("kms decrypt: %w", err)
	}

	if len(out.CiphertextForRecipient) == 0 {
		return fmt.Errorf("kms decrypt returned empty CiphertextForRecipient")
	}

	plaintext, err := cms.DecryptEnvelopedKey(rsaPrivateKey, out.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("decrypt CiphertextForRecipient: %w", err)
	}

	secretHex, err := normalizeSecretKey(plaintext)
	if err != nil {
		return err
	}

	if err := os.Setenv("INTROSPECTOR_SECRET_KEY", secretHex); err != nil {
		return fmt.Errorf("set INTROSPECTOR_SECRET_KEY: %w", err)
	}

	log.Info("successfully decrypted existing secret key")
	return nil
}

// buildAttestationDocument creates an attestation document with an RSA public key.
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

// extractPCR0FromAttestation parses the attestation document and returns PCR0 as hex.
func extractPCR0FromAttestation(attestationDoc []byte) (string, error) {
	// The attestation document is a COSE Sign1 structure; the payload is at index 2.
	var coseSign1 []cbor.RawMessage
	if err := cbor.Unmarshal(attestationDoc, &coseSign1); err != nil {
		return "", fmt.Errorf("unmarshal COSE Sign1: %w", err)
	}
	if len(coseSign1) < 3 {
		return "", fmt.Errorf("invalid COSE Sign1 structure")
	}

	var payload []byte
	if err := cbor.Unmarshal(coseSign1[2], &payload); err != nil {
		return "", fmt.Errorf("unmarshal COSE payload: %w", err)
	}

	var doc attestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return "", fmt.Errorf("unmarshal attestation document: %w", err)
	}

	pcr0, ok := doc.PCRs[0]
	if !ok {
		return "", fmt.Errorf("PCR0 not found in attestation document")
	}

	return hex.EncodeToString(pcr0), nil
}

// generateSecp256k1Key generates a random 32-byte secp256k1 private key.
func generateSecp256k1Key() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	return key, nil
}

// encryptWithKMS encrypts plaintext using KMS and returns base64-encoded ciphertext.
func encryptWithKMS(ctx context.Context, kmsClient *kms.Client, keyID string, plaintext []byte) (string, error) {
	out, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

// storeCiphertextInSSM stores the base64-encoded ciphertext in SSM Parameter Store.
func storeCiphertextInSSM(ctx context.Context, ssmClient *ssm.Client, paramName, ciphertext string) error {
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(ciphertext),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	log.Infof("stored ciphertext in SSM parameter: %s", paramName)
	return nil
}

// loadCiphertextFromSSM attempts to load the ciphertext from SSM. Returns empty string if not found.
func loadCiphertextFromSSM(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil // Parameter doesn't exist yet
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", nil // Treat UNSET as empty
	}
	return value, nil
}

// getSSMParamName returns the SSM parameter name for storing the secret key ciphertext.
func getSSMParamName() string {
	if paramName := strings.TrimSpace(os.Getenv("INTROSPECTOR_SECRET_KEY_CIPHERTEXT_PARAM")); paramName != "" {
		return paramName
	}
	deployment := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT"))
	if deployment == "" {
		deployment = "dev"
	}
	return fmt.Sprintf("/%s/NitroIntrospector/SecretKeyCiphertext", deployment)
}

// getKMSKeyID returns the KMS key ID from environment or SSM.
func getKMSKeyID(ctx context.Context, ssmClient *ssm.Client) (string, error) {
	if keyID := strings.TrimSpace(os.Getenv("INTROSPECTOR_KMS_KEY_ID")); keyID != "" {
		return keyID, nil
	}
	// Read from SSM parameter
	deployment := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT"))
	if deployment == "" {
		deployment = "dev"
	}
	paramName := fmt.Sprintf("/%s/NitroIntrospector/KMSKeyID", deployment)
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("KMS key ID not found in SSM parameter %s", paramName)
	}
	return strings.TrimSpace(*out.Parameter.Value), nil
}

// normalizeSecretKey normalizes the secret key to a hex string.
func normalizeSecretKey(plaintext []byte) (string, error) {
	candidate := strings.TrimSpace(string(plaintext))
	if len(candidate) == 64 {
		if _, err := hex.DecodeString(candidate); err == nil {
			return candidate, nil
		}
	}
	return hex.EncodeToString(plaintext), nil
}
