package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/hf/nsm"
	log "github.com/sirupsen/logrus"
)

var exportOnce sync.Once
var deleteKMSOnce sync.Once

// handleExportKey handles POST /v1/export-key.
// Exports all configured secrets encrypted with a temporary migration KMS key.
// Each secret's ciphertext is stored in SSM for the new enclave to decrypt on boot.
//
// One-shot: responds exactly once, then returns 410 Gone.
func handleExportKey(w http.ResponseWriter, r *http.Request) {
	var ok bool
	exportOnce.Do(func() { ok = true })
	if !ok {
		http.Error(w, "already exported", http.StatusGone)
		return
	}

	ctx := r.Context()
	deployment := getDeployment()
	appName := getAppName()

	// Load AWS clients.
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		log.Errorf("export-key: load AWS config: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ssmClient := ssm.NewFromConfig(awsCfg)

	// Verify migration token.
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	expectedToken, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationToken", deployment, appName))
	if err != nil || token != expectedToken {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Read migration KMS key ID.
	migrationKeyID, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationKMSKeyID", deployment, appName))
	if err != nil {
		log.Errorf("export-key: migration KMS key ID: %v", err)
		http.Error(w, "migration key not configured", http.StatusInternalServerError)
		return
	}

	kmsClient := kms.NewFromConfig(awsCfg)

	// Export all configured secrets.
	var exported []string
	for _, secret := range secretsDefs {
		secretValue := os.Getenv(secret.EnvVar)
		if secretValue == "" {
			log.Warnf("export-key: secret %s (env=%s) not loaded, skipping", secret.Name, secret.EnvVar)
			continue
		}

		keyBytes, err := hex.DecodeString(secretValue)
		if err != nil {
			log.Errorf("export-key: invalid hex for %s: %v", secret.Name, err)
			http.Error(w, fmt.Sprintf("invalid key format for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		// Encrypt with migration KMS key.
		ciphertextB64, err := encryptWithKMS(ctx, kmsClient, migrationKeyID, keyBytes)
		if err != nil {
			log.Errorf("export-key: KMS encrypt %s: %v", secret.Name, err)
			http.Error(w, fmt.Sprintf("KMS encrypt failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		// Store migration ciphertext in SSM.
		ciphertextParam := fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, secret.Name)
		if err := storeCiphertextInSSM(ctx, ssmClient, ciphertextParam, ciphertextB64); err != nil {
			log.Errorf("export-key: store ciphertext for %s: %v", secret.Name, err)
			http.Error(w, fmt.Sprintf("SSM store failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		exported = append(exported, secret.Name)
	}

	// Store this enclave's PCR0 for the attestation chain.
	pcr0 := getPCR0()
	if pcr0 != "" {
		pcr0Param := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)
		_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
			Name:      aws.String(pcr0Param),
			Value:     aws.String(pcr0),
			Type:      ssmtypes.ParameterTypeString,
			Overwrite: aws.Bool(true),
		})
		if err != nil {
			log.Warnf("export-key: store previous PCR0: %v", err)
		}
	}

	log.Infof("export-key: exported %d secret(s) (pcr0=%s)", len(exported), pcr0)

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		PCR0     string   `json:"pcr0"`
		Exported []string `json:"exported"`
	}{
		PCR0:     pcr0,
		Exported: exported,
	}
	json.NewEncoder(w).Encode(resp)
}

// readMigrationPreviousPCR0 reads the previous enclave's PCR0 from SSM.
// Returns empty string if not set (normal boot, no migration).
func readMigrationPreviousPCR0(ctx context.Context) (string, error) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return "", err
	}
	ssmClient := ssm.NewFromConfig(awsCfg)
	deployment := getDeployment()
	appName := getAppName()
	return readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName))
}

// deleteOldKMSKey checks if MigrationOldKMSKeyID is set in SSM. If so,
// schedules the old KMS key for deletion and clears the parameter.
func deleteOldKMSKey(ctx context.Context) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return
	}
	ssmClient := ssm.NewFromConfig(awsCfg)
	deployment := getDeployment()
	appName := getAppName()

	oldKeyID, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName))
	if err != nil {
		return // not set — normal boot, no old key to delete
	}

	kmsClient := kms.NewFromConfig(awsCfg)
	pendingDays := int32(7)
	_, err = kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(oldKeyID),
		PendingWindowInDays: &pendingDays,
	})
	if err != nil {
		log.Warnf("failed to schedule deletion of old KMS key %s: %v", oldKeyID, err)
		return
	}
	log.Infof("scheduled deletion of old KMS key %s (7 day pending window)", oldKeyID)

	// Clear the parameter so we don't try again on next reboot.
	_, _ = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName)),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
}

// readSSMParam reads an SSM parameter value. Returns error if missing or UNSET.
func readSSMParam(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", paramName)
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", paramName)
	}
	return value, nil
}

// getDeployment returns the deployment prefix from environment.
func getDeployment() string {
	if d := strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")); d != "" {
		return d
	}
	if d := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT")); d != "" {
		return d
	}
	return "dev"
}

// getAppName returns the app name from environment.
func getAppName() string {
	if name := strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME")); name != "" {
		return name
	}
	return "app"
}

// getPCR0 returns this enclave's PCR0 from the NSM attestation document.
func getPCR0() string {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Warnf("getPCR0: open NSM session: %v", err)
		return ""
	}
	defer session.Close()

	attestDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		log.Warnf("getPCR0: build attestation: %v", err)
		return ""
	}

	pcr0, err := extractPCR0FromAttestation(attestDoc)
	if err != nil {
		log.Warnf("getPCR0: extract PCR0: %v", err)
		return ""
	}
	return pcr0
}
