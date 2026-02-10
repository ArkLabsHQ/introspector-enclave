package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	log "github.com/sirupsen/logrus"
)

const (
	// MigrationCooldown is the mandatory waiting period between initiation and completion.
	MigrationCooldown = 24 * time.Hour

	// MigrationVsockPort is the vsock port for the migration server.
	MigrationVsockPort = 9999
)

// MigrationState tracks a pending or completed key migration.
type MigrationState struct {
	TargetPCR0     string `json:"target_pcr0"`
	V2KMSKeyID     string `json:"v2_kms_key_id"`
	InitiatedAt    int64  `json:"initiated_at"`
	CompletedAt    int64  `json:"completed_at,omitempty"`
	SourcePCR0     string `json:"source_pcr0,omitempty"`     // V1's PCR0 at time of migration
	PreviousPCR0   string `json:"previous_pcr0,omitempty"`   // V2's compiled-in predecessor PCR0
	ActivationTime int64  `json:"activation_time,omitempty"` // Maintainer-specified earliest activation
}

// migrationSSMParamName returns the SSM parameter name for storing migration state.
func migrationSSMParamName() string {
	deployment := strings.TrimSpace(getDeploymentName())
	return fmt.Sprintf("/%s/NitroIntrospector/MigrationState", deployment)
}

// v2CiphertextSSMParamName returns the SSM parameter name for V2's encrypted key.
func v2CiphertextSSMParamName() string {
	deployment := strings.TrimSpace(getDeploymentName())
	return fmt.Sprintf("/%s/NitroIntrospector/V2SecretKeyCiphertext", deployment)
}

// getDeploymentName returns the deployment name from environment.
func getDeploymentName() string {
	deployment := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT"))
	if deployment == "" {
		deployment = "dev"
	}
	return deployment
}

// loadMigrationState loads the migration state from SSM. Returns nil if no migration is pending.
func loadMigrationState(ctx context.Context, ssmClient *ssm.Client) (*MigrationState, error) {
	paramName := migrationSSMParamName()
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return nil, nil
		}
		return nil, fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return nil, nil
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return nil, nil
	}

	var state MigrationState
	if err := json.Unmarshal([]byte(value), &state); err != nil {
		return nil, fmt.Errorf("unmarshal migration state: %w", err)
	}
	return &state, nil
}

// storeMigrationState writes the migration state to SSM.
func storeMigrationState(ctx context.Context, ssmClient *ssm.Client, state *MigrationState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal migration state: %w", err)
	}
	paramName := migrationSSMParamName()
	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(string(data)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	log.Infof("stored migration state in SSM: %s", paramName)
	return nil
}

// isCooldownExpired returns true if the migration cooldown has passed.
func isCooldownExpired(state *MigrationState) bool {
	if state == nil || state.InitiatedAt == 0 {
		return false
	}
	initiated := time.Unix(state.InitiatedAt, 0)
	return time.Since(initiated) >= MigrationCooldown
}

// storeV2Ciphertext stores the V2-encrypted key ciphertext in SSM.
func storeV2Ciphertext(ctx context.Context, ssmClient *ssm.Client, ciphertextB64 string) error {
	paramName := v2CiphertextSSMParamName()
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(ciphertextB64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	log.Infof("stored V2 ciphertext in SSM: %s", paramName)
	return nil
}

// loadV2Ciphertext loads the V2-encrypted key ciphertext from SSM.
func loadV2Ciphertext(ctx context.Context, ssmClient *ssm.Client) (string, error) {
	paramName := v2CiphertextSSMParamName()
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", nil
	}
	return value, nil
}
