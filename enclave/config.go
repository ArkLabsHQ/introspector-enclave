package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SecretKey = "SECRET_KEY"
	Port      = "PORT"
	NoTLS     = "NO_TLS"
	LogLevel  = "LOG_LEVEL"
)

var (
	defaultPort     = uint32(7073)
	defaultNoTLS    = false
	defaultLogLevel = log.DebugLevel
)

type Config struct {
	SecretKey *btcec.PrivateKey
	Port      uint32
	NoTLS     bool
}

func LoadConfig() (*Config, error) {
	viper.SetEnvPrefix("INTROSPECTOR")
	viper.AutomaticEnv()

	viper.SetDefault(Port, defaultPort)
	viper.SetDefault(NoTLS, defaultNoTLS)
	viper.SetDefault(LogLevel, defaultLogLevel)

	secretKeyHex := viper.GetString(SecretKey)
	secretKeyBytes, err := hex.DecodeString(secretKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: %w", err)
	}
	secretKey, _ := btcec.PrivKeyFromBytes(secretKeyBytes)
	if secretKey == nil {
		return nil, fmt.Errorf("invalid secret key")
	}

	logLevel := viper.GetInt(LogLevel)
	log.SetLevel(log.Level(logLevel))

	cfg := &Config{
		SecretKey: secretKey,
		Port:      viper.GetUint32(Port),
		NoTLS:     viper.GetBool(NoTLS),
	}
	return cfg, nil
}
