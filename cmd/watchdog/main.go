package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type enclaveDesc struct {
	EnclaveName string `json:"EnclaveName"`
	State       string `json:"State"`
}

func main() {
	cfg := loadConfig()

	log.Printf("starting enclave %q", cfg.enclaveName)
	if err := runEnclave(cfg); err != nil {
		log.Fatalf("failed to run enclave: %v", err)
	}

	for {
		running, err := isEnclaveRunning(cfg)
		if err != nil {
			log.Printf("describe-enclaves failed: %v", err)
			break
		}
		if !running {
			log.Printf("enclave %q is not running", cfg.enclaveName)
			break
		}
		time.Sleep(cfg.pollInterval)
	}
}

type config struct {
	nitroCLIPath string
	enclaveName  string
	eifPath      string
	cpuCount     int
	memoryMiB    int
	enclaveCID   int
	debugMode    bool
	pollInterval time.Duration
}

func loadConfig() config {
	return config{
		nitroCLIPath: getEnv("NITRO_CLI_PATH", "/usr/bin/nitro-cli"),
		enclaveName:  getEnv("ENCLAVE_NAME", "app"),
		eifPath:      getEnv("EIF_PATH", "/home/ec2-user/app/server/signing_server.eif"),
		cpuCount:     getIntEnv("CPU_COUNT", 2),
		memoryMiB:    getIntEnv("MEMORY_MIB", 4320),
		enclaveCID:   getIntEnv("ENCLAVE_CID", 16),
		debugMode:    getBoolEnv("DEBUG_MODE", false),
		pollInterval: time.Duration(getIntEnv("POLL_INTERVAL_SECONDS", 5)) * time.Second,
	}
}

func isEnclaveRunning(cfg config) (bool, error) {
	out, err := exec.Command(cfg.nitroCLIPath, "describe-enclaves").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("describe-enclaves: %w: %s", err, strings.TrimSpace(string(out)))
	}

	var enclaves []enclaveDesc
	if err := json.Unmarshal(out, &enclaves); err != nil {
		return false, fmt.Errorf("parse describe-enclaves JSON: %w", err)
	}

	if len(enclaves) != 1 {
		return false, nil
	}

	enc := enclaves[0]
	return enc.EnclaveName == cfg.enclaveName && strings.EqualFold(enc.State, "running"), nil
}

func runEnclave(cfg config) error {
	args := []string{
		"run-enclave",
		"--cpu-count", strconv.Itoa(cfg.cpuCount),
		"--memory", strconv.Itoa(cfg.memoryMiB),
		"--eif-path", cfg.eifPath,
		"--enclave-cid", strconv.Itoa(cfg.enclaveCID),
		"--enclave-name", cfg.enclaveName,
	}
	if cfg.debugMode {
		args = append(args, "--debug-mode")
	}

	out, err := exec.Command(cfg.nitroCLIPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run-enclave: %w: %s", err, strings.TrimSpace(string(out)))
	}
	log.Printf("run-enclave response: %s", strings.TrimSpace(string(out)))
	return nil
}

func getEnv(key, def string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return def
}

func getIntEnv(key string, def int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return def
	}
	return parsed
}

func getBoolEnv(key string, def bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}
