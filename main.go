package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ArkLabsHQ/introspector/internal/config"
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
