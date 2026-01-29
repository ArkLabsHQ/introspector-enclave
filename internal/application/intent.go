package application

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/btcsuite/btcd/btcutil/psbt"
	log "github.com/sirupsen/logrus"
)

// SubmitIntent aims to execute arkade scripts on unsigned intent proof
// it must be used before registration of the intent
func (s *service) SubmitIntent(ctx context.Context, intent Intent) (*psbt.Packet, error) {
	if err := validateRegisterMessage(intent.Message); err != nil {
		return nil, fmt.Errorf("invalid message: %w", err)
	}

	ptx := &intent.Proof.Packet

	prevoutFetcher, err := computePrevoutFetcher(ptx)
	if err != nil {
		return nil, fmt.Errorf("failed to create prevout fetcher: %w", err)
	}

	signerPublicKey := s.signer.secretKey.PubKey()

	for inputIndex := range ptx.Inputs {
		script, err := readArkadeScript(ptx, inputIndex, signerPublicKey)
		if err != nil {
			// skip if the input is not an arkade script
			continue
		}

		log.Debugf("executing arkade script: %x", script.script)
		if err := script.execute(ptx.UnsignedTx, prevoutFetcher, inputIndex); err != nil {
			return nil, fmt.Errorf("failed to execute arkade script: %w", err)
		}
		log.Debugf("execution of %x succeeded", script.script)

		if err := s.signer.signInput(ptx, inputIndex, script.hash, prevoutFetcher); err != nil {
			return nil, fmt.Errorf("failed to sign input %d: %w", inputIndex, err)
		}

	}

	return ptx, nil
}

func validateRegisterMessage(message intent.RegisterMessage) error {
	now := time.Now()
	if message.ExpireAt > 0 {
		expireAt := time.Unix(message.ExpireAt, 0)
		if expireAt.Before(now) {
			return fmt.Errorf("intent message expired")
		}
	}

	if message.ValidAt > 0 {
		validAt := time.Unix(message.ValidAt, 0)
		if validAt.After(now) {
			return fmt.Errorf("intent message not valid yet")
		}
	}

	return nil
}
