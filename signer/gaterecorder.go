// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/engine/gate"
)

// GateClient is the record call of the gate's HTTP client.
type GateClient interface {
	Record(ctx context.Context, envelope []byte, railRef string, pub, sig []byte) ([]byte, error)
}

// GateRecorder adapts the gate's HTTP client: a receipt the gate already
// holds is the answer, and a retryable or transport failure is
// ErrUnavailable.
type GateRecorder struct{ C GateClient }

var _ Recorder = GateRecorder{}

func (g GateRecorder) Record(ctx context.Context, envelope []byte, railRef string, pub, sig []byte) ([]byte, error) {
	receipt, err := g.C.Record(ctx, envelope, railRef, pub, sig)
	if err == nil {
		return receipt, nil
	}
	var ae *edictaapi.Error
	switch {
	case errors.As(err, &ae) && errors.Is(err, gate.ErrReceiptExists) && len(ae.Stored) > 0:
		return ae.Stored, nil
	case errors.As(err, &ae) && !ae.Retryable && ae.Status != 500:
		return nil, fmt.Errorf("signer: record: %w", err)
	}
	return nil, fmt.Errorf("%w: record: %w", ErrUnavailable, err)
}
