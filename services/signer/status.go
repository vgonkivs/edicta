// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// Status returns the stored state of a decision to the caller whose API
// credential is pinned to the decision's agent key. A shared credential gets
// ErrSharedCredential before any lookup; an unknown hash and another agent's
// decision both answer ErrUnknownDecision, so the route does not tell whether
// a hash exists.
func (s *Service) Status(ctx context.Context, h commitment.Hash, caller []byte) (Status, error) {
	if caller == nil {
		return Status{}, ErrSharedCredential
	}
	e, found, err := s.st.Get(ctx, h)
	if err != nil {
		return Status{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !found {
		return Status{}, ErrUnknownDecision
	}
	sc, err := commitment.DecodeSigned(e.Envelope)
	if err != nil || subtle.ConstantTimeCompare(caller, sc.Commitment.AgentPubKey) != 1 {
		return Status{}, ErrUnknownDecision
	}
	return Status{
		State: e.State, Sent: e.SendStarted, RailRef: e.RailRef, Signed: bytes.Clone(e.Signed),
		Outcome: e.Outcome, Detail: e.Detail, PaymentProofAllowed: e.PaymentProofAllowed, Receipt: bytes.Clone(e.Receipt),
	}, nil
}
