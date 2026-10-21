// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
)

// DecodeStatusResponse decodes a CBOR 200 answer of GET /v1/status/{hash}.
func DecodeStatusResponse(b []byte) (Status, error) {
	f, err := edictaapi.DecodeWrapper(b, StatusResponseSchema)
	if err != nil {
		return Status{}, err
	}
	sent, _ := f.Uint(3)
	allowed, _ := f.Uint(8)
	return Status{
		State: State(f.Text(1)), Sent: sent == 1, RailRef: f.Text(4), Signed: f.Bytes(5), Outcome: f.Text(6),
		Detail: f.Text(7), PaymentProofAllowed: allowed == 1, Receipt: f.Bytes(9),
	}, nil
}

// Status is what the signer tells an agent about its own decision.
type Status struct {
	State State
	// Sent: the first send was allowed to start.
	Sent    bool
	RailRef string
	Signed  []byte
	Outcome string
	Detail  string
	// PaymentProofAllowed: the settlement is strong enough for a payment
	// proof.
	PaymentProofAllowed bool
	Receipt             []byte
}

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
