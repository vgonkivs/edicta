// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"
)

// PaymentProofsEnabled says whether some handler offers payment proofs.
func (s *Service) PaymentProofsEnabled() bool { return len(s.provers) > 0 }

// PaymentProof releases the payment proof of a decision the signer itself
// paid, to the agent that made it, once the rail executed the payment. In
// order, the first failure decides: the field is offered (ErrPinMismatch);
// the request carries the decision's own signed material, verified as for
// signing but on the clock of the reservation, for the reserved digest, and
// caller is the agent key the request's API credential is pinned to
// (ErrNotAuthorized); the profile's checks on the committed action and the
// requirements (ErrRequirements); the rail executed it on the word of
// enough operators (ErrNotExecuted). The message always comes from the
// committed action and the requirements it binds, never from the request.
func (s *Service) PaymentProof(ctx context.Context, req PaymentProofRequest, caller []byte) (PaymentProof, error) {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if !started {
		return PaymentProof{}, fmt.Errorf("%w: not started", ErrUnavailable)
	}
	if !s.paymentFieldOffered(req.Field) {
		return PaymentProof{}, fmt.Errorf("%w: no payment proof over field %q", ErrPinMismatch, req.Field)
	}

	e, v, p, err := s.paymentRequester(ctx, req, caller)
	if err != nil {
		return PaymentProof{}, err
	}
	if err := p.CheckPaymentProofField(req.Field); err != nil {
		return PaymentProof{}, err
	}

	r := req.Requirements
	if r == nil {
		r = e.Requirements
	}
	msg, digest, err := p.PaymentProofDigest(v.Action, r)
	if err != nil {
		return PaymentProof{}, fmt.Errorf("%w: %w", ErrRequirements, err)
	}

	if !(e.State == StateExecuted || e.State == StateRecorded) || e.Outcome != string(StateExecuted) || !e.PaymentProofAllowed {
		return PaymentProof{}, fmt.Errorf("%w: decision in state %s (outcome %q)", ErrNotExecuted, e.State, e.Outcome)
	}

	out := PaymentProof{CommitmentHash: e.CommitmentHash, Message: msg}
	if len(e.PaymentProof) > 0 {
		out.Signature, out.Repeat = bytes.Clone(e.PaymentProof), true
		return out, nil
	}
	// The payer that signed the deposit is the escrow's buyer; only its own
	// key may sign the proof, and only while it is still this agent's.
	wk, err := NewWalletKey(v.Commitment.AgentPubKey, e.Key)
	if err != nil {
		return PaymentProof{}, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	wallet := s.wallets[wk]
	if wallet == nil || s.payer(wk) != e.Payer {
		return PaymentProof{}, fmt.Errorf("%w: no payer key %x of this agent for chain %d", ErrPinMismatch, e.Payer, e.Key)
	}
	sig, err := wallet.SignDigest(ctx, digest)
	if err != nil {
		return PaymentProof{}, fmt.Errorf("%w: wallet: %w", ErrUnavailable, err)
	}
	proof, err := p.FinishPaymentProof(msg, sig, e.Payer)
	if err != nil {
		return PaymentProof{}, fmt.Errorf("signer: payment proof: %w", err)
	}
	stored, err := s.st.Update(ctx, e.CommitmentHash, func(x *Entry) error {
		if len(x.PaymentProof) == 0 {
			x.PaymentProof = proof
		}
		return nil
	})
	if err != nil {
		return PaymentProof{}, err
	}
	s.log.Info("signer: payment proof released", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]),
		"rail_ref", e.RailRef, "message", hex.EncodeToString(msg[:]))
	out.Signature = stored.PaymentProof
	return out, nil
}

func (s *Service) paymentFieldOffered(field string) bool {
	for _, p := range s.provers {
		if p.CheckPaymentProofField(field) == nil {
			return true
		}
	}
	return false
}

// paymentRequester ties the request to a decision this signer reserved and
// signed, and to the agent that made it. The material alone is public (the
// envelope is published, the Authorization archived, the action bytes and
// salt may be revealed); only the credential identifies the requester.
func (s *Service) paymentRequester(ctx context.Context, req PaymentProofRequest, caller []byte) (Entry, Verified, PaymentProver, error) {
	deny := func(format string, a ...any) (Entry, Verified, PaymentProver, error) {
		return Entry{}, Verified{}, nil, fmt.Errorf("%w: %s", ErrNotAuthorized, fmt.Sprintf(format, a...))
	}
	e, found, err := s.st.Get(ctx, req.CommitmentHash)
	if err != nil {
		return Entry{}, Verified{}, nil, err
	}
	if !found || len(e.Signed) == 0 {
		return deny("no signed decision %x", req.CommitmentHash)
	}
	// The Authorization may have expired since the deposit; it was valid
	// when the decision was reserved.
	v, _, err := s.verify(req.Request, time.Unix(e.ReservedAt, 0))
	if err != nil {
		// Only the refusal's text: an expiry here is no reason to retry.
		return deny("%v", err)
	}
	if v.CommitmentHash != req.CommitmentHash {
		return deny("the envelope is commitment %x", v.CommitmentHash)
	}
	if subtle.ConstantTimeCompare(caller, v.Commitment.AgentPubKey) != 1 {
		return deny("the API credential is not the decision's agent's")
	}
	p := s.provers[e.ActionType]
	if p == nil || e.ActionType != v.Commitment.Action.Type {
		return Entry{}, Verified{}, nil, fmt.Errorf("%w: no payment proof for %s", ErrPinMismatch, e.ActionType)
	}
	d, err := p.ActionDigest(v.Action)
	if err != nil || d != e.Digest {
		return deny("the action is not the reserved transaction")
	}
	return e, v, p, nil
}
