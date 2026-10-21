// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/commitment"
)

// Run settles and records signed decisions until ctx ends: at start (a
// restart resumes from the store), after every signature, and every retry
// interval. It never signs.
func (s *Service) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, s.cfg.MaxSettling)
	t := time.NewTicker(s.cfg.RetryInterval)
	defer t.Stop()
	for {
		states := []State{StateSigned}
		if s.rec != nil {
			states = append(states, StateExecuted, StateReverted)
		}
		entries, err := s.st.Unfinished(ctx, states...)
		if err != nil {
			s.log.Warn("signer: listing unfinished decisions", "err", err)
		}
	slots:
		for _, e := range entries {
			if !s.claim(e.CommitmentHash) {
				continue
			}
			// The loop never waits for a slot: entries left over get one in
			// a later round, and every round is bounded, so no decision
			// holds a slot until its deadline.
			select {
			case sem <- struct{}{}:
			default:
				s.release(e.CommitmentHash)
				break slots
			}
			wg.Add(1)
			go func(e Entry) {
				defer wg.Done()
				defer func() { <-sem }()
				defer s.release(e.CommitmentHash)
				defer func() {
					if p := recover(); p != nil {
						s.log.Error("signer: panic while advancing a decision",
							"commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "panic", fmt.Sprint(p))
					}
				}()
				rctx, cancel := context.WithTimeout(ctx, s.cfg.SettleRound)
				defer cancel()
				s.Advance(rctx, e)
			}(e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.kick:
		case <-t.C:
		}
	}
}

func (s *Service) claim(h commitment.Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight[h] {
		return false
	}
	s.inflight[h] = true
	return true
}

func (s *Service) release(h commitment.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, h)
}

// Advance takes one decision as far as it can go now: settle a signed one,
// then record an executed or reverted one. A failure leaves the state for
// the next round.
func (s *Service) Advance(ctx context.Context, e Entry) {
	id := hex.EncodeToString(e.CommitmentHash[:])
	if e.State == StateSigned {
		h := s.handlers[e.ActionType]
		if h == nil {
			s.log.Error("signer: no handler for a stored decision", "commitment_hash", id, "action_type", e.ActionType)
			return
		}
		res, err := h.Settle(ctx, e, e.SendStarted)
		if err != nil {
			s.log.Info("signer: settlement unknown, looking again later", "commitment_hash", id, "rail_ref", e.RailRef, "err", err)
			return
		}
		switch res.State {
		case StateExecuted, StateReverted, StateNotExecuted, StateWrong:
		default:
			s.log.Error("signer: handler returned an unknown settlement", "commitment_hash", id, "state", res.State)
			return
		}
		e, err = s.st.Update(ctx, e.CommitmentHash, func(x *Entry) error {
			if x.State != StateSigned {
				return fmt.Errorf("signer: state moved to %s", x.State)
			}
			x.State, x.Outcome, x.Detail = res.State, res.Outcome, res.Detail
			return nil
		})
		if err != nil {
			s.log.Warn("signer: storing the settlement", "commitment_hash", id, "err", err)
			return
		}
		s.log.Info("signer: settled", "commitment_hash", id, "rail_ref", e.RailRef, "state", e.State, "detail", e.Detail)
	}
	if s.rec == nil || (e.State != StateExecuted && e.State != StateReverted) {
		return
	}
	s.record(ctx, e)
}

// record: only after the rail included the transaction, a record
// request signed with the executor key.
func (s *Service) record(ctx context.Context, e Entry) {
	id := hex.EncodeToString(e.CommitmentHash[:])
	receipt, err := s.requestRecord(ctx, e)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			s.log.Info("signer: record request failed, retrying later", "commitment_hash", id, "err", err)
			return
		}
		s.log.Error("signer: the gate refused the record request", "commitment_hash", id, "rail_ref", e.RailRef, "err", err)
		_, _ = s.st.Update(ctx, e.CommitmentHash, func(x *Entry) error {
			x.State, x.Detail = StateWrong, "record refused: "+err.Error()
			return nil
		})
		return
	}
	if _, err := s.st.Update(ctx, e.CommitmentHash, func(x *Entry) error {
		x.State, x.Receipt = StateRecorded, receipt
		return nil
	}); err != nil {
		s.log.Warn("signer: storing the receipt", "commitment_hash", id, "err", err)
		return
	}
	s.log.Info("signer: recorded", "commitment_hash", id, "rail_ref", e.RailRef)
}

func (s *Service) requestRecord(ctx context.Context, e Entry) ([]byte, error) {
	msg, err := commitment.RecordRequestMessage(e.CommitmentHash, s.cfg.GateID, e.RailRef)
	if err != nil {
		return nil, err
	}
	sig, err := s.exec.SignRecord(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("%w: executor key: %w", ErrUnavailable, err)
	}
	pub := s.exec.PublicKey()
	receipt, err := s.rec.Record(ctx, e.Envelope, e.RailRef, pub, sig)
	if err != nil {
		return nil, err
	}
	// The receipt is kept only if the pinned gate signed it for this claim.
	r, _, err := commitment.VerifyReceipt(receipt)
	if err != nil {
		return nil, fmt.Errorf("signer: receipt: %w", err)
	}
	switch {
	case !bytes.Equal(r.Receipt.GatePubKey, s.cfg.GatePubKey), r.Receipt.GateID != s.cfg.GateID:
		return nil, errors.New("signer: receipt from another gate")
	case !bytes.Equal(r.Receipt.CommitmentHash, e.CommitmentHash[:]), r.Receipt.RailRef != e.RailRef:
		return nil, errors.New("signer: receipt for another claim")
	}
	return receipt, nil
}

// Requeue is the operator's way back from StateWrong, for example after a
// gate refused record requests because of a configuration mistake: an entry
// whose transaction was settled goes back to its outcome, so the record
// request is retried; one that never settled goes back to waiting for the
// rail. It never signs and never changes the signed bytes.
func (s *Service) Requeue(ctx context.Context, h commitment.Hash) (State, error) {
	e, err := s.st.Update(ctx, h, func(x *Entry) error {
		if x.State != StateWrong || len(x.Signed) == 0 {
			return fmt.Errorf("%w: state %s", ErrNotRequeueable, x.State)
		}
		switch State(x.Outcome) {
		case StateExecuted, StateReverted:
			x.State = State(x.Outcome)
		default:
			x.State = StateSigned
		}
		x.Detail = "requeued by the operator after: " + x.Detail
		return nil
	})
	if err != nil {
		return "", err
	}
	s.log.Warn("signer: requeued by the operator", "commitment_hash", hex.EncodeToString(h[:]), "state", e.State)
	s.wake()
	return e.State, nil
}
