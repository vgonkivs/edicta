// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"math/big"
	"time"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// Entry is the durable record of one decision. Everything a restart needs to
// resume is in it: the request, the signed bytes, the state.
type Entry struct {
	CommitmentHash commitment.Hash `json:"commitment_hash"`
	// Digest is what the payer key signs; one per decision.
	Digest     [32]byte `json:"digest"`
	ActionType string   `json:"action_type"`
	// Key selects the wallet: the chain id.
	Key   uint64   `json:"key"`
	Payer [20]byte `json:"payer"`
	// Value and Fee are what the caps count, big-endian.
	Value []byte `json:"value"`
	Fee   []byte `json:"fee"`
	// ReservedAt is the signer clock at reservation, Unix seconds.
	ReservedAt int64 `json:"reserved_at"`
	// Until is the chain time after which a transaction not found was not
	// executed, Unix seconds.
	Until int64 `json:"until"`

	Envelope      []byte `json:"envelope"`
	Action        []byte `json:"action"`
	Salt          []byte `json:"salt"`
	Authorization []byte `json:"authorization"`
	AuthExpires   uint64 `json:"auth_expires"`
	Mode          uint64 `json:"mode"`
	// Requirements are the payment requirements presented with the
	// request and checked before the reservation, if any.
	Requirements []byte `json:"requirements,omitempty"`
	// Slot is the rail resource the decision holds while it is unresolved
	// (the payer's nonce); empty is none.
	Slot string `json:"slot,omitempty"`

	// Signed is set once and never changes.
	Signed  []byte `json:"signed,omitempty"`
	RailRef string `json:"rail_ref,omitempty"`
	// SendStarted records that the first send was allowed to start (before
	// the Authorization expired); later sends of the same bytes are resends.
	SendStarted bool `json:"send_started,omitempty"`

	State   State  `json:"state"`
	Outcome string `json:"outcome,omitempty"`
	Receipt []byte `json:"receipt,omitempty"`
	Detail  string `json:"detail,omitempty"`
	// Seen: some source served the transaction while the signer waited.
	// It only ever turns true, and keeps not executed out of reach.
	Seen bool `json:"seen,omitempty"`
	// PaymentProofAllowed: the settlement that set the outcome is strong
	// enough for a payment proof.
	PaymentProofAllowed bool `json:"payment_proof_allowed,omitempty"`
	// PaymentProof is the payment proof released for the decision. Set
	// once, it never changes.
	PaymentProof []byte `json:"payment_proof,omitempty"`
}

// HoldsSlot says whether e still holds its slot at now: until its
// settlement is final, or, unsigned, while a repeat could still sign it.
// A decision the operator looks at keeps it.
func (e Entry) HoldsSlot(now time.Time, skewS uint64) bool {
	switch e.State {
	case StateSigned, StateWrong:
		return true
	case StateReserved:
		n := now.Unix()
		return n < 0 || uint64(n) < e.AuthExpires+skewS
	}
	return false
}

// Totals are the sums the per-hour caps compare, over the entries reserved
// inside the window, and the last other entry that reserved the new entry's
// slot.
type Totals struct {
	Value *big.Int
	Fee   *big.Int
	// SlotHolder is the entry that last reserved the same slot, if any.
	SlotHolder *Entry
}

// Store keeps the entries durably. Every write is durable when the call
// returns. An implementation may do I/O.
type Store interface {
	// Reserve stores e unless an entry for its commitment hash exists, in
	// which case it returns that entry with existing set and changes
	// nothing. Otherwise it sums the entries reserved at or after
	// windowStart, finds the last entry that reserved e's slot, calls admit
	// with both, and stores e, as the slot's new holder, only if admit
	// returns nil: the reservation, the counters and the slot are one
	// durable write.
	Reserve(ctx context.Context, e Entry, windowStart int64, admit func(Totals) error) (stored Entry, existing bool, err error)
	// Get returns the entry of h.
	Get(ctx context.Context, h commitment.Hash) (Entry, bool, error)
	// Update changes a stored entry under fn. The digest, the counted
	// amounts and the request never change, and signed bytes once stored
	// never change.
	Update(ctx context.Context, h commitment.Hash, fn func(*Entry) error) (Entry, error)
	// Unfinished returns the entries in the given states.
	Unfinished(ctx context.Context, states ...State) ([]Entry, error)
	// IndexSlot gives an entry stored without a slot (by an earlier build)
	// its slot, and makes it the slot's holder unless one is indexed.
	IndexSlot(ctx context.Context, h commitment.Hash, slot string) error
	Close() error
}
