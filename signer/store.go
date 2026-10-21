// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"math/big"

	"github.com/vgonkivs/edicta/commitment"
)

// State is where one decision stands at the signer.
type State string

const (
	// StateReserved: the digest is reserved and counted, nothing is signed
	// yet. A repeat of the request signs it.
	StateReserved State = "reserved"
	// StateSigned: the signed bytes are stored and may be on their way; the
	// rail has not been seen to include them.
	StateSigned State = "signed"
	// StateExecuted and StateReverted: the rail included the transaction at
	// the confirmation depth with that outcome; the record request is due.
	StateExecuted State = "executed"
	StateReverted State = "reverted"
	// StateRecorded: the gate returned its receipt for the rail_ref.
	StateRecorded State = "recorded"
	// StateNotExecuted: no source served the transaction by the deadline.
	// Nothing is recorded and nothing else is ever signed for the decision.
	StateNotExecuted State = "not_executed"
	// StateWrong: the rail answered with something the signed bytes cannot
	// explain, or the gate refused the record for good. The operator looks.
	StateWrong State = "wrong"
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
}

// Totals are the sums the per-hour caps compare, over the entries reserved
// inside the window.
type Totals struct {
	Value *big.Int
	Fee   *big.Int
}

// Store keeps the entries durably. Every write is durable when the call
// returns. An implementation may do I/O.
type Store interface {
	// Reserve stores e unless an entry for its commitment hash exists, in
	// which case it returns that entry with existing set and changes
	// nothing. Otherwise it sums the entries reserved at or after
	// windowStart, calls admit with the sums, and stores e only if admit
	// returns nil: the reservation and the counters are one durable write.
	Reserve(ctx context.Context, e Entry, windowStart int64, admit func(Totals) error) (stored Entry, existing bool, err error)
	// Get returns the entry of h.
	Get(ctx context.Context, h commitment.Hash) (Entry, bool, error)
	// Update changes a stored entry under fn. The digest, the counted
	// amounts and the request never change, and signed bytes once stored
	// never change.
	Update(ctx context.Context, h commitment.Hash, fn func(*Entry) error) (Entry, error)
	// Unfinished returns the entries in the given states.
	Unfinished(ctx context.Context, states ...State) ([]Entry, error)
	Close() error
}
