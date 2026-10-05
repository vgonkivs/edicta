package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
)

var (
	// ErrSeen means the decision already has a record: in flight, finished,
	// handed off or abandoned.
	ErrSeen = errors.New("transfer: commitment already executed or in flight")
	// ErrNotFound means the store has no record for the commitment.
	ErrNotFound = errors.New("transfer: no record for the commitment")
	// ErrAbandoned means nothing was ever sent for the decision and nothing
	// will be.
	ErrAbandoned = errors.New("transfer: record closed without a broadcast")
)

// State is where a record is in its life.
type State int

const (
	// StateBegun: recorded, no transaction signed and stored yet.
	StateBegun State = iota + 1
	// StatePrepared: the signed transaction is stored; it may have been sent.
	StatePrepared
	// StateFinished: the transaction was included in a block.
	StateFinished
	// StateHandedOff: not included by its timeout; the operator takes over.
	StateHandedOff
	// StateAbandoned: closed before anything was sent.
	StateAbandoned
)

// Prepared is the one signed transaction of a decision. Every send is exactly
// TxRaw.
type Prepared struct {
	TxRaw         []byte
	Hash          [32]byte
	TimeoutHeight uint64
	Expires       uint64
}

// Record is what the store holds for one decision.
type Record struct {
	State    State
	Expires  uint64
	Prepared Prepared
	Height   uint64
	Code     uint32
	Reason   string
}

// Store is the executor's durable state. Prepare must be durable before it
// returns: the executor broadcasts only afterwards, and a restart relies on
// the stored bytes to never sign a second transaction.
type Store interface {
	// Begin records the decision as in flight, atomically; ErrSeen if any
	// record exists.
	Begin(ctx context.Context, h commitment.Hash, expires uint64) error
	// Prepare stores the signed transaction of a begun record.
	Prepare(ctx context.Context, h commitment.Hash, p Prepared) error
	// Finish records the block that included the transaction, also for a
	// record already handed off. Repeating it with the same values is not an
	// error.
	Finish(ctx context.Context, h commitment.Hash, height uint64, code uint32) error
	// HandOff closes a prepared record as not included; terminal.
	HandOff(ctx context.Context, h commitment.Hash, reason string) error
	// Abandon closes a begun record that never got a transaction.
	Abandon(ctx context.Context, h commitment.Hash) error
	// Get returns the record, or ErrNotFound.
	Get(ctx context.Context, h commitment.Hash) (Record, error)
}

// MemStore is an in-memory Store for tests and one-shot demos. It is not
// durable: it does not meet the Prepare-durable rule, so after a restart an
// executor would not know it already signed a transaction for a decision and
// could sign a second one. A long-lived executor needs a durable Store.
type MemStore struct {
	mu sync.Mutex
	m  map[commitment.Hash]Record
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[commitment.Hash]Record{}} }

func (s *MemStore) Begin(_ context.Context, h commitment.Hash, expires uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[h]; ok {
		return ErrSeen
	}
	s.m[h] = Record{State: StateBegun, Expires: expires}
	return nil
}

func (s *MemStore) Prepare(_ context.Context, h commitment.Hash, p Prepared) error {
	if len(p.TxRaw) == 0 {
		return errors.New("transfer: empty transaction")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	if r.State != StateBegun {
		return fmt.Errorf("transfer: cannot prepare a record in state %d", r.State)
	}
	p.TxRaw = bytes.Clone(p.TxRaw)
	r.State, r.Prepared = StatePrepared, p
	s.m[h] = r
	return nil
}

func (s *MemStore) Finish(_ context.Context, h commitment.Hash, height uint64, code uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	switch {
	case r.State == StateFinished && r.Height == height && r.Code == code:
		return nil
	case r.State != StatePrepared && r.State != StateHandedOff:
		return fmt.Errorf("transfer: cannot finish a record in state %d", r.State)
	}
	r.State, r.Height, r.Code = StateFinished, height, code
	s.m[h] = r
	return nil
}

func (s *MemStore) HandOff(_ context.Context, h commitment.Hash, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	switch r.State {
	case StateHandedOff:
		return nil
	case StatePrepared:
	default:
		return fmt.Errorf("transfer: cannot hand off a record in state %d", r.State)
	}
	r.State, r.Reason = StateHandedOff, reason
	s.m[h] = r
	return nil
}

func (s *MemStore) Abandon(_ context.Context, h commitment.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	switch r.State {
	case StateAbandoned:
		return nil
	case StateBegun:
	default:
		return fmt.Errorf("transfer: cannot abandon a record in state %d", r.State)
	}
	r.State = StateAbandoned
	s.m[h] = r
	return nil
}

func (s *MemStore) Get(_ context.Context, h commitment.Hash) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return Record{}, ErrNotFound
	}
	r.Prepared.TxRaw = bytes.Clone(r.Prepared.TxRaw)
	return r, nil
}
