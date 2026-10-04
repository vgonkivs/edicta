package ibkr

import (
	"context"
	"errors"
	"math/bits"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
)

var (
	// ErrNotPlaced means the order was never placed and never will be: the
	// record is closed.
	ErrNotPlaced = errors.New("ibkr: order not placed")
	// ErrSeen means the commitment already has a record: executed or in
	// flight.
	ErrSeen = errors.New("ibkr: commitment already executed or in flight")
	// ErrNotFound means the store has no record for the commitment.
	ErrNotFound = errors.New("ibkr: no record for the commitment")
)

// Record is what the store holds for one commitment. It is in flight until it
// gets an order id (OrderID) or is closed as never placed (NotPlaced).
type Record struct {
	Expires   uint64
	OrderID   string
	NotPlaced bool
}

// InFlight reports whether the order was begun but not resolved.
func (r Record) InFlight() bool { return r.OrderID == "" && !r.NotPlaced }

// Store is the executor's dedupe state. It must survive a restart for the
// at-most-once guarantee to hold across one.
type Store interface {
	// Begin records the commitment as in flight, atomically; ErrSeen if a
	// record exists.
	Begin(_ context.Context, h commitment.Hash, expires uint64) error
	// Finish attaches the broker's order id. Repeating it with the same id
	// is not an error.
	Finish(_ context.Context, h commitment.Hash, orderID string) error
	// Abandon closes an in-flight record as never placed. Nothing is placed
	// for a closed record. Closing a finished record is an error.
	Abandon(_ context.Context, h commitment.Hash) error
	// Get returns the record, or ErrNotFound.
	Get(_ context.Context, h commitment.Hash) (Record, error)
}

// MemStore is an in-memory Store. It ignores contexts, as it never blocks.
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
	s.m[h] = Record{Expires: expires}
	return nil
}

func (s *MemStore) Finish(_ context.Context, h commitment.Hash, orderID string) error {
	if orderID == "" {
		return errors.New("ibkr: empty order id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	if r.NotPlaced {
		return errors.New("ibkr: commitment was closed as not placed")
	}
	if r.OrderID != "" && r.OrderID != orderID {
		return errors.New("ibkr: commitment already finished with another order id")
	}
	r.OrderID = orderID
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
	if r.OrderID != "" {
		return errors.New("ibkr: commitment already finished")
	}
	r.NotPlaced = true
	s.m[h] = r
	return nil
}

// Prune drops the records that are resolved and past expires + skewS, and
// returns how many it dropped. In-flight records stay until resolved.
func (s *MemStore) Prune(now, skewS uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for h, r := range s.m {
		if r.InFlight() {
			continue
		}
		if cut, carry := bits.Add64(r.Expires, skewS, 0); carry == 0 && now > cut {
			delete(s.m, h)
			n++
		}
	}
	return n
}

func (s *MemStore) Get(_ context.Context, h commitment.Hash) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}
