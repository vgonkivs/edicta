package ibkr

import (
	"context"
	"errors"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
)

var (
	// ErrSeen means the commitment already has a record: executed or in
	// flight.
	ErrSeen = errors.New("ibkr: commitment already executed or in flight")
	// ErrNotFound means the store has no record for the commitment.
	ErrNotFound = errors.New("ibkr: no record for the commitment")
)

// Record is what the store holds for one commitment. OrderID is empty while
// the order is in flight.
type Record struct {
	Expires uint64
	OrderID string
}

// InFlight reports whether the order was begun but not finished.
func (r Record) InFlight() bool { return r.OrderID == "" }

// Store is the executor's dedupe state. It must survive a restart for the
// at-most-once guarantee to hold across one.
type Store interface {
	// Begin records the commitment as in flight, atomically; ErrSeen if a
	// record exists.
	Begin(ctx context.Context, h commitment.Hash, expires uint64) error
	// Finish attaches the broker's order id. Repeating it with the same id
	// is not an error.
	Finish(ctx context.Context, h commitment.Hash, orderID string) error
	// Get returns the record, or ErrNotFound.
	Get(ctx context.Context, h commitment.Hash) (Record, error)
}

// MemStore is an in-memory Store.
type MemStore struct {
	mu sync.Mutex
	m  map[commitment.Hash]Record
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[commitment.Hash]Record{}} }

func (s *MemStore) Begin(ctx context.Context, h commitment.Hash, expires uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[h]; ok {
		return ErrSeen
	}
	s.m[h] = Record{Expires: expires}
	return nil
}

func (s *MemStore) Finish(ctx context.Context, h commitment.Hash, orderID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if orderID == "" {
		return errors.New("ibkr: empty order id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return ErrNotFound
	}
	if !r.InFlight() && r.OrderID != orderID {
		return errors.New("ibkr: commitment already finished with another order id")
	}
	r.OrderID = orderID
	s.m[h] = r
	return nil
}

func (s *MemStore) Get(ctx context.Context, h commitment.Hash) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[h]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}
