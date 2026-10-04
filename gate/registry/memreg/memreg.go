// Package memreg is an in-memory registry for tests and development. It has
// no durability.
package memreg

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

type Registry struct {
	mu      sync.Mutex
	claimed bool
	entries map[registry.Key]registry.Entry
	meta    registry.Meta
}

var _ registry.Registry = (*Registry)(nil)

// New creates an empty registry whose creation time is epoch.
func New(epoch uint64) (*Registry, error) {
	if epoch == 0 {
		return nil, errors.New("memreg: epoch must be set")
	}
	return &Registry{
		entries: make(map[registry.Key]registry.Entry),
		meta:    registry.Meta{Epoch: epoch, Watermark: epoch},
	}, nil
}

// Claim marks the registry as owned by one gate.
func (r *Registry) Claim() (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed {
		return nil, registry.ErrInUse
	}
	r.claimed = true
	return func() {
		r.mu.Lock()
		r.claimed = false
		r.mu.Unlock()
	}, nil
}

func (r *Registry) Consume(_ context.Context, e registry.Entry, tolerance uint64) error {
	if err := registry.CheckConsume(e); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.entries[e.Key]; ok {
		return &registry.ExistsError{Existing: old.Clone()}
	}
	if e.ValidUntil < r.meta.PruneCutoff {
		return fmt.Errorf("%w: valid_until %d, cutoff %d", registry.ErrPrunedWindow, e.ValidUntil, r.meta.PruneCutoff)
	}
	if registry.BelowWatermark(e.AuthorizedAt, tolerance, r.meta.Watermark) {
		return fmt.Errorf("%w: authorized_at %d, watermark %d", registry.ErrBelowWatermark, e.AuthorizedAt, r.meta.Watermark)
	}
	e.Receipt = nil
	r.entries[e.Key] = e.Clone()
	r.meta.Watermark = max(r.meta.Watermark, e.AuthorizedAt)
	return nil
}

func (r *Registry) Get(_ context.Context, k registry.Key) (registry.Entry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[k]
	if !ok {
		return registry.Entry{}, registry.ErrNotFound
	}
	return e.Clone(), nil
}

func (r *Registry) AttachReceipt(_ context.Context, k registry.Key, h commitment.Hash, receipt []byte) error {
	if len(receipt) == 0 {
		return fmt.Errorf("%w: empty receipt", registry.ErrInvalidEntry)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[k]
	if !ok {
		return registry.ErrNotFound
	}
	if e.CommitmentHash != h {
		return fmt.Errorf("%w: the entry holds another commitment", registry.ErrStateConflict)
	}
	if e.Receipt != nil {
		return fmt.Errorf("%w: receipt already attached", registry.ErrStateConflict)
	}
	e.Receipt = append([]byte(nil), receipt...)
	r.entries[k] = e
	return nil
}

func (r *Registry) Meta(_ context.Context) (registry.Meta, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.meta, nil
}

func (r *Registry) Prune(_ context.Context, cutoff uint64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.meta.PruneCutoff = max(r.meta.PruneCutoff, cutoff)
	n := 0
	for k, e := range r.entries {
		if registry.Prunable(e, cutoff) {
			delete(r.entries, k)
			n++
		}
	}
	return n, nil
}
