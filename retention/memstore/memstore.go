// Package memstore is an in-memory retention.Store.
package memstore

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/vgonkivs/edicta/retention"
)

type Store struct {
	mu    sync.Mutex
	chain string
	top   uint64
	runs  []retention.Run
	bound bool
}

var _ retention.Store = (*Store)(nil)

func New() *Store { return &Store{} }

func (s *Store) Bind(_ context.Context, chainID string) error {
	if chainID == "" {
		return fmt.Errorf("%w: empty chain id", retention.ErrChainMismatch)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound && s.chain != chainID {
		return fmt.Errorf("%w: bound to %q, asked for %q", retention.ErrChainMismatch, s.chain, chainID)
	}
	s.chain, s.bound = chainID, true
	return nil
}

func (s *Store) Last(_ context.Context) (retention.Run, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.runs) == 0 {
		return retention.Run{}, false, nil
	}
	return s.runs[len(s.runs)-1], true, nil
}

func (s *Store) Append(_ context.Context, smp retention.Sample, p retention.Policy) error {
	if err := smp.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.bound {
		return fmt.Errorf("%w: store is not bound", retention.ErrChainMismatch)
	}
	if smp.ChainID != "" && smp.ChainID != s.chain {
		return fmt.Errorf("%w: bound to %q, sample from %q", retention.ErrChainMismatch, s.chain, smp.ChainID)
	}
	var last retention.Run
	have := len(s.runs) > 0
	if have {
		last = s.runs[len(s.runs)-1]
	}
	run, appendNew := retention.Plan(last, have, s.top, smp, p)
	if appendNew {
		s.runs = append(s.runs, run)
		s.top = max(s.top, run.Segment)
		return nil
	}
	s.runs[len(s.runs)-1] = run
	return nil
}

func (s *Store) Segment(_ context.Context, height uint64) ([]retention.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return retention.Covering(s.runs, height), nil
}

func (s *Store) Prune(_ context.Context, before uint64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.runs) == 0 {
		return 0, nil
	}
	n := len(s.runs)
	newest := s.runs[n-1].Segment
	s.runs = slices.DeleteFunc(s.runs, func(r retention.Run) bool { return r.Segment != newest && r.LastAt < before })
	return n - len(s.runs), nil
}
