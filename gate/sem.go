package gate

import (
	"context"
	"sync"
)

// weightedSem bounds the payload bytes fetched concurrently. A request above
// the capacity is clamped to it, so it runs alone.
type weightedSem struct {
	mu      sync.Mutex
	cap     uint64
	used    uint64
	changed chan struct{}
}

func newWeightedSem(capacity uint64) *weightedSem {
	return &weightedSem{cap: capacity, changed: make(chan struct{})}
}

func (s *weightedSem) acquire(ctx context.Context, n uint64) (uint64, error) {
	n = min(n, s.cap)
	for {
		s.mu.Lock()
		if s.used+n <= s.cap {
			s.used += n
			s.mu.Unlock()
			return n, nil
		}
		ch := s.changed
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func (s *weightedSem) release(n uint64) {
	s.mu.Lock()
	s.used -= n
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}
