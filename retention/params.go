package retention

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSampleEvery = 30 * time.Second
	defaultCanaryEvery = 10 * time.Minute
)

// Params answers FibreRetention from persisted samples and, while the
// endpoint passes the height canary, from direct reads.
type Params struct {
	policy Policy
	latest LatestSource
	direct AtHeightSource
	store  Store
	clock  Clock

	// sampleMu keeps head reads and appends in the order they were taken.
	sampleMu sync.Mutex
	obsOnly  atomic.Bool
}

func NewParams(p Policy, latest LatestSource, direct AtHeightSource, st Store, clk Clock) (*Params, error) {
	if latest == nil {
		return nil, errors.New("retention: nil latest source")
	}
	if st == nil {
		return nil, errors.New("retention: nil store")
	}
	if clk == nil {
		return nil, errors.New("retention: nil clock")
	}
	pr := &Params{policy: p, latest: latest, direct: direct, store: st, clock: clk}
	pr.obsOnly.Store(true)
	return pr, nil
}

// Start binds the store to the chain, runs the canary and takes the first
// sample. A failing canary only turns direct reads off.
func (p *Params) Start(ctx context.Context) error {
	chain, err := p.latest.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("retention: chain id: %w", err)
	}
	if err := p.store.Bind(ctx, chain); err != nil {
		return err
	}
	p.Canary(ctx)
	return p.Observe(ctx)
}

// Canary re-runs the height canary and reports whether direct reads are on.
func (p *Params) Canary(ctx context.Context) bool {
	ok := false
	if p.direct != nil {
		h, err := p.direct.HonoursHeight(ctx)
		ok = err == nil && h
	}
	p.obsOnly.Store(!ok)
	return ok
}

func (p *Params) ObservationsOnly() bool { return p.obsOnly.Load() }

func (p *Params) sample(ctx context.Context) (Sample, error) {
	p.sampleMu.Lock()
	defer p.sampleMu.Unlock()
	s, err := p.latest.LatestSample(ctx)
	if err != nil {
		return Sample{}, fmt.Errorf("retention: latest sample: %w", err)
	}
	if s.FromHeight > p.policy.AssumedLagBlocks {
		s.FromHeight -= p.policy.AssumedLagBlocks
	} else {
		s.FromHeight = 0
	}
	if now := p.clock.Now().Unix(); now > 0 {
		s.ObservedAt = uint64(now)
	} else {
		s.ObservedAt = 0
	}
	if err := p.store.Append(ctx, s, p.policy); err != nil {
		return Sample{}, err
	}
	return s, nil
}

// Observe takes and persists one sample.
func (p *Params) Observe(ctx context.Context) error {
	_, err := p.sample(ctx)
	return err
}

// FibreRetention returns the latest value for height 0. For a height it
// returns the minimum of the direct read, when trusted, and the recorded
// samples, or an error; the latest value is never used for a past height.
func (p *Params) FibreRetention(ctx context.Context, height uint64) (uint64, error) {
	if height == 0 {
		s, err := p.sample(ctx)
		if err != nil {
			return 0, err
		}
		return s.RetentionS, nil
	}

	last, have, err := p.store.Last(ctx)
	if err != nil {
		return 0, err
	}
	if !have || height > last.LastFrom {
		if _, err := p.sample(ctx); errors.Is(err, ErrStoreCorrupt) || errors.Is(err, ErrChainMismatch) {
			return 0, err
		}
	}

	var (
		best  uint64
		found bool
	)
	runs, err := p.store.Segment(ctx, height)
	if err != nil {
		return 0, err
	}
	if v, err := AtHeight(runs, height); err == nil {
		best, found = v, true
	}
	if v, ok := p.directAt(ctx, height); ok && (!found || v < best) {
		best, found = v, true
	}
	if !found {
		return 0, fmt.Errorf("%w: height %d", ErrNotCovered, height)
	}
	return best, nil
}

// directAt keeps a read only if the canary passes right after it, so an
// endpoint that started ignoring heights cannot slip a value through.
func (p *Params) directAt(ctx context.Context, height uint64) (uint64, bool) {
	if p.direct == nil || p.obsOnly.Load() {
		return 0, false
	}
	v, err := p.direct.RetentionAt(ctx, height)
	ok, cerr := p.direct.HonoursHeight(ctx)
	if cerr == nil && !ok {
		p.obsOnly.Store(true)
	}
	if err != nil || cerr != nil || !ok {
		return 0, false
	}
	return v, true
}

// Run samples and re-checks the canary on a schedule until ctx ends. It
// stops early only when the store is unusable.
func (p *Params) Run(ctx context.Context, sample, canary time.Duration) error {
	if sample <= 0 {
		sample = defaultSampleEvery
	}
	if canary <= 0 {
		canary = defaultCanaryEvery
	}
	st, ct := time.NewTicker(sample), time.NewTicker(canary)
	defer st.Stop()
	defer ct.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ct.C:
			p.Canary(ctx)
		case <-st.C:
			if err := p.Observe(ctx); errors.Is(err, ErrStoreCorrupt) || errors.Is(err, ErrChainMismatch) {
				return err
			}
		}
	}
}
