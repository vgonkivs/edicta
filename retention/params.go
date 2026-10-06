package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSampleEvery = 30 * time.Second
	defaultCanaryEvery = 10 * time.Minute
	pruneEvery         = time.Hour
)

// Params answers FibreRetention from persisted samples and, while the
// endpoint passes the height canary, from direct reads.
type Params struct {
	policy Policy
	latest LatestSource
	direct AtHeightSource
	store  Store
	clock  Clock
	log    *slog.Logger

	// lock keeps head reads and appends in the order they were taken; a
	// channel so a waiter can give up with its context.
	lock    chan struct{}
	obsOnly atomic.Bool

	mu      sync.Mutex
	chain   string
	cached  cachedSample
	hasSamp bool
}

// cachedSample is the newest sample with the outcome of persisting it.
type cachedSample struct {
	s       Sample
	persist error
	at      time.Time
}

// Option configures optional parts of Params.
type Option func(*Params)

// WithLogger sets where mode switches are reported; the default is
// slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(p *Params) {
		if l != nil {
			p.log = l
		}
	}
}

func NewParams(p Policy, latest LatestSource, direct AtHeightSource, st Store, clk Clock, opts ...Option) (*Params, error) {
	if latest == nil {
		return nil, errors.New("retention: nil latest source")
	}
	if st == nil {
		return nil, errors.New("retention: nil store")
	}
	if clk == nil {
		return nil, errors.New("retention: nil clock")
	}
	p, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	pr := &Params{policy: p, latest: latest, direct: direct, store: st, clock: clk, log: slog.Default(), lock: make(chan struct{}, 1)}
	for _, o := range opts {
		o(pr)
	}
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
	p.mu.Lock()
	p.chain = chain
	p.mu.Unlock()
	p.canary(ctx, true)
	return p.Observe(ctx)
}

// Canary re-runs the height canary and reports whether direct reads are on.
func (p *Params) Canary(ctx context.Context) bool { return p.canary(ctx, false) }

func (p *Params) canary(ctx context.Context, startup bool) bool {
	var reason error
	switch {
	case p.direct == nil:
		reason = errors.New("no direct at-height source")
	default:
		h, err := p.direct.HonoursHeight(ctx)
		switch {
		case err != nil:
			reason = fmt.Errorf("canary inconclusive: %w", err)
		case !h:
			reason = errors.New("endpoint ignores heights")
		}
	}
	p.setMode(reason, startup)
	return reason == nil
}

// setMode records the mode and logs a switch, or the mode itself at startup.
func (p *Params) setMode(reason error, force bool) {
	obs := reason != nil
	changed := p.obsOnly.Swap(obs) != obs
	switch {
	case obs && (changed || force):
		p.log.Warn("retention: observations-only mode", "reason", reason)
	case !obs && (changed || force):
		p.log.Info("retention: direct at-height reads on")
	}
}

func (p *Params) ObservationsOnly() bool { return p.obsOnly.Load() }

func (p *Params) acquire(ctx context.Context) error {
	select {
	case p.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Params) release() { <-p.lock }

func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint64(0)
}

// fresh returns the cached sample if it is younger than MaxSampleAge.
func (p *Params) fresh() (cachedSample, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasSamp {
		return cachedSample{}, false
	}
	age := p.clock.Now().Sub(p.cached.at)
	return p.cached, age >= 0 && age < time.Duration(p.policy.MaxSampleAge)*time.Second
}

// sample reads and persists one sample. readErr means no usable value was
// read; persistErr means the value was read but not recorded. With reuse a
// sample younger than MaxSampleAge is returned instead of a new read.
func (p *Params) sample(ctx context.Context, reuse bool) (s Sample, persistErr, readErr error) {
	if reuse {
		if c, ok := p.fresh(); ok {
			return c.s, c.persist, nil
		}
	}
	if err := p.acquire(ctx); err != nil {
		return Sample{}, nil, fmt.Errorf("retention: waiting to sample: %w", err)
	}
	defer p.release()
	if reuse {
		if c, ok := p.fresh(); ok {
			return c.s, c.persist, nil
		}
	}

	s, err := p.latest.LatestSample(ctx)
	if err != nil {
		return Sample{}, nil, fmt.Errorf("retention: latest sample: %w", err)
	}
	if s.FromHeight > p.policy.AssumedLagBlocks {
		s.FromHeight -= p.policy.AssumedLagBlocks
	} else {
		s.FromHeight = 0
	}
	p.mu.Lock()
	bound := p.chain
	p.mu.Unlock()
	if bound != "" && s.ChainID != bound {
		return Sample{}, nil, fmt.Errorf("%w: endpoint reports %q, bound to %q", ErrChainMismatch, s.ChainID, bound)
	}
	s.ToHeight = satAdd(s.ToHeight, p.policy.AssumedLagBlocks)
	if err := s.Validate(); err != nil {
		return Sample{}, nil, err
	}
	now := p.clock.Now()
	if u := now.Unix(); u > 0 {
		s.ObservedAt = uint64(u)
	} else {
		s.ObservedAt = 0
	}
	persistErr = p.store.Append(ctx, s, p.policy)
	p.mu.Lock()
	p.cached, p.hasSamp = cachedSample{s: s, persist: persistErr, at: now}, true
	p.mu.Unlock()
	return s, persistErr, nil
}

// Observe takes and persists one sample.
func (p *Params) Observe(ctx context.Context) error {
	_, persistErr, readErr := p.sample(ctx, false)
	return errors.Join(readErr, persistErr)
}

// FibreRetention returns the latest value for height 0, even when recording
// it failed: only reads at a height depend on the store. For a height it
// returns the minimum of the direct read, when trusted, and the recorded
// samples, or an error; the latest value is never used for a past height.
func (p *Params) FibreRetention(ctx context.Context, height uint64) (uint64, error) {
	if height == 0 {
		s, persistErr, err := p.sample(ctx, true)
		if err != nil {
			return 0, err
		}
		if persistErr != nil {
			p.log.Warn("retention: latest sample not recorded", "err", persistErr)
		}
		return s.RetentionS, nil
	}

	last, have, err := p.store.Last(ctx)
	if err != nil {
		return 0, err
	}
	if !have || height > last.LastFrom {
		_, persistErr, readErr := p.sample(ctx, false)
		for _, e := range []error{readErr, persistErr} {
			if errors.Is(e, ErrStoreCorrupt) || errors.Is(e, ErrChainMismatch) {
				return 0, e
			}
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
		p.setMode(errors.New("endpoint ignores heights"), false)
	}
	if err != nil || cerr != nil || !ok {
		return 0, false
	}
	return v, true
}

// Run samples, re-checks the canary and prunes on a schedule until ctx ends.
// Each step is bounded by the sample timeout. It stops early only when the
// store is unusable.
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
	var lastPrune time.Time
	fatal := func(err error) bool {
		return errors.Is(err, ErrStoreCorrupt) || errors.Is(err, ErrChainMismatch)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ct.C:
			sctx, cancel := context.WithTimeout(ctx, p.policy.SampleTimeout)
			p.Canary(sctx)
			cancel()
		case <-st.C:
			sctx, cancel := context.WithTimeout(ctx, p.policy.SampleTimeout)
			err := p.Observe(sctx)
			cancel()
			if fatal(err) {
				return err
			}
			if lastPrune.IsZero() || time.Since(lastPrune) >= pruneEvery {
				lastPrune = time.Now()
				pctx, cancel := context.WithTimeout(ctx, p.policy.SampleTimeout)
				err := p.prune(pctx)
				cancel()
				if fatal(err) {
					return err
				}
			}
		}
	}
}

func (p *Params) prune(ctx context.Context) error {
	now := p.clock.Now().Unix()
	if now <= 0 || uint64(now) <= p.policy.KeepS {
		return nil
	}
	_, err := p.store.Prune(ctx, uint64(now)-p.policy.KeepS)
	if err != nil {
		p.log.Warn("retention: prune failed", "err", err)
	}
	return err
}
