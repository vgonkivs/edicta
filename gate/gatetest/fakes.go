package gatetest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
)

// Clock is a settable clock.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

var _ gate.Clock = (*Clock)(nil)

func NewClock(unix uint64) *Clock { return &Clock{now: time.Unix(int64(unix), 0)} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *Clock) Set(unix uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = time.Unix(int64(unix), 0)
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ChainParams serves the Fibre retention per height.
type ChainParams struct {
	mu       sync.Mutex
	latest   uint64
	at       map[uint64]uint64
	latestEr error
	histErr  error
}

var _ gate.ChainParams = (*ChainParams)(nil)

func NewChainParams(latest uint64) *ChainParams {
	return &ChainParams{latest: latest, at: make(map[uint64]uint64)}
}

func (p *ChainParams) SetLatest(v uint64) { p.mu.Lock(); p.latest = v; p.mu.Unlock() }

// SetAt sets the value in force at one height; other heights read the latest value.
func (p *ChainParams) SetAt(height, v uint64) { p.mu.Lock(); p.at[height] = v; p.mu.Unlock() }

// FailLatest makes the read of the latest value fail; nil clears it.
func (p *ChainParams) FailLatest(err error) { p.mu.Lock(); p.latestEr = err; p.mu.Unlock() }

// FailHistorical makes every read at a height fail; nil clears it.
func (p *ChainParams) FailHistorical(err error) { p.mu.Lock(); p.histErr = err; p.mu.Unlock() }

func (p *ChainParams) FibreRetention(_ context.Context, height uint64) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if height == 0 {
		if p.latestEr != nil {
			return 0, p.latestEr
		}
		return p.latest, nil
	}
	if p.histErr != nil {
		return 0, p.histErr
	}
	if v, ok := p.at[height]; ok {
		return v, nil
	}
	return p.latest, nil
}

// Headers serves block times.
type Headers struct {
	mu    sync.Mutex
	times map[uint64]uint64
	err   error
}

var _ gate.HeaderSource = (*Headers)(nil)

func NewHeaders() *Headers { return &Headers{times: make(map[uint64]uint64)} }

func (h *Headers) Set(height, blockTime uint64) {
	h.mu.Lock()
	h.times[height] = blockTime
	h.mu.Unlock()
}
func (h *Headers) Fail(err error) { h.mu.Lock(); h.err = err; h.mu.Unlock() }

func (h *Headers) BlockTime(_ context.Context, height uint64) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return 0, h.err
	}
	t, ok := h.times[height]
	if !ok {
		return 0, gate.ErrAnchorNotFound
	}
	return t, nil
}

func refKey(ref commitment.PayloadRef) string {
	return fmt.Sprintf("%d|%x|%x|%d|%x", ref.DA, ref.Namespace, ref.Commitment, ref.Height, ref.Signer)
}

// Anchors serves anchors by payload reference.
type Anchors struct {
	mu   sync.Mutex
	byID map[string]gate.Anchor
	err  error
}

var _ gate.AnchorSource = (*Anchors)(nil)

func NewAnchors() *Anchors { return &Anchors{byID: make(map[string]gate.Anchor)} }

func (a *Anchors) Set(ref commitment.PayloadRef, an gate.Anchor) {
	a.mu.Lock()
	a.byID[refKey(ref)] = an
	a.mu.Unlock()
}
func (a *Anchors) Fail(err error) { a.mu.Lock(); a.err = err; a.mu.Unlock() }

func (a *Anchors) FindAnchor(_ context.Context, ref commitment.PayloadRef) (gate.Anchor, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return gate.Anchor{}, a.err
	}
	an, ok := a.byID[refKey(ref)]
	if !ok {
		return gate.Anchor{}, gate.ErrAnchorNotFound
	}
	return an, nil
}

// BlobSource serves blobs by payload reference and counts fetches. Put any
// bytes to model wrong, truncated or oversized blobs.
type BlobSource struct {
	mu      sync.Mutex
	blobs   map[string][]byte
	err     error
	hang    bool
	onFetch func()
	fetches int
}

var _ gate.BlobSource = (*BlobSource)(nil)

func NewBlobSource() *BlobSource { return &BlobSource{blobs: make(map[string][]byte)} }

func (s *BlobSource) Put(ref commitment.PayloadRef, blob []byte) {
	s.mu.Lock()
	s.blobs[refKey(ref)] = append([]byte(nil), blob...)
	s.mu.Unlock()
}

// Fail makes every fetch fail with err; nil clears it.
func (s *BlobSource) Fail(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }

// Hang makes every fetch block until its context ends.
func (s *BlobSource) Hang() { s.mu.Lock(); s.hang = true; s.mu.Unlock() }

// OnFetch sets a function that runs at the start of every fetch.
func (s *BlobSource) OnFetch(f func()) { s.mu.Lock(); s.onFetch = f; s.mu.Unlock() }

func (s *BlobSource) Fetches() int { s.mu.Lock(); defer s.mu.Unlock(); return s.fetches }

func (s *BlobSource) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	s.mu.Lock()
	s.fetches++
	hook, hang, err := s.onFetch, s.hang, s.err
	blob, ok := s.blobs[refKey(ref)]
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, gate.ErrBlobNotFound
	}
	if uint64(len(blob)) > maxSize {
		blob = blob[:maxSize+1]
	}
	return append([]byte(nil), blob...), nil
}

// DACommitter accepts exactly the blobs bound to a commitment.
type DACommitter struct {
	mu    sync.Mutex
	bound map[string][]byte
}

var _ gate.DACommitter = (*DACommitter)(nil)

func NewDACommitter() *DACommitter { return &DACommitter{bound: make(map[string][]byte)} }

func (d *DACommitter) Bind(commitmentBytes, blob []byte) {
	d.mu.Lock()
	d.bound[string(commitmentBytes)] = append([]byte(nil), blob...)
	d.mu.Unlock()
}

func (d *DACommitter) Check(ref commitment.PayloadRef, blob []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if want, ok := d.bound[string(ref.Commitment)]; ok && string(want) == string(blob) {
		return nil
	}
	return gate.ErrDACommitmentMismatch
}

// Executor is a fake rail. By default every order is acknowledged with the
// reference "9876543210" and Lookup reports an unknown outcome.
type Executor struct {
	mu          sync.Mutex
	result      gate.ExecResult
	err         error
	hang        bool
	onExecute   func(context.Context, gate.ExecRequest)
	onLookup    func()
	lookupRes   gate.ExecResult
	lookupErr   error
	requests    []gate.ExecRequest
	lookupCalls int
	lookupIDs   []string
}

var _ gate.Executor = (*Executor)(nil)

func NewExecutor() *Executor {
	return &Executor{result: gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "9876543210"}}
}

// SetResult sets the result of Execute and clears a pending error.
func (e *Executor) SetResult(r gate.ExecResult) { e.mu.Lock(); e.result, e.err = r, nil; e.mu.Unlock() }

// SetError makes Execute fail; the order counts as sent.
func (e *Executor) SetError(err error) { e.mu.Lock(); e.err = err; e.mu.Unlock() }

// Hang makes Execute block until its context ends.
func (e *Executor) Hang() { e.mu.Lock(); e.hang = true; e.mu.Unlock() }

func (e *Executor) OnExecute(f func(context.Context, gate.ExecRequest)) {
	e.mu.Lock()
	e.onExecute = f
	e.mu.Unlock()
}

func (e *Executor) OnLookup(f func()) { e.mu.Lock(); e.onLookup = f; e.mu.Unlock() }

func (e *Executor) SetLookup(r gate.ExecResult, err error) {
	e.mu.Lock()
	e.lookupRes, e.lookupErr = r, err
	e.mu.Unlock()
}

// Calls is the number of Execute calls.
func (e *Executor) Calls() int { e.mu.Lock(); defer e.mu.Unlock(); return len(e.requests) }

func (e *Executor) Requests() []gate.ExecRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]gate.ExecRequest(nil), e.requests...)
}

func (e *Executor) LookupCalls() int { e.mu.Lock(); defer e.mu.Unlock(); return e.lookupCalls }

func (e *Executor) LookupIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.lookupIDs...)
}

func (e *Executor) Execute(ctx context.Context, req gate.ExecRequest) (gate.ExecResult, error) {
	e.mu.Lock()
	e.requests = append(e.requests, req)
	hook, hang, res, err := e.onExecute, e.hang, e.result, e.err
	e.mu.Unlock()
	if hook != nil {
		hook(ctx, req)
	}
	if hang {
		<-ctx.Done()
		return gate.ExecResult{}, ctx.Err()
	}
	return res, err
}

func (e *Executor) Lookup(_ context.Context, id string) (gate.ExecResult, error) {
	e.mu.Lock()
	e.lookupCalls++
	e.lookupIDs = append(e.lookupIDs, id)
	hook, res, err := e.onLookup, e.lookupRes, e.lookupErr
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	return res, err
}

// Metrics records admission events.
type Metrics struct {
	mu     sync.Mutex
	events []gate.AdmissionEvent
}

var _ gate.Metrics = (*Metrics)(nil)

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) Admission(ev gate.AdmissionEvent) {
	m.mu.Lock()
	m.events = append(m.events, ev)
	m.mu.Unlock()
}

func (m *Metrics) Events() []gate.AdmissionEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]gate.AdmissionEvent(nil), m.events...)
}

// FaultyRegistry wraps a registry and injects failures per operation. The
// operation names are Reserve, Resolve, Get, Pending, Recover, Meta, Prune.
type FaultyRegistry struct {
	inner registry.Registry

	mu     sync.Mutex
	fail   map[string]error
	before map[string]func()
}

var _ registry.Registry = (*FaultyRegistry)(nil)

func NewFaultyRegistry(inner registry.Registry) *FaultyRegistry {
	return &FaultyRegistry{inner: inner, fail: make(map[string]error), before: make(map[string]func())}
}

// FailNext makes the next call of op fail with err before it reaches the
// wrapped registry.
func (f *FaultyRegistry) FailNext(op string, err error) {
	f.mu.Lock()
	f.fail[op] = err
	f.mu.Unlock()
}

// Before runs fn once, before the next call of op reaches the wrapped
// registry. fn may call the registry again; it is cleared before it runs.
func (f *FaultyRegistry) Before(op string, fn func()) {
	f.mu.Lock()
	f.before[op] = fn
	f.mu.Unlock()
}

func (f *FaultyRegistry) enter(op string) error {
	f.mu.Lock()
	hook := f.before[op]
	delete(f.before, op)
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	err := f.fail[op]
	delete(f.fail, op)
	f.mu.Unlock()
	return err
}

// Claim passes the ownership claim through to the wrapped registry.
func (f *FaultyRegistry) Claim() (func(), error) {
	if c, ok := f.inner.(registry.Claimer); ok {
		return c.Claim()
	}
	return func() {}, nil
}

func (f *FaultyRegistry) Reserve(ctx context.Context, e registry.Entry, tolerance uint64) error {
	if err := f.enter("Reserve"); err != nil {
		return err
	}
	return f.inner.Reserve(ctx, e, tolerance)
}

func (f *FaultyRegistry) Resolve(ctx context.Context, k registry.Key, from registry.State, upd registry.Entry) error {
	if err := f.enter("Resolve"); err != nil {
		return err
	}
	return f.inner.Resolve(ctx, k, from, upd)
}

func (f *FaultyRegistry) Get(ctx context.Context, k registry.Key) (registry.Entry, error) {
	if err := f.enter("Get"); err != nil {
		return registry.Entry{}, err
	}
	return f.inner.Get(ctx, k)
}

func (f *FaultyRegistry) Pending(ctx context.Context) ([]registry.Entry, error) {
	if err := f.enter("Pending"); err != nil {
		return nil, err
	}
	return f.inner.Pending(ctx)
}

func (f *FaultyRegistry) Recover(ctx context.Context, now uint64) (int, error) {
	if err := f.enter("Recover"); err != nil {
		return 0, err
	}
	return f.inner.Recover(ctx, now)
}

func (f *FaultyRegistry) Meta(ctx context.Context) (registry.Meta, error) {
	if err := f.enter("Meta"); err != nil {
		return registry.Meta{}, err
	}
	return f.inner.Meta(ctx)
}

func (f *FaultyRegistry) Prune(ctx context.Context, cutoff uint64) (int, error) {
	if err := f.enter("Prune"); err != nil {
		return 0, err
	}
	return f.inner.Prune(ctx, cutoff)
}
