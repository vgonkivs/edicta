// Package retentionfix holds the fakes and builders shared by the retention
// tests.
package retentionfix

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/retention"
)

var ErrExhausted = errors.New("retentionfix: script exhausted")

var Policy = retention.Policy{MaxGapBlocks: 100, MaxGapS: 300, KeepS: 8 * 24 * 3600}

// S builds a sample.
func S(from, to, retentionS, at uint64) retention.Sample {
	return retention.Sample{FromHeight: from, ToHeight: to, RetentionS: retentionS, ObservedAt: at}
}

type Clock struct {
	mu  sync.Mutex
	now int64
}

func NewClock(unix int64) *Clock { return &Clock{now: unix} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Unix(c.now, 0)
}

func (c *Clock) Set(unix int64) {
	c.mu.Lock()
	c.now = unix
	c.mu.Unlock()
}

func (c *Clock) Advance(s int64) {
	c.mu.Lock()
	c.now += s
	c.mu.Unlock()
}

// Step is one scripted answer of the latest source.
type Step struct {
	Sample retention.Sample
	Err    error
}

// Latest is a scripted LatestSource. The caller fills ObservedAt, so the
// scripted value is ignored there.
type Latest struct {
	mu      sync.Mutex
	Chain   string
	ChainEr error
	steps   []Step
	Fn      func(call int) (retention.Sample, error)
	calls   int
}

func NewLatest(chain string, steps ...Step) *Latest { return &Latest{Chain: chain, steps: steps} }

func Ok(s retention.Sample) Step { return Step{Sample: s} }

func (l *Latest) ChainID(context.Context) (string, error) { return l.Chain, l.ChainEr }

func (l *Latest) LatestSample(context.Context) (retention.Sample, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.calls
	l.calls++
	if l.Fn != nil {
		return l.Fn(n)
	}
	if n >= len(l.steps) {
		return retention.Sample{}, ErrExhausted
	}
	return l.steps[n].Sample, l.steps[n].Err
}

func (l *Latest) Calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// Direct is a scripted AtHeightSource. Canary answers are consumed in order
// and the last one repeats.
type Direct struct {
	mu        sync.Mutex
	Canary    []bool
	CanaryErr error
	At        func(h uint64) (uint64, error)
	reads     int
	canaries  int
}

func (d *Direct) RetentionAt(_ context.Context, h uint64) (uint64, error) {
	d.mu.Lock()
	d.reads++
	d.mu.Unlock()
	return d.At(h)
}

func (d *Direct) HonoursHeight(context.Context) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	i := d.canaries
	d.canaries++
	if d.CanaryErr != nil {
		return false, d.CanaryErr
	}
	if len(d.Canary) == 0 {
		return false, nil
	}
	return d.Canary[min(i, len(d.Canary)-1)], nil
}

func (d *Direct) Reads() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reads
}

func (d *Direct) Canaries() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.canaries
}

// Const answers every height with v.
func Const(v uint64) func(uint64) (uint64, error) {
	return func(uint64) (uint64, error) { return v, nil }
}

// Ticking is a latest source whose head moves by step blocks per call
// starting at base; the value of call n is vals(n). Samples are points
// (From == To), so a run covers exactly what its samples span.
func Ticking(chain string, base, step uint64, vals func(call int) uint64) *Latest {
	l := NewLatest(chain)
	l.Fn = func(n int) (retention.Sample, error) {
		h := base + step*uint64(n)
		return retention.Sample{FromHeight: h, ToHeight: h, RetentionS: vals(n)}, nil
	}
	return l
}
