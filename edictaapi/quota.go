package edictaapi

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/gate"
)

// Quota is the per-agent publish quota (rule PR7). Allow returns an error
// matching ErrQuotaExceeded when the blob does not fit; it consumes nothing in
// that case. An error may also implement RetryAfter() time.Duration, which the
// handler reports in the Retry-After header.
type Quota interface {
	Allow(ctx context.Context, agentID string, blobBytes uint64) error
}

// QuotaConfig sets the limits of NewQuota per agent_id. A zero limit allows
// nothing (fail closed), so a missing configuration cannot spend fees.
type QuotaConfig struct {
	BlobsPerHour uint64
	BytesPerDay  uint64
}

type quotaError struct{ after time.Duration }

func (e *quotaError) Error() string             { return ErrQuotaExceeded.Error() }
func (e *quotaError) Unwrap() error             { return ErrQuotaExceeded }
func (e *quotaError) RetryAfter() time.Duration { return e.after }

type bucket struct {
	capacity float64
	tokens   float64
	period   time.Duration
	last     time.Time
}

func newBucket(capacity uint64, period time.Duration, now time.Time) *bucket {
	c := float64(capacity)
	return &bucket{capacity: c, tokens: c, period: period, last: now}
}

func (b *bucket) refill(now time.Time) {
	el := now.Sub(b.last)
	b.last = now
	switch {
	case el <= 0:
	case el >= b.period:
		b.tokens = b.capacity
	default:
		b.tokens = math.Min(b.capacity, b.tokens+b.capacity*float64(el)/float64(b.period))
	}
}

const quotaEps = 1e-9

func (b *bucket) fits(need float64) bool { return need <= b.tokens+quotaEps }

// wait is how long until need tokens are available; a request larger than the
// capacity never fits and reports one period.
func (b *bucket) wait(need float64) time.Duration {
	if b.fits(need) {
		return 0
	}
	if need > b.capacity+quotaEps {
		return b.period
	}
	return time.Duration((need - b.tokens) / b.capacity * float64(b.period))
}

type agentBuckets struct{ blobs, bytes *bucket }

type quota struct {
	cfg   QuotaConfig
	clock gate.Clock
	mu    sync.Mutex
	m     map[string]*agentBuckets
}

// NewQuota returns in-memory token buckets per agent_id: BlobsPerHour blobs and
// BytesPerDay bytes, refilled continuously. A restart resets them (accepted
// for v0). It is safe for concurrent use. A nil clock means the system clock.
func NewQuota(cfg QuotaConfig, clock gate.Clock) Quota {
	if clock == nil {
		clock = systemClock{}
	}
	return &quota{cfg: cfg, clock: clock, m: make(map[string]*agentBuckets)}
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (q *quota) Allow(_ context.Context, agentID string, blobBytes uint64) error {
	now := q.clock.Now()
	q.mu.Lock()
	defer q.mu.Unlock()
	a := q.m[agentID]
	if a == nil {
		a = &agentBuckets{
			blobs: newBucket(q.cfg.BlobsPerHour, time.Hour, now),
			bytes: newBucket(q.cfg.BytesPerDay, 24*time.Hour, now),
		}
		q.m[agentID] = a
	}
	a.blobs.refill(now)
	a.bytes.refill(now)
	nb := float64(blobBytes)
	if a.blobs.fits(1) && a.bytes.fits(nb) {
		a.blobs.tokens -= 1
		a.bytes.tokens = math.Max(0, a.bytes.tokens-nb)
		return nil
	}
	after := max(a.blobs.wait(1), a.bytes.wait(nb))
	return &quotaError{after: after}
}

// retryAfter extracts the advised wait of a quota error, rounded up to whole
// seconds; the default is 60 s.
func retryAfter(err error) time.Duration {
	var ra interface{ RetryAfter() time.Duration }
	if errors.As(err, &ra) {
		if d := ra.RetryAfter(); d > 0 {
			return d
		}
	}
	return 60 * time.Second
}
