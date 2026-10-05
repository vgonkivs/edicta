package recorder_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/recorder"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// gated blocks its first Submit until release is closed.
type gated struct {
	*landing
	n       atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (g *gated) Submit(ctx context.Context, ns, data []byte) (recorder.SubmitResult, error) {
	if g.n.Add(1) == 1 {
		close(g.started)
		<-g.release
	}
	return g.landing.Submit(ctx, ns, data)
}

func newGated(l *landing) *gated {
	return &gated{landing: l, started: make(chan struct{}), release: make(chan struct{})}
}

func TestBlobAcrossTheTTLWhileInflightIsNotSubmittedTwice(t *testing.T) {
	ch := newChain()
	sub := newGated(newLanding(ch))
	clk := &testClock{t: t0}
	c := cfg()
	c.MaxPending = 1
	c.Now = clk.Now
	rec := mk(t, c, sub, ch)
	blob := []byte{1, 0xaa}

	first := make(chan error, 1)
	go func() { _, err := rec.Publish(bg, blob); first <- err }()
	<-sub.started

	clk.add(2 * time.Hour)
	for i := 0; i < 2; i++ {
		_, err := rec.Publish(bg, blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the first call still owns the blob")
	}
	assert.Equal(t, int32(1), sub.n.Load(), "no second Submit")

	close(sub.release)
	require.NoError(t, <-first)

	pub, err := rec.Publish(bg, blob)
	require.NoError(t, err, "the verified blob answers from the cache")
	assert.Equal(t, int32(1), sub.n.Load())
	assert.NotZero(t, pub.Ref.Height)

	// unresolved is back at zero, not drifted: with a cap of one, a single
	// unresolved blob fills it and the next new blob is refused.
	sub.landing.Err, sub.landing.NoLand = errBoom, true
	_, err = rec.Publish(bg, []byte{2, 0xaa})
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	_, err = rec.Publish(bg, []byte{3, 0xaa})
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "unresolved did not go negative")
}

func TestTTLEvictionOfAnIdleEntryCountsOnce(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	clk := &testClock{t: t0}
	c := cfg()
	c.MaxPending = 1
	c.Now = clk.Now
	rec := mk(t, c, sub, ch)
	blob := []byte{1, 0xaa}

	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	clk.add(2 * time.Hour)
	_, err = rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Equal(t, 2, sub.Calls, "after the TTL the blob is submitted again")

	_, err = rec.Publish(bg, []byte{9, 0xaa})
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "one unresolved entry, not two")
}
