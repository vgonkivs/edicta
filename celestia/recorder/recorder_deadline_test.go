package recorder_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// expiring is a context that reports DeadlineExceeded once fire is called,
// so a deadline can hit at an exact point without waiting for the clock.
type expiring struct {
	context.Context
	cancel context.CancelFunc
	fired  atomic.Bool
}

func newExpiring() *expiring {
	c, cancel := context.WithCancel(bg)
	return &expiring{Context: c, cancel: cancel}
}

func (c *expiring) Err() error {
	if c.fired.Load() {
		return context.DeadlineExceeded
	}
	return c.Context.Err()
}

func (c *expiring) fire() { c.fired.Store(true); c.cancel() }

// deadlineReader fires the deadline inside the chosen read. With notFound it
// then answers ErrNotFound, as a node that is merely behind would; otherwise
// it fails with the context error, as a real client does.
type deadlineReader struct {
	node.Reader
	ctx      *expiring
	onHeader bool
	onBlob   bool
	notFound bool
}

func (r *deadlineReader) trip(ctx context.Context) error {
	r.ctx.fire()
	if r.notFound {
		return node.ErrNotFound
	}
	<-ctx.Done()
	return ctx.Err()
}

func (r *deadlineReader) HeaderAt(ctx context.Context, h uint64) (node.Header, error) {
	if r.onHeader {
		return node.Header{}, r.trip(ctx)
	}
	return r.Reader.HeaderAt(ctx, h)
}

func (r *deadlineReader) Blob(ctx context.Context, h uint64, n, c []byte) (node.Blob, error) {
	if r.onBlob {
		return node.Blob{}, r.trip(ctx)
	}
	return r.Reader.Blob(ctx, h, n, c)
}

func TestDeadlineDuringReadBackIsNodeUnavailable(t *testing.T) {
	cases := map[string]struct {
		onHeader, onBlob, notFound bool
	}{
		"header read fails with the deadline": {onHeader: true},
		"header read behind, deadline passed": {onHeader: true, notFound: true},
		"blob read fails with the deadline":   {onBlob: true},
		"blob read behind, deadline passed":   {onBlob: true, notFound: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			ctx := newExpiring()
			rd := &deadlineReader{Reader: ch, ctx: ctx, onHeader: c.onHeader, onBlob: c.onBlob, notFound: c.notFound}
			rec := mk(t, cfg(), sub, rd)
			_, err := rec.Publish(ctx, []byte("deadline in read-back"))
			require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
			assert.ErrorIs(t, err, context.DeadlineExceeded, "the cause stays visible")
			assert.Equal(t, 1, sub.Calls)
		})
	}
}

func TestDeadlineDuringScanIsNodeUnavailable(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.ErrAfterLand = errBoom, true
	ctx := newExpiring()
	rd := &deadlineReader{Reader: ch, ctx: ctx}
	rec := mk(t, cfg(), sub, rd)
	blob := []byte("deadline in scan")
	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	rd.onBlob = true
	sub.Err = nil
	_, err = rec.Publish(ctx, blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, 1, sub.Calls, "a scan never resubmits")
}

func TestDeadlineDuringReadBackAfterScanHitIsNodeUnavailable(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.ErrAfterLand = errBoom, true
	ctx := newExpiring()
	rd := &deadlineReader{Reader: ch, ctx: ctx}
	rec := mk(t, cfg(), sub, rd)
	blob := []byte("deadline after scan hit")
	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	rd.onHeader = true
	sub.Err = nil
	_, err = rec.Publish(ctx, blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.Equal(t, 1, sub.Calls)
}
