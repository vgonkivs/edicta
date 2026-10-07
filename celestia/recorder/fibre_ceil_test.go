package recorder_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// headHook is a consensus reader whose next head read, when armed, fails
// instead of answering. It records the deadline of the read it failed.
type headHook struct {
	recorder.FibreChain
	mu       sync.Mutex
	armed    bool
	low      bool
	deadline []time.Duration
	noDL     int
}

func (h *headHook) arm() {
	h.mu.Lock()
	h.armed = true
	h.mu.Unlock()
}

func (h *headHook) LatestHeight(ctx context.Context) (uint64, error) {
	h.mu.Lock()
	armed := h.armed
	h.armed = false
	h.mu.Unlock()
	if !armed {
		return h.FibreChain.LatestHeight(ctx)
	}
	if h.low {
		v, err := h.FibreChain.LatestHeight(ctx)
		return v - 1, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		h.deadline = append(h.deadline, time.Until(dl))
	} else {
		h.noDL++
	}
	return 0, errors.New("head read failed")
}

func (f *fibreFx) newRecWithHook(c recorder.FibreConfig) (*recorder.FibreRecorder, *headHook) {
	f.t.Helper()
	hook := &headHook{FibreChain: f.node}
	d := f.deps()
	d.Chain = hook
	r, err := recorder.NewFibre(c, d)
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r, hook
}

// The head read right after a submit failed, so the Recorder does not know
// how high the chain was when the upload read its promise height. The PFF
// lands close to the end of the promise window, long after the head read
// before the submit plus a settle span.
func TestFibreUnknownCeilingIsNeverReadyBeforeAHeadWasReadAfterTheAttempt(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	var hook *headHook
	late := startHead + 1200
	f.sub.Plan = seq(func(int, []byte, []byte) nodefake.SubmitPlan {
		hook.arm()
		return nodefake.SubmitPlan{Err: node.ErrUnavailable}
	}, f.ok(late+fibreSpan))
	var rec *recorder.FibreRecorder
	rec, hook = f.newRecWithHook(f.cfg(st))

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, f.sub.Calls())

	// The next head is the first one read after the attempt.
	f.grow(startHead + 900)
	for _, h := range []uint64{startHead + 900, startHead + 1100, startHead + 1100} {
		f.grow(h)
		_, err = rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "head %d", h)
		require.Equal(t, 1, f.sub.Calls(), "the window from the pre-submit head must not open a second submit")
	}

	f.grow(late)
	f.landLater(late)
	pub, err := publishUntil(t, f, rec, 6)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls(), "the late PFF is found, never paid twice")
	assert.Equal(t, late, pub.Ref.Height)
	requireVerifies(t, f, st, late)
}

// A head below the one read before the submit is as useless as a failed
// read: it says nothing about where the chain was during the attempt.
func TestFibrePostSubmitHeadBelowTheEarlierOneKeepsTheCeilingUnknown(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	var hook *headHook
	late := startHead + 1200
	f.sub.Plan = seq(func(int, []byte, []byte) nodefake.SubmitPlan {
		hook.arm()
		return nodefake.SubmitPlan{Err: node.ErrUnavailable}
	}, f.ok(late+fibreSpan))
	var rec *recorder.FibreRecorder
	rec, hook = f.newRecWithHook(f.cfg(st))
	hook.low = true

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, f.sub.Calls())

	for _, h := range []uint64{startHead + 900, startHead + 1100, startHead + 1100} {
		f.grow(h)
		_, err = rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "head %d", h)
		require.Equal(t, 1, f.sub.Calls(), "no second submit while the ceiling is unknown")
	}

	f.grow(late)
	f.landLater(late)
	pub, err := publishUntil(t, f, rec, 6)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls())
	assert.Equal(t, late, pub.Ref.Height)
}

func TestFibreUnknownCeilingStillResubmitsOnceAHeadAfterTheAttemptIsPastTheWindow(t *testing.T) {
	f := newFibreFx(t)
	var hook *headHook
	land := startHead + 900 + fibreSpan + 3
	f.sub.Plan = seq(func(int, []byte, []byte) nodefake.SubmitPlan {
		hook.arm()
		return nodefake.SubmitPlan{Err: node.ErrUnavailable}
	}, f.ok(land))
	var rec *recorder.FibreRecorder
	rec, hook = f.newRecWithHook(f.cfg(f.openArchive(t.TempDir())))

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	f.grow(startHead + 900)
	_, err = rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	f.grow(startHead + 900 + fibreSpan + 1)
	_, err = publishUntil(t, f, rec, 6)
	require.NoError(t, err)
	assert.Equal(t, 2, f.sub.Calls())
}

func TestFibrePostSubmitHeadReadIsBounded(t *testing.T) {
	f := newFibreFx(t)
	var hook *headHook
	f.sub.Plan = func(int, []byte, []byte) nodefake.SubmitPlan {
		hook.arm()
		return nodefake.SubmitPlan{Err: node.ErrUnavailable}
	}
	var rec *recorder.FibreRecorder
	rec, hook = f.newRecWithHook(f.cfg(f.openArchive(t.TempDir())))

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	_, err := rec.Publish(ctx, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	hook.mu.Lock()
	defer hook.mu.Unlock()
	assert.Zero(t, hook.noDL, "the read runs detached from the caller and must not run unbounded")
	require.Len(t, hook.deadline, 1)
	assert.Positive(t, hook.deadline[0])
	assert.LessOrEqual(t, hook.deadline[0], 30*time.Second)
}

func TestFibreMaxClockSkewIsBounded(t *testing.T) {
	good := recorder.FibreConfig{Namespace: ns, OwnNode: true}.WithDefaults()
	for _, d := range []time.Duration{time.Second, 60 * time.Second, 2 * time.Minute} {
		c := good
		c.MaxClockSkew = d
		require.NoError(t, c.ValidateBasic(), "%s", d)
	}
	for _, d := range []time.Duration{2*time.Minute + time.Nanosecond, 5 * time.Minute, time.Hour} {
		c := good
		c.MaxClockSkew = d
		require.Error(t, c.ValidateBasic(), "%s", d)
	}
	f := newFibreFx(t)
	c := f.cfg(f.openArchive(t.TempDir()))
	c.MaxClockSkew = 3 * time.Minute
	_, err := recorder.NewFibre(c, f.deps())
	require.Error(t, err)
}
