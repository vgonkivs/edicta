package recorder_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// safety bounds a wait that must be released by an event; it is never what a
// test measures.
const safety = 10 * time.Second

func waitDone(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(safety):
		require.FailNow(t, "not cancelled", what)
	}
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestFibreUploadsOutliveThePublishCallUntilTheDrainEnds(t *testing.T) {
	t.Run("the upload context is detached from the caller", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.ok(f.l.Height)
		rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))

		ctx, cancel := context.WithCancel(bg)
		_, err := rec.Publish(ctx, f.blob)
		require.NoError(t, err)
		cancel()

		uctx := f.sub.UploadCtx(1)
		require.NoError(t, uctx.Err(), "shard uploads continue after Publish returns and the caller is gone")

		_ = rec.Close(cancelled())
		waitDone(t, uctx, "Close ends the draining upload")
	})
	t.Run("the upload context ends after UploadDrain", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.ok(f.l.Height)
		c := f.cfg(f.openArchive(t.TempDir()))
		c.UploadDrain = 30 * time.Millisecond
		rec := f.newRec(c)

		_, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)
		waitDone(t, f.sub.UploadCtx(1), "UploadDrain")
	})
	t.Run("a failed submit drains too", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.fail(errBoom)
		c := f.cfg(f.openArchive(t.TempDir()))
		c.UploadDrain = 30 * time.Millisecond
		rec := f.newRec(c)

		_, err := rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		waitDone(t, f.sub.UploadCtx(1), "UploadDrain after an error")
	})
}

func TestFibreBlockedSubmitEnds(t *testing.T) {
	t.Run("SubmitTimeout", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = func(int, []byte, []byte) nodefake.SubmitPlan {
			return nodefake.SubmitPlan{Block: make(chan struct{})}
		}
		c := f.cfg(f.openArchive(t.TempDir()))
		c.SubmitTimeout = 30 * time.Millisecond
		rec := f.newRec(c)

		_, err := rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		assert.Equal(t, 1, f.sub.Calls())
		waitDone(t, f.sub.UploadCtx(1), "the timed out submit")
	})
	t.Run("the caller cancels", func(t *testing.T) {
		f := newFibreFx(t)
		entered := make(chan struct{})
		f.sub.Plan = func(int, []byte, []byte) nodefake.SubmitPlan {
			close(entered)
			return nodefake.SubmitPlan{Block: make(chan struct{})}
		}
		rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))
		ctx, cancel := context.WithCancel(bg)
		done := make(chan error, 1)
		go func() { _, err := rec.Publish(ctx, f.blob); done <- err }()
		<-entered
		cancel()

		select {
		case err := <-done:
			require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		case <-time.After(safety):
			require.FailNow(t, "Publish did not return after the caller cancelled")
		}
		waitDone(t, f.sub.UploadCtx(1), "the cancelled submit")
		assert.Equal(t, 1, f.sub.Calls())
	})
}

func TestFibreDrainSlotsAreBounded(t *testing.T) {
	other := []byte{1, 2, 3}

	t.Run("a publish waits for a free slot and its context ends it without a submit", func(t *testing.T) {
		f := newFibreFx(t)
		fs := newFlaky(f.openArchive(t.TempDir()))
		arrived := make(chan struct{}, 4)
		fs.onPut = func(r archive.Record) {
			if p, ok := r.(*archive.PayloadRecord); ok && len(p.Blob) == len(other) {
				arrived <- struct{}{}
			}
		}
		f.sub.Plan = f.ok(f.l.Height)
		c := f.cfg(fs)
		c.MaxDraining = 1
		rec := f.newRec(c)

		_, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)
		require.Equal(t, 1, f.sub.Calls())

		ctx, cancel := context.WithCancel(bg)
		done := make(chan error, 1)
		go func() { _, err := rec.Publish(ctx, other); done <- err }()
		<-arrived
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(safety):
			require.FailNow(t, "the waiting publish did not end with its context")
		}
		assert.Equal(t, 1, f.sub.Calls(), "no slot, no submit")
	})
	t.Run("the slot is free again once the drain ends", func(t *testing.T) {
		f := newFibreFx(t)
		var firstEnded atomic.Bool
		inner := f.ok(f.l.Height)
		f.sub.Plan = func(call int, n, d []byte) nodefake.SubmitPlan {
			if call == 2 {
				firstEnded.Store(f.sub.UploadCtx(1).Err() != nil)
				return nodefake.SubmitPlan{Err: errBoom}
			}
			return inner(call, n, d)
		}
		c := f.cfg(f.openArchive(t.TempDir()))
		c.MaxDraining = 1
		c.UploadDrain = 30 * time.Millisecond
		rec := f.newRec(c)

		_, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)
		_, err = rec.Publish(bg, other)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		assert.Equal(t, 2, f.sub.Calls())
		assert.True(t, firstEnded.Load(), "the second submit started only after the first upload drained")
	})
}

func TestFibreCloseDrainsAndRefusesNewWork(t *testing.T) {
	t.Run("waits for the drain", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.ok(f.l.Height)
		c := f.cfg(f.openArchive(t.TempDir()))
		c.UploadDrain = 30 * time.Millisecond
		rec := f.newRec(c)
		_, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(bg, safety)
		defer cancel()
		require.NoError(t, rec.Close(ctx))
		require.Error(t, f.sub.UploadCtx(1).Err(), "nothing is left uploading")

		_, err = rec.Publish(bg, []byte{1, 2, 3})
		require.Error(t, err, "a closed Recorder refuses new publishes")
		assert.Equal(t, 1, f.sub.Calls())
	})
	t.Run("cancels what is still uploading when its context ends", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.ok(f.l.Height)
		rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))
		_, err := rec.Publish(bg, f.blob)
		require.NoError(t, err)
		require.NoError(t, f.sub.UploadCtx(1).Err())

		_ = rec.Close(cancelled())
		waitDone(t, f.sub.UploadCtx(1), "Close after its context ended")
	})
}
