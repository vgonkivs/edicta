package recorder_test

import (
	"context"
	"errors"
	"testing"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/commitment"
)

func requireVerifies(t *testing.T, f *fibreFx, st archive.Store, height uint64) {
	t.Helper()
	ev, err := st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
	require.NoError(t, err)
	assert.Equal(t, height, ev.Height)
	ref := f.l.Ref
	ref.Height = height
	_, err = anchorverify.Fibre().VerifyAnchor(ref, ev)
	require.NoError(t, err)
}

func TestFibreCrashBeforeSubmitWaitsOutTheWindow(t *testing.T) {
	f := newFibreFx(t)
	dir := t.TempDir()
	f.diedAfterPayload(f.openArchive(dir))

	f.grow(startHead + 400)
	end := startHead + 400 + fibreSpan
	land := end + 3
	f.sub.Plan = f.ok(land)
	st := f.openArchive(dir)
	rec := f.newRec(f.cfg(st))

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "an earlier process may have submitted")
	assert.Zero(t, f.sub.Calls())

	f.grow(end)
	_, err = rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the head at the end of the window is inside it")
	assert.Zero(t, f.sub.Calls())

	f.grow(end + 1)
	pub, err := publishUntil(t, f, rec, 5)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls())
	assert.Equal(t, land, pub.Ref.Height)
	requireVerifies(t, f, st, land)
}

func TestFibreCrashAfterSubmitBeforeReadBackNeverPaysTwice(t *testing.T) {
	t.Run("same process", func(t *testing.T) {
		f := newFibreFx(t)
		f.sub.Plan = f.failAfterLand(startHead+5, context.DeadlineExceeded)
		st := f.openArchive(t.TempDir())
		rec := f.newRec(f.cfg(st))

		_, err := rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.Equal(t, 1, f.sub.Calls())

		pub, err := publishUntil(t, f, rec, 5)
		require.NoError(t, err)
		assert.Equal(t, 1, f.sub.Calls(), "the landed PayForFibre is found, not paid for again")
		assert.Equal(t, startHead+5, pub.Ref.Height)
		requireVerifies(t, f, st, startHead+5)
	})
	t.Run("after a restart", func(t *testing.T) {
		f := newFibreFx(t)
		dir := t.TempDir()
		f.sub.Plan = f.failAfterLand(startHead+5, context.DeadlineExceeded)
		_, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.Equal(t, 1, f.sub.Calls())

		st := f.openArchive(dir)
		pub, err := publishUntil(t, f, f.newRec(f.cfg(st)), 5)
		require.NoError(t, err)
		assert.Equal(t, 1, f.sub.Calls())
		assert.Equal(t, startHead+5, pub.Ref.Height)
		requireVerifies(t, f, st, startHead+5)
	})
}

func TestFibreFailedSubmitResubmitsOnlyAfterTheWindow(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(c *recorder.FibreConfig)
		// land is where the second submit puts its PayForFibre.
		land uint64
		// run follows the first, failed, submit.
		run func(t *testing.T, f *fibreFx, rec *recorder.FibreRecorder)
	}{
		{
			name: "the window comes from the chain parameter",
			land: startHead + fibreSpan + 3,
			run: func(t *testing.T, f *fibreFx, rec *recorder.FibreRecorder) {
				end := startHead + fibreSpan
				for _, h := range []uint64{startHead, end} {
					f.grow(h)
					_, err := rec.Publish(bg, f.blob)
					require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "head %d", h)
					require.Equal(t, 1, f.sub.Calls())
				}
				f.grow(end + 1)
				pub, err := publishUntil(t, f, rec, 5)
				require.NoError(t, err)
				assert.Equal(t, 2, f.sub.Calls())
				assert.Equal(t, end+3, pub.Ref.Height)
			},
		},
		{
			name: "a raised window widens the end and a lowered one never narrows it",
			land: startHead + 1569,
			run: func(t *testing.T, f *fibreFx, rec *recorder.FibreRecorder) {
				f.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: 1500})
				_, err := rec.Publish(bg, f.blob)
				require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

				f.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: 50})
				for _, h := range []uint64{startHead + fibreSpan + 1, startHead + 1566} {
					f.grow(h)
					_, err = rec.Publish(bg, f.blob)
					require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "head %d", h)
					require.Equal(t, 1, f.sub.Calls())
				}
				f.grow(startHead + 1567)
				pub, err := publishUntil(t, f, rec, 5)
				require.NoError(t, err)
				assert.Equal(t, 2, f.sub.Calls())
				assert.Equal(t, startHead+1569, pub.Ref.Height)
			},
		},
		{
			name: "settle blocks above the chain window win",
			cfg:  func(c *recorder.FibreConfig) { c.SettleBlocks = 1500 },
			land: startHead + 1504,
			run: func(t *testing.T, f *fibreFx, rec *recorder.FibreRecorder) {
				for _, h := range []uint64{startHead, startHead + fibreSpan + 1, startHead + 1500} {
					f.grow(h)
					_, err := rec.Publish(bg, f.blob)
					require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "head %d", h)
					require.Equal(t, 1, f.sub.Calls())
				}
				f.grow(startHead + 1501)
				_, err := publishUntil(t, f, rec, 5)
				require.NoError(t, err)
				assert.Equal(t, 2, f.sub.Calls())
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFibreFx(t)
			c := f.cfg(f.openArchive(t.TempDir()))
			if tc.cfg != nil {
				tc.cfg(&c)
			}
			f.sub.Plan = seq(f.fail(node.ErrUnavailable), f.ok(tc.land))
			rec := f.newRec(c)

			_, err := rec.Publish(bg, f.blob)
			require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
			require.Equal(t, 1, f.sub.Calls())
			tc.run(t, f, rec)
		})
	}
}

func TestFibreNodeStateThatCannotBoundTheWindowSubmitsNothing(t *testing.T) {
	t.Run("head behind the archived intent", func(t *testing.T) {
		f := newFibreFx(t)
		dir := t.TempDir()
		f.diedAfterPayload(f.openArchive(dir))
		f.lag(startHead - 10)
		f.sub.Plan = f.ok(startHead + 5)
		_, err := f.newRec(f.cfg(f.openArchive(dir))).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
		assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
		assert.Zero(t, f.sub.Calls())
	})
	t.Run("head goes backwards", func(t *testing.T) {
		f := newFibreFx(t)
		dir := t.TempDir()
		f.diedAfterPayload(f.openArchive(dir))
		f.grow(startHead + 10)
		f.sub.Plan = f.ok(startHead + 5)
		rec := f.newRec(f.cfg(f.openArchive(dir)))
		_, err := rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

		f.lag(startHead + 5)
		_, err = rec.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable, "another or lagging node")
		assert.Zero(t, f.sub.Calls())
	})
	t.Run("no promise height window reported", func(t *testing.T) {
		f := newFibreFx(t)
		dir := t.TempDir()
		f.diedAfterPayload(f.openArchive(dir))
		f.node.SetFibreParams(node.FibreParams{RetentionS: 14400})
		f.grow(startHead + 10)
		f.sub.Plan = f.ok(startHead + 5)
		_, err := publishUntil(t, f, f.newRec(f.cfg(f.openArchive(dir))), 3)
		require.Error(t, err)
		assert.Zero(t, f.sub.Calls(), "without the chain's bound the Recorder cannot know the window")
	})
}

func TestFibreFailedPFFLeavesTheWindowOpen(t *testing.T) {
	f := newFibreFx(t)
	dir := t.TempDir()
	f.diedAfterPayload(f.openArchive(dir))
	failed := f.pff(startHead + 10)
	failed.Code = 5
	f.grow(startHead + 10)
	f.node.Land(*failed)

	end := startHead + 10 + fibreSpan
	land := end + 3
	f.sub.Plan = f.ok(land)
	st := f.openArchive(dir)
	rec := f.newRec(f.cfg(st))

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "a failed PayForFibre is no anchor")
	assert.NotErrorIs(t, err, recorder.ErrAnchorRejected)
	assert.Zero(t, f.sub.Calls())

	f.grow(end + 1)
	pub, err := publishUntil(t, f, rec, 5)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls())
	assert.Equal(t, land, pub.Ref.Height)
	requireVerifies(t, f, st, land)
}

func TestFibreCertificateFailureIsStickyAndNeverResubmitted(t *testing.T) {
	f := newFibreFx(t)
	bad := fibrefix.MutateTx(t, f.l.PFFTx, func(m *fibretypes.MsgPayForFibre) {
		m.ValidatorSignatures[1] = append([]byte(nil), m.ValidatorSignatures[1]...)
		m.ValidatorSignatures[1][0] ^= 1
	})
	blk := fibrefix.BuildBlock(t, bad)
	land := startHead + 4
	landed := f.pff(land)
	landed.Tx, landed.Block = bad, blk
	landed.Header.DataHash = append([]byte(nil), blk.DataHash...)
	f.sub.Plan = func(_ int, n, d []byte) nodefake.SubmitPlan {
		r := f.result(n, d, land)
		r.TxHash = sha256Sum(bad)
		return nodefake.SubmitPlan{Land: landed, Result: r}
	}
	st := f.openArchive(t.TempDir())
	rec := f.newRec(f.cfg(st))

	var err error
	for i := 0; i < 5; i++ {
		_, err = rec.Publish(bg, f.blob)
		if errors.Is(err, recorder.ErrAnchorRejected) {
			break
		}
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the node's claim is not believed until the scan decides")
	}
	require.ErrorIs(t, err, recorder.ErrAnchorRejected)
	assert.Equal(t, 1, f.sub.Calls())

	f.grow(land + 5*fibreSpan)
	_, err = rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrAnchorRejected, "sticky: the escrow was charged, never pay again")
	assert.Equal(t, 1, f.sub.Calls())
	_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestFibreFalseHeightClaimIsUnresolved(t *testing.T) {
	f := newFibreFx(t)
	st := f.openArchive(t.TempDir())
	f.sub.Plan = func(_ int, n, d []byte) nodefake.SubmitPlan {
		f.node.SetHead(startHead + 3)
		return nodefake.SubmitPlan{Result: f.result(n, d, startHead+3)}
	}
	rec := f.newRec(f.cfg(st))
	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the node says it landed, the chain at that height says it did not")
	assert.Equal(t, 1, f.sub.Calls())
	_, err = st.Evidence(bg, commitment.DAFibre, f.l.Ref.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

// P2's PayForFibre is still unlanded when P3 first looks, and lands before the
// window that starts at P3's first head closes.
func TestFibrePendingSubmitLandsInsideTheExtendedWindow(t *testing.T) {
	f := newFibreFx(t)
	dir := t.TempDir()
	f.diedAfterPayload(f.openArchive(dir))

	f.grow(startHead + 500)
	p2end := startHead + 500 + fibreSpan
	f.sub.Plan = f.fail(context.DeadlineExceeded)
	rec2 := f.newRec(f.cfg(f.openArchive(dir)))
	_, err := rec2.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	f.grow(p2end + 1)
	_, err = rec2.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, f.sub.Calls(), "P2 submitted once and died")

	f.grow(startHead + 830)
	st := f.openArchive(dir)
	rec3 := f.newRec(f.cfg(st))
	_, err = rec3.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, f.sub.Calls())

	late := uint64(startHead + 830 + 100)
	f.grow(late)
	f.landLater(late)
	pub, err := publishUntil(t, f, rec3, 5)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls(), "the pending tx of P2 is found, never paid again")
	assert.Equal(t, late, pub.Ref.Height)
	requireVerifies(t, f, st, late)
}

// P3 first looks through a node that is far behind the chain: the window must
// not start from that head.
func TestFibreStaleHeadIsNeverTakenAsTheFirstSeenHead(t *testing.T) {
	f := newFibreFx(t)
	dir := t.TempDir()
	f.diedAfterPayload(f.openArchive(dir))

	f.grow(startHead + 400)
	fs := newFlaky(f.openArchive(dir))
	fs.failPut(archive.KindEvidence, errBoom)
	land := startHead + 400 + fibreSpan + 2
	f.sub.Plan = f.ok(land)
	rec2 := f.newRec(f.cfg(fs))
	_, err := rec2.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	f.grow(startHead + 400 + fibreSpan + 1)
	_, err = rec2.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable, "P2 paid and died before the evidence")
	require.Equal(t, 1, f.sub.Calls())

	lag := startHead + 50
	f.lag(lag)
	st := f.openArchive(dir)
	rec3 := f.newRec(f.cfg(st))
	_, err = rec3.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable, "the head is far behind the clock")
	assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Equal(t, 1, f.sub.Calls())

	f.lag(lag + 200)
	_, err = rec3.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.Equal(t, 1, f.sub.Calls())

	f.lag(land)
	pub, err := publishUntil(t, f, rec3, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls(), "the window starts at the caught-up head, so P2's PayForFibre is found")
	assert.Equal(t, land, pub.Ref.Height)
	requireVerifies(t, f, st, land)
}

func TestFibreHeadWithinTheFreshnessBoundIsAccepted(t *testing.T) {
	f := newFibreFx(t)
	f.lag(startHead - 8)
	f.sub.Plan = f.ok(f.l.Height)
	rec := f.newRec(f.cfg(f.openArchive(t.TempDir())))
	_, err := rec.Publish(bg, f.blob)
	require.NoError(t, err, "8 seconds behind the clock is a normal lag")
	assert.Equal(t, 1, f.sub.Calls())
}

// The landing is past the window the intent height alone would open, and the
// retry comes after the pending TTL.
func TestFibreLateLandingIsFoundAfterTheTTLWithoutASecondSubmit(t *testing.T) {
	f := newFibreFx(t)
	dir := t.TempDir()
	f.diedAfterPayload(f.openArchive(dir))

	f.grow(startHead + 500)
	land := startHead + 500 + fibreSpan + 2
	f.sub.Plan = f.failAfterLand(land, context.DeadlineExceeded)
	st := f.openArchive(dir)
	rec := f.newRec(f.cfg(st))
	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	f.grow(startHead + 500 + fibreSpan + 1)
	_, err = rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, f.sub.Calls())
	require.Equal(t, land, f.node.Head(), "the PayForFibre is beyond the intent height plus the window")

	f.grow(land + pendingTTLBlocks)
	pub, err := publishUntil(t, f, rec, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, f.sub.Calls(), "the landed PayForFibre is found, never paid again")
	assert.Equal(t, land, pub.Ref.Height)
	requireVerifies(t, f, st, land)
}

func TestFibreSubmittedEntryIsEvictedAfterTheTTLWithAnArchive(t *testing.T) {
	f := newFibreFx(t)
	c := f.cfg(f.openArchive(t.TempDir()))
	c.MaxPending = 1
	other := []byte{1, 2, 3}
	f.sub.Plan = f.fail(node.ErrUnavailable)
	rec := f.newRec(c)

	_, err := rec.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	_, err = rec.Publish(bg, other)
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "inside the TTL the slot is held")
	assert.Equal(t, 1, f.sub.Calls())

	f.grow(startHead + pendingTTLBlocks)
	_, err = rec.Publish(bg, other)
	require.NotErrorIs(t, err, recorder.ErrTooManyPending, "the dead entry no longer blocks a new blob")
	assert.Equal(t, 2, f.sub.Calls())
}
