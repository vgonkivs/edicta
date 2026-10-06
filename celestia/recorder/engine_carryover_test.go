package recorder_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// swapReader serves from one node at a time, as a failover would.
type swapReader struct {
	mu sync.Mutex
	rd node.Reader
}

func (s *swapReader) set(rd node.Reader) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rd = rd
}

func (s *swapReader) cur() node.Reader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rd
}

func (s *swapReader) Head(ctx context.Context) (node.Header, error) { return s.cur().Head(ctx) }
func (s *swapReader) HeaderAt(ctx context.Context, h uint64) (node.Header, error) {
	return s.cur().HeaderAt(ctx, h)
}
func (s *swapReader) Blob(ctx context.Context, h uint64, n, c []byte) (node.Blob, error) {
	return s.cur().Blob(ctx, h, n, c)
}
func (s *swapReader) CommitmentProof(ctx context.Context, h uint64, n, c []byte) (node.CommitmentProof, error) {
	return s.cur().CommitmentProof(ctx, h, n, c)
}

// A head that is far behind the chain says nothing about where earlier submits
// landed, so a call that sees one must not start the settle window from it.
func TestStaleHeadIsNeverTakenAsTheFirstSeenHead(t *testing.T) {
	const settle = 256
	dir := t.TempDir()
	ch := newChain()
	comm := realCommitment(t, ns, signer, decisionBlob)
	trueNow := followHead(ch)

	diedAfterPayloadWrite(t, dir, ch, decisionBlob)

	grow(ch, 2000)
	p2 := newLanding(ch)
	fs := &failStore{Store: openArchive(t, dir), err: errBoom, kinds: map[archive.Kind]bool{archive.KindEvidence: true}}
	rec2 := mk(t, settleCfg(fs, settle), p2, ev(t, ch, decisionBlob))
	_, err := rec2.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	grow(ch, 2000+settle+1)
	for i := 0; i < 10 && p2.Calls == 0; i++ {
		_, err = rec2.Publish(bg, decisionBlob)
	}
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	require.Equal(t, 1, p2.Calls)
	landed := uint64(2000 + settle + 2)
	grow(ch, 2500)

	// P3 starts on a node that is at 1500: past the intent, inside P2's
	// window, and an hour and a half behind the clock.
	behind := nodefake.NewChain(signer)
	for h := genesis; h <= 1500; h++ {
		behind.AddHeader(blockAt(h))
	}
	sw := &swapReader{rd: behind}
	p3 := newLanding(ch)
	st := openArchive(t, dir)
	c3 := settleCfg(st, settle)
	c3.Now = trueNow
	rec3 := mk(t, c3, p3, ev(t, sw, decisionBlob))

	_, err = rec3.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Zero(t, p3.Calls)

	grow(behind, 1500+settle+50)
	_, err = rec3.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable, "still behind the clock")
	assert.Zero(t, p3.Calls)

	sw.set(ch)
	var pub sdk.Published
	for i := 0; i < 10; i++ {
		pub, err = rec3.Publish(bg, decisionBlob)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.Zero(t, p3.Calls)
	}
	require.NoError(t, err)
	assert.Zero(t, p3.Calls, "the window starts at the caught-up head, so P2's blob is found")
	assert.Equal(t, landed, pub.Ref.Height)
	evd, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	assert.Equal(t, landed, evd.Height)
}

func TestHeadWithinTheFreshnessBoundIsAccepted(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	c := archCfg(openArchive(t, t.TempDir()))
	c.Now = func() time.Time { return blockAt(genesis).Time.Add(30 * time.Second) }
	p, err := mk(t, c, sub, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
	require.NoError(t, err)
	assert.Equal(t, 1, sub.Calls)
	assert.Equal(t, genesis+1, p.Ref.Height)
}

func TestHeadFarBehindTheClockSubmitsNothing(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	st := openArchive(t, t.TempDir())
	c := archCfg(st)
	c.Now = func() time.Time { return blockAt(genesis).Time.Add(10 * time.Minute) }
	_, err := mk(t, c, sub, ev(t, ch, decisionBlob)).Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.Zero(t, sub.Calls)
	_, err = st.Payload(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, decisionBlob))
	require.ErrorIs(t, err, archive.ErrNotFound, "no intent is archived from a stale head")
}

// With an archive a submitted entry that never resolved is dropped after the
// TTL, so one dead endpoint cannot fill every pending slot.
func TestSubmittedEntryIsEvictedAfterTheTTLWithAnArchive(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	clk := &testClock{t: blockAt(genesis).Time}
	c := settleCfg(openArchive(t, t.TempDir()), 256)
	c.MaxPending = 1
	c.Now = clk.Now
	rec := mk(t, c, sub, ev(t, ch, decisionBlob))
	other := []byte("another decision")

	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, sub.Calls)

	_, err = rec.Publish(bg, other)
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "inside the TTL the slot is held")

	advance(ch, clk, 2*time.Hour)
	_, err = rec.Publish(bg, other)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.NotErrorIs(t, err, recorder.ErrTooManyPending, "the dead entry no longer blocks a new blob")
	assert.Equal(t, 2, sub.Calls)
}

// The dropped entry's blob is windowed again: it is submitted once the window
// from the new first head has been read and found empty, not before.
func TestBlobOfAnEvictedEntryWaitsOutANewWindowBeforeItIsSubmittedAgain(t *testing.T) {
	const settle = 256
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	clk := &testClock{t: blockAt(genesis).Time}
	c := settleCfg(openArchive(t, t.TempDir()), settle)
	c.Now = clk.Now
	rec := mk(t, c, sub, ev(t, ch, decisionBlob))

	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, sub.Calls)

	advance(ch, clk, 2*time.Hour)
	sub.Err, sub.NoLand = nil, false
	head, _ := ch.Head(bg)
	_, err = rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "the new entry waits out a window first")
	assert.Equal(t, 1, sub.Calls)

	grow(ch, head.Height+settle+1)
	advance(ch, clk, time.Second)
	var pub sdk.Published
	for i := 0; i < 10; i++ {
		pub, err = rec.Publish(bg, decisionBlob)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	}
	require.NoError(t, err)
	assert.Equal(t, 2, sub.Calls, "submitted once the window is read and empty")
	assert.NotZero(t, pub.Ref.Height)
}

func TestSubmittedEntryWithoutAnArchiveIsKeptAfterTheTTL(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	clk := &testClock{t: blockAt(genesis).Time}
	c := cfg()
	c.MaxPending = 1
	c.Now = clk.Now
	rec := mk(t, c, sub, ch)

	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	advance(ch, clk, 2*time.Hour)
	_, err = rec.Publish(bg, []byte("another decision"))
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "nothing remembers the submit but this entry")
	_, err = rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Equal(t, 1, sub.Calls)
}

// The submit lands after the window the intent height alone would open, and
// the retry comes after the TTL.
func TestLateLandingIsFoundAfterTheTTLWithoutASecondSubmit(t *testing.T) {
	const settle = 256
	dir := t.TempDir()
	ch := newChain()
	diedAfterPayloadWrite(t, dir, ch, decisionBlob)

	sub := newLanding(ch)
	sub.Err, sub.ErrAfterLand = errBoom, true
	clk := &testClock{t: blockAt(500).Time}
	grow(ch, 500)
	c := settleCfg(openArchive(t, dir), settle)
	c.Now = clk.Now
	rec := mk(t, c, sub, ev(t, ch, decisionBlob))

	_, err := rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	grow(ch, 500+settle+1)
	clk.add(blockAt(500 + settle + 1).Time.Sub(clk.Now()))
	_, err = rec.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, sub.Calls)
	landed := uint64(500 + settle + 2)
	head, _ := ch.Head(bg)
	require.Equal(t, landed, head.Height, "the blob is beyond the intent height plus the window")

	advance(ch, clk, 2*time.Hour)
	sub.Err = nil
	var pub sdk.Published
	for i := 0; i < 10; i++ {
		pub, err = rec.Publish(bg, decisionBlob)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.Equal(t, 1, sub.Calls)
	}
	require.NoError(t, err)
	assert.Equal(t, 1, sub.Calls, "the landed blob is found, never paid again")
	assert.Equal(t, landed, pub.Ref.Height)
}

// P2's tx is still pending when P3 first looks, and lands before the window
// that starts at P3's first head closes.
func TestPendingSubmitOfAnEarlierProcessLandsInsideTheExtendedWindow(t *testing.T) {
	const settle = 256
	dir := t.TempDir()
	ch := newChain()
	comm := realCommitment(t, ns, signer, decisionBlob)
	diedAfterPayloadWrite(t, dir, ch, decisionBlob)

	grow(ch, 500)
	p2 := newLanding(ch)
	p2.NoLand, p2.Err = true, context.DeadlineExceeded
	rec2 := mk(t, settleCfg(openArchive(t, dir), settle), p2, ev(t, ch, decisionBlob))
	_, err := rec2.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	grow(ch, 500+settle+1)
	_, err = rec2.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Equal(t, 1, p2.Calls)

	grow(ch, 830)
	p3 := newLanding(ch)
	st := openArchive(t, dir)
	rec3 := mk(t, settleCfg(st, settle), p3, ev(t, ch, decisionBlob))
	_, err = rec3.Publish(bg, decisionBlob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.Zero(t, p3.Calls)

	late := uint64(830 + 100)
	grow(ch, late)
	ch.AddBlob(late, node.Blob{Namespace: ns, Data: decisionBlob, ShareVersion: 1, Signer: signer, Commitment: comm}, nil)

	var pub sdk.Published
	for i := 0; i < 10; i++ {
		pub, err = rec3.Publish(bg, decisionBlob)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.Zero(t, p3.Calls)
	}
	require.NoError(t, err)
	assert.Zero(t, p3.Calls, "the pending tx of P2 is found, never paid again")
	assert.Equal(t, late, pub.Ref.Height)
	assert.Equal(t, 1, p2.Calls+p3.Calls)
}
