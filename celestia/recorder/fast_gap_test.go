package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

// slowPoll keeps the confirmation loop from sending an intent again during a
// test that scripts the node's answers.
const slowPoll = time.Hour

func (f *blobFast) recSlow(st archive.Store, log *logBuf) *recorder.Recorder {
	f.t.Helper()
	c := archCfg(st)
	c.Now = followHead(f.ch)
	c.FastTimeoutBlocks = 20
	c.PollInterval = slowPoll
	d := recorder.FastDeps{Signer: f.sig, Node: f.node}
	if log != nil {
		d.Log = slog.New(slog.NewTextHandler(log, nil))
	}
	r, err := recorder.NewFast(c, d, f.rd)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = r.Close(context.Background()) })
	return r
}

func (f *blobFast) intentOf(blob []byte) *archive.AnchorIntentRecord {
	f.t.Helper()
	rec, err := f.st.Intent(bg, commitment.DACelestiaBlob, realCommitment(f.t, ns, f.addr, blob), genesis)
	require.NoError(f.t, err)
	return rec
}

func (f *blobFast) hasPayload(blob []byte) bool {
	_, err := f.st.Payload(bg, commitment.DACelestiaBlob, realCommitment(f.t, ns, f.addr, blob))
	if err != nil {
		require.ErrorIs(f.t, err, archive.ErrNotFound)
	}
	return err == nil
}

// The fake node refuses any sequence but the committed one plus the txs it
// holds, as CheckTx does; the next intent still never reuses a live one's.
func TestFastBlobNextIntentSkipsALiveSequenceOnAStrictNode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first []error
	}{
		{"A accepted", nil},
		{"A's broadcast outcome unknown", []error{errTransport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBlobFast(t)
			f.node.beStrict()
			f.node.script(tc.first...)
			r := f.rec()
			_, _ = r.Publish(bg, f.blob)
			a := f.intent(genesis).Tx
			require.EqualValues(t, 3, txSequence(t, a))
			pub, err := r.Publish(bg, f.blob)
			require.NoError(t, err, "A is polled again")
			require.True(t, pub.Ref.Pending())

			blobB := []byte("blob B")
			_, err = r.Publish(bg, blobB)
			if errors.Is(err, recorder.ErrOutcomeUnknown) {
				_, err = r.Publish(bg, blobB)
			}
			require.NoError(t, err)
			b := f.intentOf(blobB).Tx
			assert.EqualValues(t, 4, txSequence(t, b), "B must not reuse A's sequence while A is live")
			for _, raw := range f.node.sends() {
				tx := innerTx(raw)
				assert.True(t, bytes.Equal(tx, a) || bytes.Equal(tx, b), "only the archived txs are sent")
			}
		})
	}
}

// A refusal naming a missing earlier sequence sends the live intent at that
// sequence again, exactly as archived, and the refused intent stays
// resumable without a new signature.
func TestFastBlobGapResendsTheLiveIntentAtTheExpectedSequence(t *testing.T) {
	f := newBlobFast(t)
	r := f.recSlow(f.st, nil)
	f.node.script(errTransport)
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	a := f.intent(genesis).Tx

	blobB := []byte("blob B")
	f.node.script(mismatch(3))
	_, err = r.Publish(bg, blobB)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.NotErrorIs(t, err, recorder.ErrIntentStale)
	b := f.intentOf(blobB).Tx
	require.EqualValues(t, 4, txSequence(t, b))

	sent := f.node.sends()
	require.Len(t, sent, 3)
	assert.Equal(t, [][]byte{a, b, a}, [][]byte{innerTx(sent[0]), innerTx(sent[1]), innerTx(sent[2])},
		"A's archived bytes go out right after B's refusal")
	assert.Equal(t, sent[0], sent[2], "unchanged on the wire")

	pub, err := r.Publish(bg, blobB)
	require.NoError(t, err, "B is not sticky")
	assert.True(t, pub.Ref.Pending())
	sent = f.node.sends()
	require.Len(t, sent, 4)
	assert.Equal(t, b, innerTx(sent[3]), "B's archived tx, not a new signature")
	assert.Equal(t, b, f.intentOf(blobB).Tx)
}

// A gap no live intent can fill stops new intents before anything is
// archived or uploaded, logged once, until the gap fills.
func TestFastBlobUnfillableGapStopsNewIntentsUntilItFills(t *testing.T) {
	f := newBlobFast(t)
	log := &logBuf{}
	r := f.recSlow(f.st, log)
	f.node.script(mismatch(2))
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	for _, blob := range [][]byte{[]byte("blob B"), []byte("blob C")} {
		_, err = r.Publish(bg, blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
		assert.False(t, f.hasPayload(blob), "nothing archived while the gap stands")
	}
	assert.Len(t, f.node.sends(), 1, "nothing signed or sent")
	assert.Equal(t, 1, log.count("no live intent holds"), "logged once")

	_, err = r.Publish(bg, f.blob)
	require.NoError(t, err, "A is accepted: the gap is filled")
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	assert.EqualValues(t, 4, txSequence(t, f.intentOf([]byte("blob B")).Tx))
}

// An unreadable sequence refusal stops new drafts before their upload, logged
// once, until the node accepts an anchor tx again.
func TestFastBlobBlindSequenceRefusesNewDraftsBeforeUpload(t *testing.T) {
	f := newFibreFast(t)
	log := &logBuf{}
	c := f.cfg(f.st)
	c.PollInterval = slowPoll
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: f.up, Log: slog.New(slog.NewTextHandler(log, nil))}
	r, err := recorder.NewFibre(c, d)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_ = r.Close(ctx)
	})

	f.node.script(unparsable)
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	require.EqualValues(t, 1, f.up.calls.Load())

	other := f.sameSize(0x66)
	commB, err := fibrecommit.Commitment(other)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = r.Publish(bg, other)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	}
	assert.EqualValues(t, 1, f.up.calls.Load(), "no upload while the sequence is unknown")
	assert.Len(t, f.node.sends(), 1, "no send")
	_, err = f.st.Payload(bg, commitment.DAFibre, commB[:])
	require.ErrorIs(t, err, archive.ErrNotFound, "no payload record either")
	assert.Equal(t, 1, log.count("without naming the expected one"), "logged once")

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "A's resend is accepted")
	require.True(t, pub.Ref.Pending())
	_, err = r.Publish(bg, other)
	require.ErrorIs(t, err, recorder.ErrSubmitMismatch, "drafted again: only the live blob has a certificate")
	assert.EqualValues(t, 2, f.up.calls.Load())
}

// A blob whose first Publish failed before its intent is drafted again after
// prune made room, not refused as an earlier process's record, and such
// entries never fill the pending bound.
func TestFastFibreFailedUploadIsRetriedInTheSameProcessAfterPrune(t *testing.T) {
	f := newFibreFast(t)
	failed := false
	up := &hookUploader{liveUploader: f.up, hook: func(_ context.Context, blob []byte) error {
		if bytes.Equal(blob, f.blob) && !failed {
			failed = true
			return errTransport
		}
		return nil
	}}
	c := f.cfg(f.st)
	c.MaxPending = 2
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: up}
	r, err := recorder.NewFibre(c, d)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_ = r.Close(ctx)
	})

	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	for _, tag := range []byte{0x61, 0x62, 0x63} {
		_, err = r.Publish(bg, f.sameSize(tag))
		require.ErrorIs(t, err, recorder.ErrSubmitMismatch, "failures before an intent do not fill the bound")
		require.NotErrorIs(t, err, recorder.ErrTooManyPending)
	}

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "drafted again, not refused as a record without an intent")
	assert.True(t, pub.Ref.Pending())
	assert.EqualValues(t, 5, up.calls.Load())
}

// conflictStore lets another intent take the key just before this
// Recorder's intent write: other is stored first, and the write then
// conflicts.
type conflictStore struct {
	*fsarchive.Store
	other *archive.AnchorIntentRecord
	// force reports a conflict even when other equals the written record.
	force bool
}

func (s *conflictStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	if r.Kind() == archive.KindAnchorIntent && s.other != nil {
		other := s.other
		s.other = nil
		if _, err := s.Store.Put(ctx, other); err != nil {
			return 0, err
		}
		if s.force {
			return 0, archive.ErrConflict
		}
	}
	return s.Store.Put(ctx, r)
}

func TestFastBlobConflictFollowsTheStoredIntent(t *testing.T) {
	f := newBlobFast(t)
	tx, err := f.sig.SignPFB(bg, ns, f.blob, node.TxParams{AccountNumber: 7, Sequence: 7, GasPrice: big.NewRat(1, 250), TimeoutHeight: genesis + 20})
	require.NoError(t, err)
	other := &archive.AnchorIntentRecord{DA: commitment.DACelestiaBlob, Commitment: f.comm, Namespace: ns, RefHeight: genesis,
		Tx: tx, Signer: f.addr, CreatedAt: 12345}
	r := f.recSlow(&conflictStore{Store: f.st, other: other}, nil)

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.True(t, pub.Ref.Pending())
	assert.Equal(t, genesis, pub.Ref.Height)
	assert.Equal(t, uint64(blockAt(genesis).Time.Unix()), pub.RetentionStart, "the stored intent's own times")
	assert.Equal(t, other, f.intent(genesis))
	sent := f.node.sends()
	require.NotEmpty(t, sent)
	for _, raw := range sent {
		assert.Equal(t, tx, innerTx(raw), "only the stored tx is sent")
	}
}

func TestFastFibreConflictFollowsTheStoredIntentWithItsTimes(t *testing.T) {
	stored := func(f *fibreFast) *archive.AnchorIntentRecord {
		return &archive.AnchorIntentRecord{DA: commitment.DAFibre, Commitment: f.comm[:], Namespace: f.l.Ref.Namespace,
			RefHeight: f.h0, Tx: f.l.PFFTx, CreatedAt: uint64(f.l.Created.Unix())}
	}
	t.Run("checked stored intent", func(t *testing.T) {
		f := newFibreFast(t)
		f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
		other := stored(f)
		r := f.recWith(&conflictStore{Store: f.st.(*fsarchive.Store), other: other, force: true}, f.up)
		pub, err := r.Publish(bg, f.blob)
		require.NoError(t, err)
		assert.True(t, pub.Ref.Pending())
		assert.Equal(t, other.CreatedAt, pub.RetentionStart, "retention starts at the stored promise")
		for _, raw := range f.node.sends() {
			assert.Equal(t, other.Tx, raw)
		}

		var short *recorder.EscrowShortfall
		_, err = r.Publish(bg, f.sameSize(0x66))
		require.ErrorAs(t, err, &short, "this upload's promise is never anchored and stays chargeable")
		f.landNow()
		require.Eventually(t, f.evidence, 5*time.Second, time.Millisecond)
		_, err = r.Publish(bg, f.sameSize(0x66))
		require.ErrorAs(t, err, &short, "the stored intent landing does not pay this upload's promise")
	})
	t.Run("stored intent failing the check", func(t *testing.T) {
		f := newFibreFast(t)
		other := stored(f)
		other.CreatedAt += 5
		r := f.recWith(&conflictStore{Store: f.st.(*fsarchive.Store), other: other}, f.up)
		_, err := r.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
		assert.Empty(t, f.node.sends())
	})
}
