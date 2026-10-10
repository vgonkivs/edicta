package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	nodeblob "github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// blobFast is a da = 2 fast-mode world: a chain, an archive, the own node and
// a keyring signer whose address signs the blob.
type blobFast struct {
	t    *testing.T
	ch   *nodefake.Chain
	st   *fsarchive.Store
	node *anchorNode
	sig  node.AnchorSigner
	addr []byte
	blob []byte
	comm []byte
	rd   *evReader
}

func squareFor(t testing.TB, addr, data []byte) square {
	t.Helper()
	nsv, err := libshare.NewNamespaceFromBytes(ns)
	require.NoError(t, err)
	bl, err := nodeblob.NewBlobV1(nsv, data, addr)
	require.NoError(t, err)
	shares, err := nodeblob.BlobsToShares(bl)
	require.NoError(t, err)
	raw := make([][]byte, len(shares))
	for i, s := range shares {
		raw[i] = s.ToBytes()
	}
	eds, err := da.ExtendShares(raw)
	require.NoError(t, err)
	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)
	p, err := nodeblob.ProveCommitment(eds, nsv, shares)
	require.NoError(t, err)
	return square{root: dah.Hash(), comm: bytes.Clone(bl.Commitment), proof: p}
}

func newBlobFast(t *testing.T) *blobFast {
	t.Helper()
	f := &blobFast{t: t, ch: newChain(), st: openArchive(t, t.TempDir()), node: newAnchorNode(), blob: []byte("fast decision payload")}
	f.sig, f.addr = anchorSigner(t, "devnet-1")
	f.comm = realCommitment(t, ns, f.addr, f.blob)
	f.rd = &evReader{Reader: f.ch, t: t, sq: squareFor(t, f.addr, f.blob)}
	return f
}

func (f *blobFast) rec() *recorder.Recorder {
	f.t.Helper()
	c := archCfg(f.st)
	c.Now = followHead(f.ch)
	c.FastTimeoutBlocks = 20
	r, err := recorder.NewFast(c, recorder.FastDeps{Signer: f.sig, Node: f.node}, f.rd)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = r.Close(context.Background()) })
	return r
}

// land makes every accepted BlobTx land in the next block.
func (f *blobFast) land() {
	f.node.onAccept = func(raw []byte) {
		head, err := f.ch.Head(bg)
		require.NoError(f.t, err)
		h := head.Height + 1
		f.ch.AddHeader(blockAt(h))
		f.ch.AddBlob(h, node.Blob{Namespace: bytes.Clone(ns), Data: bytes.Clone(f.blob), ShareVersion: 1,
			Signer: bytes.Clone(f.addr), Commitment: bytes.Clone(f.comm)}, nil)
		f.node.setTx(innerTx(raw), node.TxStatus{Found: true, Height: h})
	}
}

func (f *blobFast) intent(h0 uint64) *archive.AnchorIntentRecord {
	f.t.Helper()
	rec, err := f.st.Intent(bg, commitment.DACelestiaBlob, f.comm, h0)
	require.NoError(f.t, err)
	return rec
}

func TestFastBlobArchivesTheIntentBeforeTheBroadcast(t *testing.T) {
	f := newBlobFast(t)
	f.land()
	seen := 0
	f.node.before = func(raw []byte) {
		seen++
		rec, err := f.st.Intent(bg, commitment.DACelestiaBlob, f.comm, genesis)
		require.NoError(t, err, "the intent is archived before any broadcast")
		assert.Equal(t, rec.Tx, innerTx(raw), "the BlobTx carries exactly the archived tx")
		_, err = f.st.Payload(bg, commitment.DACelestiaBlob, f.comm)
		require.NoError(t, err, "the payload is archived first")
	}
	r := f.rec()
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, 1, seen)

	assert.True(t, pub.Ref.Pending())
	assert.Equal(t, genesis, pub.Ref.Height, "h0 is the head read before signing")
	assert.Equal(t, f.addr, pub.Ref.Signer)
	assert.Equal(t, f.comm, pub.Ref.Commitment)
	tRef := uint64(blockAt(genesis).Time.Unix())
	assert.Equal(t, tRef, pub.BlockTime, "T_ref is the floored header time at h0")
	assert.Equal(t, tRef, pub.RetentionStart)

	rec := f.intent(genesis)
	assert.Equal(t, f.addr, rec.Signer)
	assert.Equal(t, ns, rec.Namespace)
	timeout, err := gatechain.CheckPFB(rec.Tx, pub.Ref)
	require.NoError(t, err, "the intent passes the gate's PFB check")
	assert.Equal(t, genesis+20, timeout)
	assert.EqualValues(t, 3, txSequence(t, rec.Tx), "signed at the chain's sequence")

	require.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
		return err == nil
	}, 5*time.Second, time.Millisecond, "the confirmation loop writes the evidence")
	again, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	assert.False(t, again.Ref.Pending(), "once anchored, the included reference is returned")
	assert.Equal(t, genesis+1, again.Ref.Height)
	assert.Len(t, f.node.sends(), 1)
}

func TestFastBlobSequencesFollowEachOther(t *testing.T) {
	f := newBlobFast(t)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	_, err = r.Publish(bg, []byte("a second payload"))
	require.NoError(t, err)
	sent := f.node.sends()
	require.Len(t, sent, 2)
	assert.EqualValues(t, 3, txSequence(t, innerTx(sent[0])))
	assert.EqualValues(t, 4, txSequence(t, innerTx(sent[1])), "the next intent takes the next sequence")
}

func TestFastBlobCrashAfterTheIntentResumesWithTheArchivedTx(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	_, err := f.rec().Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	rec := f.intent(genesis)

	f.ch.AddHeader(blockAt(genesis + 1))
	pub, err := f.rec().Publish(bg, f.blob)
	require.NoError(t, err, "a new process finds the intent")
	assert.True(t, pub.Ref.Pending())
	assert.Equal(t, genesis, pub.Ref.Height, "the same h0, not a new intent")
	sent := f.node.sends()
	require.Len(t, sent, 2)
	assert.Equal(t, rec.Tx, innerTx(sent[1]), "the archived tx is sent again, not signed anew")
	for h := genesis + 1; h <= genesis+1+64; h++ {
		_, err := f.st.Intent(bg, commitment.DACelestiaBlob, f.comm, h)
		require.ErrorIs(t, err, archive.ErrNotFound, "no second intent at height %d", h)
	}
}

func TestFastBlobStaleArchivedTxIsNeverReSigned(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	rec := f.intent(genesis)

	f.node.script(mismatch(9))
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale, "the node expects a sequence past the archived tx")
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale, "sticky")
	sent := f.node.sends()
	require.Len(t, sent, 2, "no further broadcast")
	for _, raw := range sent {
		assert.Equal(t, rec.Tx, innerTx(raw), "only the archived tx is ever sent")
	}
	assert.Equal(t, rec, f.intent(genesis), "the intent record is untouched")

	f.node.script(mismatch(9))
	_, err = f.rec().Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale, "a new process finds the intent stale too")
	sent = f.node.sends()
	require.Len(t, sent, 3)
	assert.Equal(t, rec.Tx, innerTx(sent[2]))
}

func TestFastBlobArchivedTxBehindAGapIsRetried(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	rec := f.intent(genesis)

	f.node.script(mismatch(2))
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable, "an earlier tx is missing: transient")
	require.NotErrorIs(t, err, recorder.ErrIntentStale)

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "not sticky: the retry sends the archived tx again")
	assert.True(t, pub.Ref.Pending())
	sent := f.node.sends()
	require.Len(t, sent, 3)
	for _, raw := range sent {
		assert.Equal(t, rec.Tx, innerTx(raw), "only the archived tx is ever sent")
	}
}

func TestFastBlobArchivedTxThatLandsDuringTheResendIsConfirmed(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	rec := f.intent(genesis)

	h := genesis + 1
	f.node.before = func(raw []byte) {
		if len(f.node.sends()) < 2 {
			return
		}
		f.ch.AddHeader(blockAt(h))
		f.ch.AddBlob(h, node.Blob{Namespace: bytes.Clone(ns), Data: bytes.Clone(f.blob), ShareVersion: 1,
			Signer: bytes.Clone(f.addr), Commitment: bytes.Clone(f.comm)}, nil)
		f.node.setTx(innerTx(raw), node.TxStatus{Found: true, Height: h})
	}
	f.node.script(mismatch(4))
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "the tx is looked up again after the mismatch and found")
	assert.False(t, pub.Ref.Pending())
	assert.Equal(t, h, pub.Ref.Height)
	_, err = f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
	require.NoError(t, err)
	sent := f.node.sends()
	require.Len(t, sent, 2)
	assert.Equal(t, rec.Tx, innerTx(sent[1]))
}

func TestFastBlobNewIntentWithAStaleSequenceIsSticky(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(mismatch(5))
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale)
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale, "this blob is not published again")
	assert.Len(t, f.node.sends(), 1)

	_, err = r.Publish(bg, []byte("a fresh payload"))
	require.NoError(t, err)
	sent := f.node.sends()
	assert.EqualValues(t, 5, txSequence(t, innerTx(sent[1])), "the next intent uses the sequence the node expects")
}

func TestFastBlobRetriesTheTransientValsetRefusal(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(fmt.Errorf("%w: failed to get historical validator set", node.ErrRejected))
	pub, err := f.rec().Publish(bg, f.blob)
	require.NoError(t, err)
	assert.True(t, pub.Ref.Pending())
	sent := f.node.sends()
	require.Len(t, sent, 2)
	assert.Equal(t, sent[0], sent[1], "the same bytes again")
}

func TestFastBlobRefusedTxIsSticky(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(fmt.Errorf("%w: insufficient fee", node.ErrRejected))
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrAnchorTxRejected)
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrAnchorTxRejected)
	assert.Len(t, f.node.sends(), 1)
}

func TestFastBlobAnchorThatNeverLandsExpires(t *testing.T) {
	f := newBlobFast(t)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	for h := genesis + 1; h <= genesis+21; h++ {
		f.ch.AddHeader(blockAt(h))
	}
	require.Eventually(t, func() bool {
		_, err := r.Publish(bg, f.blob)
		return errors.Is(err, recorder.ErrAnchorExpired)
	}, 5*time.Second, 5*time.Millisecond)
	_, err = f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestFastBlobArchiveWithoutIntentFromAnEarlierProcessIsRefused(t *testing.T) {
	f := newBlobFast(t)
	_, err := f.st.Put(bg, &archive.PayloadRecord{DA: commitment.DACelestiaBlob, Commitment: f.comm, Namespace: ns,
		Signer: f.addr, Blob: f.blob, IntentHeight: genesis})
	require.NoError(t, err)
	_, err = f.rec().Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Empty(t, f.node.sends(), "an earlier submit may still land: nothing is signed or sent")
}

func TestFastConfigRefusals(t *testing.T) {
	f := newBlobFast(t)
	c := archCfg(f.st)
	_, err := recorder.NewFast(c, recorder.FastDeps{Node: f.node}, f.rd)
	require.Error(t, err, "no signer")
	c.Archive = nil
	_, err = recorder.NewFast(c, recorder.FastDeps{Signer: f.sig, Node: f.node}, f.rd)
	require.Error(t, err, "no archive")
	c = archCfg(f.st)
	c.FastTimeoutBlocks = 12
	_, err = recorder.NewFast(c, recorder.FastDeps{Signer: f.sig, Node: f.node}, f.rd)
	require.Error(t, err, "timeout below the floor")
}
