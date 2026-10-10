package recorder_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// A restarted Recorder must not sign over the sequence of an intent an
// earlier process signed and returned a pending reference for, even when the
// node has lost that intent from its mempool, and it follows that intent to
// its evidence without a Publish of it.
func TestFastBlobRestartKeepsTheSequenceOfAnArchivedLiveIntent(t *testing.T) {
	f := newBlobFast(t)
	first := f.rec()
	pub, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())
	a := f.intent(genesis).Tx
	require.EqualValues(t, 3, txSequence(t, a))
	require.NoError(t, first.Close(bg))

	r := f.rec()
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	sent := f.node.sends()
	last := innerTx(sent[len(sent)-1])
	require.NotEqual(t, a, last)
	assert.EqualValues(t, 4, txSequence(t, last), "B must not take the sequence of A, whose reference was returned")

	h := genesis + 1
	f.ch.AddHeader(blockAt(h))
	f.ch.AddBlob(h, node.Blob{Namespace: ns, Data: f.blob, ShareVersion: 1, Signer: f.addr, Commitment: f.comm}, nil)
	f.node.setTx(a, node.TxStatus{Found: true, Height: h})
	assert.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
		return err == nil
	}, 5*time.Second, 5*time.Millisecond, "the restarted Recorder follows A")
}

func TestFastFibreRestartFollowsAnArchivedIntentWithoutAPublish(t *testing.T) {
	f := newFibreFast(t)
	first := f.rec()
	pub, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_ = first.Close(ctx)

	r := f.rec()
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.ErrorIs(t, err, recorder.ErrSubmitMismatch, "only the live blob has a certificate")
	f.landNow()
	assert.Eventually(t, f.evidence, 5*time.Second, 5*time.Millisecond, "the restarted Recorder follows the archived intent")
}

// The sequence a refusal named stays the floor after a later intent is
// adopted, until the committed sequence reaches it: that later intent may
// still fail, and the committed sequence lags the node's mempool.
func TestFastBlobRefusalFloorOutlivesTheNextIntent(t *testing.T) {
	f := newBlobFast(t)
	r := f.rec()
	f.node.script(mismatch(9))
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale)

	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	sent := f.node.sends()
	require.EqualValues(t, 9, txSequence(t, innerTx(sent[len(sent)-1])))
	f.node.script(fmt.Errorf("%w: insufficient fee", node.ErrRejected))
	_, err = r.Publish(bg, []byte("blob B"))
	require.ErrorIs(t, err, recorder.ErrAnchorTxRejected)

	_, err = r.Publish(bg, []byte("blob C"))
	require.NoError(t, err)
	sent = f.node.sends()
	assert.EqualValues(t, 9, txSequence(t, innerTx(sent[len(sent)-1])), "not the lagging committed sequence 3")
}
