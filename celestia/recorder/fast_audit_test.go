package recorder_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// The chain's committed sequence lags while our own intents sit in the
// mempool: the next intent must never take the sequence of a live one.
func TestFastBlobNextIntentSkipsTheSequenceOfALiveIntent(t *testing.T) {
	for _, tc := range []struct {
		name string
		// between runs after blob A was sent at sequence 3.
		between func(t *testing.T, f *blobFast, r *recorder.Recorder)
		first   []error
	}{
		{"A polled again", func(t *testing.T, f *blobFast, r *recorder.Recorder) {
			f.node.script(fmt.Errorf("%w: tx already exists in cache", node.ErrAlreadyInMempool))
			pub, err := r.Publish(bg, f.blob)
			require.NoError(t, err)
			require.True(t, pub.Ref.Pending())
		}, nil},
		{"A's broadcast outcome unknown", func(*testing.T, *blobFast, *recorder.Recorder) {}, []error{errTransport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBlobFast(t)
			f.node.script(tc.first...)
			r := f.rec()
			_, _ = r.Publish(bg, f.blob)
			require.EqualValues(t, 3, txSequence(t, f.intent(genesis).Tx))
			tc.between(t, f, r)

			_, err := r.Publish(bg, []byte("blob B"))
			require.NoError(t, err)
			sent := f.node.sends()
			last := innerTx(sent[len(sent)-1])
			require.False(t, bytes.Equal(last, f.intent(genesis).Tx))
			assert.EqualValues(t, 4, txSequence(t, last), "B must not reuse A's sequence while A is live")
		})
	}
}

// A first broadcast with an unknown outcome still leaves a live intent: it
// is followed without another Publish, and its evidence is written when it
// lands.
func TestFastBlobIntentWithAnUnknownBroadcastIsFollowedWithoutAPublish(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	_, err := f.rec().Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	tx := f.intent(genesis).Tx

	h := genesis + 1
	f.ch.AddHeader(blockAt(h))
	f.ch.AddBlob(h, node.Blob{Namespace: ns, Data: f.blob, ShareVersion: 1, Signer: f.addr, Commitment: f.comm}, nil)
	f.node.setTx(tx, node.TxStatus{Found: true, Height: h})
	assert.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
		return err == nil
	}, 2*time.Second, 5*time.Millisecond, "the confirmation loop runs for every archived intent")
}

// An intent that drops out of the mempool is sent again by the confirmation
// loop, not only when a caller polls.
func TestFastBlobLoopRebroadcastsAnIntentThatLeftTheMempool(t *testing.T) {
	f := newBlobFast(t)
	pub, err := f.rec().Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())
	tx := f.intent(genesis).Tx
	assert.Eventually(t, func() bool { return len(f.node.sends()) >= 2 }, 2*time.Second, 5*time.Millisecond,
		"the loop rebroadcasts the archived tx while it is not found")
	for _, raw := range f.node.sends() {
		assert.Equal(t, tx, innerTx(raw))
	}
}

// A PayForFibre refused in CheckTx leaves its promise unprocessed and still
// chargeable by a timeout settlement, so its cost stays reserved.
func TestFastFibreRefusedAnchorTxKeepsTheEscrowReserved(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fibreFast, st *stepStore)
	}{
		{"node refuses the tx", func(f *fibreFast, _ *stepStore) {
			f.node.script(fmt.Errorf("%w: insufficient fee", node.ErrRejected))
		}},
		{"intent write fails after the upload", func(_ *fibreFast, st *stepStore) {
			st.crash[archive.KindAnchorIntent] = crashBefore
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFibreFast(t)
			f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
			st := newStepStore(f.st.(*fsarchive.Store))
			tc.setup(f, st)
			r := f.recWith(st, f.up)
			_, err := r.Publish(bg, f.blob)
			require.Error(t, err)
			st.crash = map[archive.Kind]crashMode{}

			_, err = r.Publish(bg, f.sameSize(0x66))
			var short *recorder.EscrowShortfall
			assert.ErrorAs(t, err, &short, "the uploaded promise can still be charged")
		})
	}
}

// The settle wait of a stale intent must run past created +
// PromiseTimeoutS: settlement only starts to be possible then.
func TestFastFibreStaleIntentKeepsTheEscrowPastThePromiseTimeout(t *testing.T) {
	f := newFibreFast(t)
	f.fibreFx.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 1})
	f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
	f.node.script(errTransport)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	f.skew.Store(int64(-time.Hour))
	seq, err := node.TxSequence(f.l.PFFTx)
	require.NoError(t, err)
	f.node.script(mismatch(seq + 1))
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrIntentStale)
	f.skew.Store(0)

	var short *recorder.EscrowShortfall
	assert.Never(t, func() bool {
		_, err := r.Publish(bg, f.sameSize(0x66))
		return !errors.As(err, &short)
	}, 2500*time.Millisecond, 100*time.Millisecond, "still reserved after created + PromiseTimeoutS")
}
