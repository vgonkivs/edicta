package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// headSwitch is a reader whose head is at height 0 while zero is set, as a
// node that has not synced its first block reports it.
type headSwitch struct {
	*evReader
	zero atomic.Bool
}

func (z *headSwitch) Head(ctx context.Context) (node.Header, error) {
	if z.zero.Load() {
		return node.Header{}, nil
	}
	return z.evReader.Head(ctx)
}

// A head at height 0 lists no intent; it must not count as a finished
// recovery, or the next intent takes the sequence of a live archived one.
func TestFastBlobHeadZeroDoesNotFinishTheRecovery(t *testing.T) {
	f := newBlobFast(t)
	first := f.rec()
	_, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.NoError(t, first.Close(bg))

	rd := &headSwitch{evReader: f.rd}
	rd.zero.Store(true)
	r := f.recRd(rd, 20)
	_, err = r.Publish(bg, []byte("blob B"))
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)

	rd.zero.Store(false)
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	sent := f.node.sends()
	assert.EqualValues(t, 4, txSequence(t, innerTx(sent[len(sent)-1])), "B is signed above the archived intent at 3")
}

// sentAfter reports whether tx was broadcast after the first n sends.
func (f *blobFast) sentAfter(n int, tx []byte) bool {
	for _, raw := range f.node.sends()[n:] {
		if bytes.Equal(innerTx(raw), tx) {
			return true
		}
	}
	return false
}

// A restarted Recorder follows a live archived intent from its construction:
// with nothing published, it sends the archived bytes again for a node that
// lost them, and writes the evidence once the anchor lands.
func TestFastBlobRecoveryRunsAtBootWithoutAPublish(t *testing.T) {
	f := newBlobFast(t)
	first := f.rec()
	_, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.NoError(t, first.Close(bg))
	a := f.intent(genesis).Tx
	n := len(f.node.sends())

	f.rec()
	assert.Eventually(t, func() bool { return f.sentAfter(n, a) }, 5*time.Second, 5*time.Millisecond,
		"the archived bytes are sent again without a Publish")

	h := genesis + 1
	f.ch.AddHeader(blockAt(h))
	f.ch.AddBlob(h, node.Blob{Namespace: ns, Data: f.blob, ShareVersion: 1, Signer: f.addr, Commitment: f.comm}, nil)
	f.node.setTx(a, node.TxStatus{Found: true, Height: h})
	assert.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
		return err == nil
	}, 5*time.Second, 5*time.Millisecond, "the evidence is written without a Publish")
}

// listFail is an archive whose intent listing fails while fail is set.
type listFail struct {
	*fsarchive.Store
	fail  atomic.Bool
	mu    sync.Mutex
	calls []time.Time
}

func (s *listFail) Intents(ctx context.Context, da commitment.DA, from uint64) ([]*archive.AnchorIntentRecord, error) {
	s.mu.Lock()
	s.calls = append(s.calls, time.Now())
	s.mu.Unlock()
	if s.fail.Load() {
		return nil, errors.New("disk unavailable")
	}
	return s.Store.Intents(ctx, da, from)
}

func (s *listFail) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// A failing recovery is retried in the background with a growing wait, a
// Publish meanwhile is refused with the failure, and Close ends the retries.
func TestFastBlobRecoveryRetriesWithBackoff(t *testing.T) {
	f := newBlobFast(t)
	first := f.rec()
	_, err := first.Publish(bg, f.blob)
	require.NoError(t, err)
	require.NoError(t, first.Close(bg))

	st := &listFail{Store: f.st}
	st.fail.Store(true)
	r := f.recOn(st)
	require.Eventually(t, func() bool { return st.count() >= 4 }, 5*time.Second, time.Millisecond, "retried without a Publish")
	time.Sleep(100 * time.Millisecond)
	assert.Less(t, st.count(), 15, "the poll interval is 1ms: without backoff it would retry about a hundred times")
	st.mu.Lock()
	c := st.calls
	assert.Greater(t, c[3].Sub(c[2]), c[1].Sub(c[0]), "the wait grows")
	st.mu.Unlock()

	_, err = r.Publish(bg, []byte("blob B"))
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	sends := len(f.node.sends())

	st.fail.Store(false)
	_, err = r.Publish(bg, []byte("blob B"))
	require.NoError(t, err, "a Publish asks for an attempt at once")
	sent := f.node.sends()
	require.Greater(t, len(sent), sends)
	assert.EqualValues(t, 4, txSequence(t, innerTx(sent[len(sent)-1])), "B is signed above the recovered intent")
}

func TestFastBlobCloseStopsAFailingRecovery(t *testing.T) {
	f := newBlobFast(t)
	st := &listFail{Store: f.st}
	st.fail.Store(true)
	r := f.recOn(st)
	require.Eventually(t, func() bool { return st.count() >= 2 }, 5*time.Second, time.Millisecond)
	require.NoError(t, r.Close(bg))
	n := st.count()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, n, st.count(), "no attempt after Close")
	_, err := r.Publish(bg, f.blob)
	require.Error(t, err)
}
