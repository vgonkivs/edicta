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
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// countReader counts the anchor lookups per height and per call context and
// can make each one slow.
type countReader struct {
	*evReader
	mu      sync.Mutex
	perH    map[uint64]int
	perCtx  map[context.Context]int
	delay   time.Duration
	started chan struct{}
}

func newCountReader(rd *evReader) *countReader {
	return &countReader{evReader: rd, perH: map[uint64]int{}, perCtx: map[context.Context]int{}, started: make(chan struct{})}
}

func (r *countReader) Blob(ctx context.Context, h uint64, ns, comm []byte) (node.Blob, error) {
	r.mu.Lock()
	r.perH[h]++
	r.perCtx[ctx]++
	delay := r.delay
	if delay > 0 {
		select {
		case <-r.started:
		default:
			close(r.started)
		}
	}
	r.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return r.evReader.Blob(ctx, h, ns, comm)
}

func (r *countReader) slow(d time.Duration) {
	r.mu.Lock()
	r.delay = d
	r.mu.Unlock()
}

func (r *countReader) stats() (heights, maxPerHeight, maxPerCall int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.perH {
		maxPerHeight = max(maxPerHeight, n)
	}
	for _, n := range r.perCtx {
		maxPerCall = max(maxPerCall, n)
	}
	return len(r.perH), maxPerHeight, maxPerCall
}

func (f *blobFast) recRd(rd node.Reader, timeout uint64) *recorder.Recorder {
	f.t.Helper()
	c := archCfg(f.st)
	c.Now = followHead(f.ch)
	c.FastTimeoutBlocks = timeout
	r, err := recorder.NewFast(c, recorder.FastDeps{Signer: f.sig, Node: f.node}, rd)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = r.Close(context.Background()) })
	return r
}

// The verdict scan of an intent whose anchor never lands reads each block of
// its window once, a bounded number per call, so the intent closes however
// wide the window is.
func TestFastBlobExpiredIntentClosesWithBoundedWorkPerStep(t *testing.T) {
	f := newBlobFast(t)
	rd := newCountReader(f.rd)
	r := f.recRd(rd, 1000)
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	for h := genesis + 1; h <= genesis+1001; h++ {
		f.ch.AddHeader(blockAt(h))
	}
	require.Eventually(t, func() bool {
		// A context per call, so that the lookups are counted per call.
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		_, err := r.Publish(ctx, f.blob)
		return isExpired(err)
	}, 10*time.Second, 5*time.Millisecond)

	heights, perHeight, perCall := rd.stats()
	assert.Equal(t, 1001, heights, "every block of the window is read")
	assert.LessOrEqual(t, perHeight, 2, "no rescan from the reference height")
	assert.LessOrEqual(t, perCall, 64, "one step reads a bounded number of blocks")
}

func isExpired(err error) bool { return errors.Is(err, recorder.ErrAnchorExpired) }

// A stale verdict reads blocks outside the sequence lock: another blob's
// intent is signed and sent meanwhile.
func TestFastBlobStaleScanDoesNotBlockAnotherSend(t *testing.T) {
	f := newBlobFast(t)
	rd := newCountReader(f.rd)
	r := f.recRd(rd, 100)
	f.node.script(errTransport)
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	for h := genesis + 1; h <= genesis+40; h++ {
		f.ch.AddHeader(blockAt(h))
	}
	rd.slow(20 * time.Millisecond)
	f.node.script(mismatch(9))
	go func() { _, _ = r.Publish(bg, f.blob) }()

	select {
	case <-rd.started:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the stale verdict never scanned")
	}
	start := time.Now()
	pub, err := r.Publish(bg, []byte("blob B"))
	require.NoError(t, err)
	assert.True(t, pub.Ref.Pending())
	assert.Less(t, time.Since(start), 400*time.Millisecond, "the send waited for the block scan")
	sent := f.node.sends()
	assert.EqualValues(t, 9, txSequence(t, innerTx(sent[len(sent)-1])), "B follows the sequence the refusal named")

	require.Eventually(t, func() bool {
		_, err := r.Publish(bg, f.blob)
		return errors.Is(err, recorder.ErrIntentStale)
	}, 10*time.Second, 5*time.Millisecond)
}
