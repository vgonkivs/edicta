package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// logBuf collects log lines for assertions.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.b.String(), s)
}

func (f *fibreFast) recLog(up node.FibreUploader, log *logBuf) *recorder.FibreRecorder {
	f.t.Helper()
	d := f.deps()
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: up,
		Log: slog.New(slog.NewTextHandler(log, nil))}
	r, err := recorder.NewFibre(f.cfg(f.st), d)
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r
}

// failingUpload fails every upload of the live blob after the shards may have
// left: the promise can already be in the validators' hands.
func (f *fibreFast) failingUpload() *hookUploader {
	return &hookUploader{liveUploader: f.up, hook: func(_ context.Context, blob []byte) error {
		if bytes.Equal(blob, f.blob) {
			return errTransport
		}
		return nil
	}}
}

func TestFastFibreUploadErrorKeepsTheEscrowReserved(t *testing.T) {
	f := newFibreFast(t)
	f.fibreFx.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 60, WithdrawalDelayS: 120})
	f.sub.EscrowVal = node.Escrow{AvailableUtia: f.cost() + 10}
	r := f.recWith(f.st, f.failingUpload())
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)

	var short *recorder.EscrowShortfall
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.ErrorAs(t, err, &short, "a failed upload may have left a chargeable promise")
	f.grow(f.h0 + 100)
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.ErrorAs(t, err, &short, "held through the withdrawal delay plus the clock skew")
	f.grow(f.h0 + 400)
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.False(t, errors.As(err, &short), "released once no settlement can charge it: %v", err)
}

// weekS is the withdrawal delay of the fixtures that do not test it.
const weekS = 7 * 24 * 3600

// paramsChain makes the x/fibre params read fail on demand, leaving the other
// reads of the node alone.
type paramsChain struct {
	recorder.FibreChain
	fail  atomic.Bool
	calls atomic.Int32
}

func (c *paramsChain) FibreParams(ctx context.Context) (node.FibreParams, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return node.FibreParams{}, errTransport
	}
	return c.FibreChain.FibreParams(ctx)
}

func (f *fibreFast) recParams(chain *paramsChain, first *node.FibreParams, log *logBuf) *recorder.FibreRecorder {
	f.t.Helper()
	d := f.deps()
	chain.FibreChain = d.Chain
	d.Chain, d.Params = chain, first
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: f.up,
		Log: slog.New(slog.NewTextHandler(log, nil))}
	r, err := recorder.NewFibre(f.cfg(f.st), d)
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r
}

// A node that does not report the withdrawal delay gives no readable params:
// nothing is uploaded on a guessed escrow hold.
func TestFastFibreMissingWithdrawalDelayIsUnreadable(t *testing.T) {
	f := newFibreFast(t)
	f.fibreFx.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 3600})
	f.sub.EscrowVal = node.Escrow{AvailableUtia: 2*f.cost() + 10}
	r := f.recLog(f.up, &logBuf{})
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.Contains(t, err.Error(), "withdrawal delay")
	assert.Zero(t, f.up.calls.Load(), "nothing is uploaded")

	missing := node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow, PromiseTimeoutS: 3600}
	d := f.deps()
	d.Params = &missing
	d.Fast = &recorder.FastDeps{Signer: liveSigner{f.fibreFx}, Node: f.node, Uploader: f.up}
	_, err = recorder.NewFibre(f.cfg(f.st), d)
	require.Error(t, err, "a first snapshot without the delay is refused too")
}

// Without any snapshot read, a failing params query refuses the upload.
func TestFastFibreParamsNeverReadRefusesTheUpload(t *testing.T) {
	f := newFibreFast(t)
	f.sub.EscrowVal = node.Escrow{AvailableUtia: 2*f.cost() + 10}
	chain := &paramsChain{}
	chain.fail.Store(true)
	r := f.recParams(chain, nil, &logBuf{})
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	assert.Zero(t, f.up.calls.Load(), "nothing is uploaded")
}

// Once a snapshot was read, a failing params query does not stop publishing:
// the Recorder goes on with the last snapshot and warns once per failure
// streak.
func TestFastFibreParamsFailureContinuesOnTheCachedSnapshot(t *testing.T) {
	f := newFibreFast(t)
	f.sub.EscrowVal = node.Escrow{AvailableUtia: 10 * f.cost()}
	first, err := f.fibreFx.node.FibreParams(bg)
	require.NoError(t, err)
	chain := &paramsChain{}
	chain.fail.Store(true)
	log := &logBuf{}
	r := f.recParams(chain, &first, log)
	f.land()

	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err, "the first snapshot, read before the build, is used")
	assert.True(t, pub.Ref.Pending())
	assert.EqualValues(t, 1, f.up.calls.Load())
	n := chain.calls.Load()
	require.Positive(t, n, "the params are read again")
	_, _ = r.Publish(bg, f.sameSize(0x66))
	require.Greater(t, chain.calls.Load(), n)
	const warn = "x/fibre params unreadable; continuing on the last snapshot read"
	assert.Equal(t, 1, log.count(warn), "warned once per failure streak")
	assert.Equal(t, 1, log.count(fibreEndpoint), "the warning names the endpoint")

	chain.fail.Store(false)
	_, _ = r.Publish(bg, f.sameSize(0x67))
	chain.fail.Store(true)
	_, _ = r.Publish(bg, f.sameSize(0x68))
	assert.Equal(t, 2, log.count(warn), "a new streak warns again")
}
