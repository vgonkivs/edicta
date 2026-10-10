package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

func TestFastFibreMissingWithdrawalDelayUsesTheMaximum(t *testing.T) {
	f := newFibreFast(t)
	f.sub.EscrowVal = node.Escrow{AvailableUtia: 2*f.cost() + 10}
	log := &logBuf{}
	r := f.recLog(f.failingUpload(), log)
	for i := 0; i < 2; i++ {
		_, err := r.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
	}
	assert.Equal(t, 1, log.count("no fibre withdrawal delay"), "warned once")

	var short *recorder.EscrowShortfall
	day := uint64(24 * 3600)
	f.grow(f.h0 + day + 600)
	_, err := r.Publish(bg, f.sameSize(0x66))
	require.ErrorAs(t, err, &short, "a node without the parameter must not get the 24 h default")
	f.grow(f.h0 + 6*day)
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.ErrorAs(t, err, &short, "held up to the chain maximum of 7 days")
	f.grow(f.h0 + 8*day)
	_, err = r.Publish(bg, f.sameSize(0x66))
	require.False(t, errors.As(err, &short), "released after 7 days: %v", err)
}
