package edictad_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibreworld"
)

// recordWaits stands in for the start's retry sleep and records each wait.
func recordWaits(waits *[]time.Duration, after func(n int)) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*waits = append(*waits, d)
		if after != nil {
			after(len(*waits))
		}
		return nil
	}
}

var startBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}

// The fast fibre Recorder never starts on guessed x/fibre params: after six
// reads with a doubling wait the daemon refuses to start, naming what failed
// and the node it asked.
func TestRecorderFastFibreStartRefusesUnreadableParams(t *testing.T) {
	cases := map[string]func(rf *fibreRecFakes){
		"query fails": func(rf *fibreRecFakes) { rf.node.Fail = errSeam },
		"withdrawal delay missing": func(rf *fibreRecFakes) {
			p := fastFibreParams
			p.WithdrawalDelayS = 0
			rf.node.SetFibreParams(p)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			p, rf, up := fibreFastEnv(t)
			setup(rf)
			var waits []time.Duration
			p.deps.RetryWait = recordWaits(&waits, nil)
			srv, err := edictad.Start(bg, p.cfg(p.fibreFastEdits()...), p.deps)
			require.ErrorIs(t, err, edictad.ErrFibreParams)
			require.Nil(t, srv)
			assert.Contains(t, err.Error(), fibreworld.Endpoint)
			assert.Contains(t, err.Error(), "withdrawal delay")
			assert.Contains(t, err.Error(), "after 6 attempts")
			assert.Equal(t, startBackoff, waits)
			assert.Zero(t, p.listens)
			assert.Zero(t, rf.builds.Load(), "the Recorder is never built")
			assert.EqualValues(t, 1, up.closes.Load())
			assert.EqualValues(t, 1, rf.closer.closes.Load())
			p.registryReopens()
		})
	}
}

// A node that answers within the retries lets the daemon start, and the
// snapshot read is the Recorder's first cached one.
func TestRecorderFastFibreStartRetriesTheParams(t *testing.T) {
	p, rf, _ := fibreFastEnv(t)
	rf.node.Fail = errSeam
	var waits []time.Duration
	p.deps.RetryWait = recordWaits(&waits, func(n int) {
		if n == 3 {
			rf.node.Fail = nil
		}
	})
	p.start(p.fibreFastEdits()...)
	assert.Equal(t, startBackoff[:3], waits)
	d := rf.deps.Load()
	require.NotNil(t, d.Params)
	assert.Equal(t, fastFibreParams, *d.Params)
	assert.Len(t, p.logLines("level=WARN", "reading x/fibre params failed", fibreworld.Endpoint), 3)
}

// A cancelled start stops waiting for the params.
func TestRecorderFastFibreStartParamsWaitEndsWithTheContext(t *testing.T) {
	p, rf, _ := fibreFastEnv(t)
	rf.node.Fail = errSeam
	p.deps.RetryWait = func(context.Context, time.Duration) error { return context.Canceled }
	_, err := edictad.Start(bg, p.cfg(p.fibreFastEdits()...), p.deps)
	require.ErrorIs(t, err, edictad.ErrFibreParams)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, rf.builds.Load())
}

type blockingParamsChain struct {
	recorder.FibreChain
	calls atomic.Int32
}

func (b *blockingParamsChain) FibreParams(ctx context.Context) (node.FibreParams, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return node.FibreParams{}, ctx.Err()
}

// A node that never answers fails each attempt on its own timeout, so the
// start still refuses after the retries.
func TestRecorderFastFibreStartParamsReadTimesOut(t *testing.T) {
	p, rf, _ := fibreFastEnv(t)
	chain := &blockingParamsChain{FibreChain: rf.node}
	p.deps.Fibre.RecorderChain = chain
	p.deps.ParamsTimeout = 5 * time.Millisecond
	var waits []time.Duration
	p.deps.RetryWait = recordWaits(&waits, nil)
	_, err := edictad.Start(bg, p.cfg(p.fibreFastEdits()...), p.deps)
	require.ErrorIs(t, err, edictad.ErrFibreParams)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.EqualValues(t, 6, chain.calls.Load())
	assert.Equal(t, startBackoff, waits)
	assert.Zero(t, rf.builds.Load())
}
