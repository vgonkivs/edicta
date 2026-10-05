package recorder_test

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

func TestConcurrentPublishOfTheSameBlobSubmitsOnce(t *testing.T) {
	for round := 0; round < 20; round++ {
		ch := newChain()
		sub := newLanding(ch)
		rec := mk(t, cfg(), sub, ch)
		blob := []byte("one blob, many callers")
		const n = 8
		var wg sync.WaitGroup
		start := make(chan struct{})
		var ok atomic.Int32
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = rec.Publish(bg, blob)
				if errs[i] == nil {
					ok.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		sub.mu.Lock()
		calls := sub.Calls
		sub.mu.Unlock()
		require.Equal(t, 1, calls, "round %d: the blob is submitted once", round)
		assert.GreaterOrEqual(t, ok.Load(), int32(1))
		for _, err := range errs {
			if err != nil {
				assert.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "a caller that does not publish is told the outcome is pending")
			}
		}
	}
}

// landLate puts the blob on chain by hand, as a first tx that was still in a
// mempool when the first Publish gave up.
func landLate(t *testing.T, ch *nodefake.Chain, h uint64, blob []byte) {
	t.Helper()
	ch.AddHeader(blockAt(h))
	ch.AddBlob(h, node.Blob{Namespace: bytes.Clone(ns), Data: bytes.Clone(blob), ShareVersion: 1,
		Signer: bytes.Clone(signer), Commitment: realCommitment(t, ns, signer, blob)}, nil)
}

func TestScanMissThenLateLandingIsFoundWithoutResubmit(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	rec := mk(t, cfg(), sub, ch)
	blob := []byte("lands late")
	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	sub.Err = nil

	_, err = rec.Publish(bg, blob) // scan miss
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	head, _ := ch.Head(bg)
	landLate(t, ch, head.Height+1, blob)
	p, err := rec.Publish(bg, blob) // bounded re-scan finds it
	require.NoError(t, err)
	assert.Equal(t, head.Height+1, p.Ref.Height)
	assert.Equal(t, 1, sub.Calls, "never resubmitted")
}

func TestScanStartsAtTheHeightBeforeTheSubmitNotAtHeadMinusScanBlocks(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.ErrAfterLand = errBoom, true // lands at genesis+1
	c := cfg()                                // ScanBlocks 16
	rec := mk(t, c, sub, ch)
	blob := []byte("landed long ago")
	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	for h := genesis + 2; h <= genesis+40; h++ {
		ch.AddHeader(blockAt(h))
	}
	sub.Err = nil
	p, err := rec.Publish(bg, blob)
	require.NoError(t, err, "a blob more than ScanBlocks behind the head is still found")
	assert.Equal(t, genesis+1, p.Ref.Height)
	assert.Equal(t, 1, sub.Calls)
}
