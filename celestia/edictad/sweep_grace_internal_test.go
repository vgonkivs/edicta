package edictad

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/gate/registry"
)

// A scan must not write a record for an entry whose own request may still be
// about to write it with the retention inputs: the archive keeps the first
// write. The hold does not depend on any clock.
func TestScanLeavesEntriesWhoseRequestIsAtWork(t *testing.T) {
	old := entryOf(1) // an earlier process: no request of this one waits for it
	mine := entryOf(3)
	mine.AuthorizedAt = 0 // a stepped clock changes nothing
	l := &memLister{entries: []registry.Entry{old, mine}}
	st := &memStore{}
	sw := newSweeper(st, l)

	sw.q.begin(mine.CommitmentHash)
	sw.q.begin(mine.CommitmentHash) // an identical request overlaps
	sw.run(context.Background(), true)
	assert.True(t, st.putAuthFor(old.CommitmentHash))
	assert.False(t, st.putAuthFor(mine.CommitmentHash))

	sw.q.end(mine.CommitmentHash)
	sw.run(context.Background(), true)
	assert.False(t, st.putAuthFor(mine.CommitmentHash), "one request is still at work")

	sw.q.end(mine.CommitmentHash)
	sw.run(context.Background(), true)
	assert.True(t, st.putAuthFor(mine.CommitmentHash), "a gap is repaired once no request is at work")
}

// A probe that fails at once, with no interval configured, is retried at a
// minimum interval and does not spin.
func TestBridgeFallbackProbeRetriesAtAMinimumInterval(t *testing.T) {
	var calls atomic.Int32
	cfg := Config{Fibre: FibreConfig{BridgeFallback: true, CanaryEveryS: 0}}
	_, probe := bridgeFallback(cfg, &FibreDeps{BridgeCompat: func(context.Context) error {
		calls.Add(1)
		return node.ErrUnavailable
	}}, discard)
	require.NotNil(t, probe)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	probe(ctx)
	assert.EqualValues(t, 1, calls.Load())
}

func TestValidateBasicRefusesAZeroCanaryIntervalForFibre(t *testing.T) {
	f := FibreConfig{MaxDataBytes: 1 << 20, MaxReadBytes: 1 << 20, LookupTimeoutS: 60, SampleEveryS: 30}
	c := Config{Network: NetworkConfig{DA: DAConfigFibre}, Fibre: f, Archive: ArchiveConfig{Dir: "x", WriteTimeoutS: 10, SweepIntervalS: 600}}
	assert.ErrorIs(t, c.validateFibre(), ErrConfig)
}
