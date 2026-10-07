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

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// A scan must not write a record for an entry whose own request may still be
// about to write it with the retention inputs: the archive keeps the first
// write.
func TestScanLeavesRecentEntriesToTheirRequests(t *testing.T) {
	now := time.Unix(10_000, 0)
	old := entryOf(1)   // authorized at 1, before this process started
	prior := entryOf(2) // authorized by an earlier process, just before start
	prior.AuthorizedAt = 9_990
	mine := entryOf(3) // authorized by this process a moment ago
	mine.AuthorizedAt = 9_995
	l := &memLister{entries: []registry.Entry{old, prior, mine}}
	st := &memStore{}
	sw := newSweeper(st, l)
	sw.clock, sw.grace, sw.startedAt = fixedClock{now}, 100*time.Second, 9_990

	res := sw.run(context.Background(), true)
	assert.True(t, st.putAuthFor(old.CommitmentHash))
	assert.True(t, st.putAuthFor(prior.CommitmentHash), "no request of this process waits for it")
	assert.False(t, st.putAuthFor(mine.CommitmentHash), "left to the request path")
	assert.True(t, res.deferred, "and found again by a later scan")

	sw.clock = fixedClock{now.Add(200 * time.Second)}
	res = sw.run(context.Background(), true)
	assert.True(t, st.putAuthFor(mine.CommitmentHash), "after the grace a crash gap is repaired")
	assert.False(t, res.deferred)
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
