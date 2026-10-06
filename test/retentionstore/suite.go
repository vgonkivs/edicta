// Package retentionstore is the conformance suite every retention.Store
// implementation must pass.
package retentionstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/test/retentionfix"
)

// Handle is one store under test. Reopen drops every in-memory state of the
// implementation and returns a store over the same persisted data; a memory
// store returns itself.
type Handle struct {
	Store  retention.Store
	Reopen func() retention.Store
}

type Opener func(t *testing.T) *Handle

var ctx = context.Background()

var pol = retentionfix.Policy

func s(from, to, ret, at uint64) retention.Sample { return retentionfix.S(from, to, ret, at) }

func bound(t *testing.T, open Opener) *Handle {
	t.Helper()
	h := open(t)
	require.NoError(t, h.Store.Bind(ctx, "mocha-5"))
	return h
}

func Run(t *testing.T, open Opener) {
	t.Run("EmptyHasNoLast", func(t *testing.T) {
		h := bound(t, open)
		_, have, err := h.Store.Last(ctx)
		require.NoError(t, err)
		assert.False(t, have)
		runs, err := h.Store.Segment(ctx, 100)
		require.NoError(t, err)
		assert.Empty(t, runs)
	})

	t.Run("AppendReadBack", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 14400, 5000), pol))
		last, have, err := h.Store.Last(ctx)
		require.NoError(t, err)
		require.True(t, have)
		assert.Equal(t, retention.Run{
			Segment: last.Segment, FirstFrom: 100, FirstTo: 100, LastFrom: 100, LastTo: 100,
			RetentionS: 14400, FirstAt: 5000, LastAt: 5000,
		}, last)
		runs, err := h.Store.Segment(ctx, 100)
		require.NoError(t, err)
		assert.Equal(t, []retention.Run{last}, runs)
		runs, err = h.Store.Segment(ctx, 99)
		require.NoError(t, err)
		assert.Empty(t, runs, "below the first sample nothing is covered")
	})

	t.Run("SameValueExtendsTheRun", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Append(ctx, s(130, 130, 7, 5030), pol))
		runs, err := h.Store.Segment(ctx, 120)
		require.NoError(t, err)
		require.Len(t, runs, 1)
		assert.Equal(t, uint64(100), runs[0].FirstFrom)
		assert.Equal(t, uint64(100), runs[0].FirstTo)
		assert.Equal(t, uint64(130), runs[0].LastFrom)
		assert.Equal(t, uint64(130), runs[0].LastTo)
		assert.Equal(t, uint64(5000), runs[0].FirstAt)
		assert.Equal(t, uint64(5030), runs[0].LastAt)
	})

	t.Run("ChangedValueStartsARunInTheSameSegment", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Append(ctx, s(130, 130, 9, 5030), pol))
		runs, err := h.Store.Segment(ctx, 120)
		require.NoError(t, err)
		require.Len(t, runs, 2)
		assert.Equal(t, uint64(7), runs[0].RetentionS)
		assert.Equal(t, uint64(9), runs[1].RetentionS)
		assert.Equal(t, runs[0].Segment, runs[1].Segment)
		got, err := retention.AtHeight(runs, 120)
		require.NoError(t, err)
		assert.Equal(t, uint64(7), got)
	})

	t.Run("GapStartsANewSegment", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Append(ctx, s(1000, 1000, 7, 5030), pol))
		a, err := h.Store.Segment(ctx, 100)
		require.NoError(t, err)
		b, err := h.Store.Segment(ctx, 1000)
		require.NoError(t, err)
		require.Len(t, a, 1)
		require.Len(t, b, 1)
		assert.NotEqual(t, a[0].Segment, b[0].Segment)
		mid, err := h.Store.Segment(ctx, 500)
		require.NoError(t, err)
		assert.Empty(t, mid, "heights inside the gap are not covered")
	})

	t.Run("TimeGapStartsANewSegment", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Append(ctx, s(110, 110, 7, 5301), pol))
		last, _, err := h.Store.Last(ctx)
		require.NoError(t, err)
		runs, err := h.Store.Segment(ctx, 100)
		require.NoError(t, err)
		require.Len(t, runs, 1)
		assert.NotEqual(t, runs[0].Segment, last.Segment)
	})

	t.Run("EveryAppendIsDurable", func(t *testing.T) {
		h := bound(t, open)
		st := h.Store
		for i, smp := range []retention.Sample{
			s(100, 100, 7, 5000), s(130, 130, 7, 5030), s(160, 160, 9, 5060), s(190, 190, 9, 5090),
		} {
			require.NoError(t, st.Append(ctx, smp, pol), "append %d", i)
			want, haveWant, err := st.Last(ctx)
			require.NoError(t, err)
			st = h.Reopen()
			got, have, err := st.Last(ctx)
			require.NoError(t, err)
			require.Equal(t, haveWant, have)
			assert.Equal(t, want, got, "run lost after append %d", i)
		}
		runs, err := st.Segment(ctx, 150)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
	})

	t.Run("RestartContinuesWithinTheGaps", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		before, _, err := h.Store.Last(ctx)
		require.NoError(t, err)
		st := h.Reopen()
		require.NoError(t, st.Append(ctx, s(200, 200, 7, 5300), pol))
		after, _, err := st.Last(ctx)
		require.NoError(t, err)
		assert.Equal(t, before.Segment, after.Segment)
		assert.Equal(t, uint64(100), after.FirstFrom)
		runs, err := st.Segment(ctx, 150)
		require.NoError(t, err)
		assert.NotEmpty(t, runs)
	})

	t.Run("RestartBeyondTheGapsLeavesTheDowntimeUncovered", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		st := h.Reopen()
		require.NoError(t, st.Append(ctx, s(900, 900, 7, 9000), pol))
		runs, err := st.Segment(ctx, 500)
		require.NoError(t, err)
		assert.Empty(t, runs)
		old, err := st.Segment(ctx, 100)
		require.NoError(t, err)
		assert.NotEmpty(t, old, "the history before the downtime stays readable")
	})

	t.Run("ChainMismatchRefused", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Bind(ctx, "mocha-5"), "rebinding the same chain is a no-op")
		st := h.Reopen()
		require.ErrorIs(t, st.Bind(ctx, "mainnet"), retention.ErrChainMismatch)
		require.NoError(t, st.Bind(ctx, "mocha-5"))
	})

	t.Run("MismatchLeavesRunsUntouched", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		want, _, err := h.Store.Last(ctx)
		require.NoError(t, err)
		require.ErrorIs(t, h.Store.Bind(ctx, "other"), retention.ErrChainMismatch)
		got, have, err := h.Reopen().Last(ctx)
		require.NoError(t, err)
		require.True(t, have)
		assert.Equal(t, want, got)
	})

	t.Run("Prune", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Append(ctx, s(1000, 1000, 7, 9000), pol))
		n, err := h.Store.Prune(ctx, 7000)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		old, err := h.Store.Segment(ctx, 100)
		require.NoError(t, err)
		assert.Empty(t, old)
		cur, err := h.Store.Segment(ctx, 1000)
		require.NoError(t, err)
		assert.NotEmpty(t, cur)
		n, err = h.Store.Prune(ctx, 7000)
		require.NoError(t, err)
		assert.Zero(t, n)
	})

	t.Run("FreshSampleAfterPrune", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		_, err := h.Store.Prune(ctx, 5001)
		require.NoError(t, err)
		require.NoError(t, h.Store.Append(ctx, s(110, 110, 7, 5010), pol))
		runs, err := h.Store.Segment(ctx, 110)
		require.NoError(t, err)
		assert.NotEmpty(t, runs, "a fresh sample after a prune must stay readable")
	})

	t.Run("AppendBeforeBindRefused", func(t *testing.T) {
		h := open(t)
		require.Error(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
		require.NoError(t, h.Store.Bind(ctx, "mocha-5"))
		_, have, err := h.Store.Last(ctx)
		require.NoError(t, err)
		assert.False(t, have, "a refused write leaves nothing behind")
	})

	t.Run("EmptyChainIDRefused", func(t *testing.T) {
		h := open(t)
		require.Error(t, h.Store.Bind(ctx, ""))
		require.Error(t, h.Store.Append(ctx, s(100, 100, 7, 5000), pol))
	})

	t.Run("AppendUnderOtherChainRefused", func(t *testing.T) {
		h := bound(t, open)
		other := s(100, 100, 7, 5000)
		other.ChainID = "mainnet"
		require.ErrorIs(t, h.Store.Append(ctx, other, pol), retention.ErrChainMismatch)
		_, have, err := h.Store.Last(ctx)
		require.NoError(t, err)
		assert.False(t, have)
		same := s(100, 100, 7, 5000)
		same.ChainID = "mocha-5"
		require.NoError(t, h.Store.Append(ctx, same, pol))
	})

	t.Run("PruneKeepsTheNewestSegmentWhenTheClockSteppedBack", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 9000), pol))
		require.NoError(t, h.Store.Append(ctx, s(1000, 1000, 8, 100), pol))
		want, _, err := h.Store.Last(ctx)
		require.NoError(t, err)
		_, err = h.Store.Prune(ctx, 5000)
		require.NoError(t, err)
		got, have, err := h.Store.Last(ctx)
		require.NoError(t, err)
		require.True(t, have)
		assert.Equal(t, want, got)
		runs, err := h.Store.Segment(ctx, 1000)
		require.NoError(t, err)
		assert.NotEmpty(t, runs)
	})

	t.Run("PruneKeepsEveryRunOfTheNewestSegment", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 1000), pol))
		require.NoError(t, h.Store.Append(ctx, s(130, 130, 9, 1030), pol))
		n, err := h.Store.Prune(ctx, 5000)
		require.NoError(t, err)
		assert.Zero(t, n)
		runs, err := h.Store.Segment(ctx, 120)
		require.NoError(t, err)
		assert.Len(t, runs, 2)
	})

	t.Run("PruneStillDropsOlderSegments", func(t *testing.T) {
		h := bound(t, open)
		require.NoError(t, h.Store.Append(ctx, s(100, 100, 7, 1000), pol))
		require.NoError(t, h.Store.Append(ctx, s(1000, 1000, 7, 1100), pol))
		n, err := h.Store.Prune(ctx, 5000)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		cur, err := h.Store.Segment(ctx, 1000)
		require.NoError(t, err)
		assert.NotEmpty(t, cur)
	})

	t.Run("SegmentIDsAreNeverReusedAfterAPrune", func(t *testing.T) {
		h := bound(t, open)
		seen := map[uint64]bool{}
		next := func(smp retention.Sample) {
			require.NoError(t, h.Store.Append(ctx, smp, pol))
			last, _, err := h.Store.Last(ctx)
			require.NoError(t, err)
			require.False(t, seen[last.Segment], "segment %d reused", last.Segment)
			seen[last.Segment] = true
		}
		next(s(100, 100, 7, 9000))
		next(s(1000, 1000, 7, 100))
		next(s(2000, 2000, 7, 9500))
		_, err := h.Store.Prune(ctx, 5000)
		require.NoError(t, err)
		h.Store = h.Reopen()
		next(s(3000, 3000, 7, 9600))
		next(s(4000, 4000, 7, 9700))
	})
}
