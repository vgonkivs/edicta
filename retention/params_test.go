package retention_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

var ctx = context.Background()

// 100 for two samples, then 50, then 7: the latest value (7) must never
// stand in for an older one.
func history(n int) uint64 {
	switch {
	case n < 2:
		return 100
	case n == 2:
		return 50
	}
	return 7
}

func started(t *testing.T, direct retention.AtHeightSource) (*retention.Params, *Latest, retention.Store, *Clock) {
	t.Helper()
	clk := NewClock(5000)
	latest := Ticking("mocha-5", 100, 30, history)
	st := memstore.New()
	p, err := retention.NewParams(Policy, latest, direct, st, clk)
	require.NoError(t, err)
	require.NoError(t, p.Start(ctx))
	require.NoError(t, p.Observe(ctx))
	require.NoError(t, p.Observe(ctx))
	return p, latest, st, clk
}

func TestNewParamsRejectsMissingParts(t *testing.T) {
	clk := NewClock(1)
	l := NewLatest("c")
	st := memstore.New()
	_, err := retention.NewParams(Policy, nil, nil, st, clk)
	require.Error(t, err)
	_, err = retention.NewParams(Policy, l, nil, nil, clk)
	require.Error(t, err)
	_, err = retention.NewParams(Policy, l, nil, st, nil)
	require.Error(t, err)
	_, err = retention.NewParams(Policy, l, nil, st, clk)
	require.NoError(t, err)
}

func TestStart(t *testing.T) {
	t.Run("binds the chain and takes the first sample", func(t *testing.T) {
		clk := NewClock(5000)
		st := memstore.New()
		p, err := retention.NewParams(Policy, Ticking("mocha-5", 100, 30, history), nil, st, clk)
		require.NoError(t, err)
		require.NoError(t, p.Start(ctx))
		last, have, err := st.Last(ctx)
		require.NoError(t, err)
		require.True(t, have)
		assert.Equal(t, uint64(100), last.RetentionS)
		assert.Equal(t, uint64(5000), last.LastAt, "ObservedAt is the gate clock")
		require.ErrorIs(t, st.Bind(ctx, "mainnet"), retention.ErrChainMismatch)
	})

	t.Run("a store bound to another chain refuses", func(t *testing.T) {
		st := memstore.New()
		require.NoError(t, st.Bind(ctx, "mainnet"))
		p, err := retention.NewParams(Policy, Ticking("mocha-5", 100, 30, history), nil, st, NewClock(5000))
		require.NoError(t, err)
		require.ErrorIs(t, p.Start(ctx), retention.ErrChainMismatch)
	})

	t.Run("a failing first sample fails the start", func(t *testing.T) {
		boom := errors.New("boom")
		l := NewLatest("mocha-5", Step{Err: boom})
		p, err := retention.NewParams(Policy, l, nil, memstore.New(), NewClock(5000))
		require.NoError(t, err)
		require.ErrorIs(t, p.Start(ctx), boom)
	})

	t.Run("chain id error fails the start", func(t *testing.T) {
		boom := errors.New("boom")
		l := Ticking("mocha-5", 100, 30, history)
		l.ChainEr = boom
		p, err := retention.NewParams(Policy, l, nil, memstore.New(), NewClock(5000))
		require.NoError(t, err)
		require.ErrorIs(t, p.Start(ctx), boom)
	})
}

func TestObservationsOnlyMode(t *testing.T) {
	cases := []struct {
		name   string
		direct func() retention.AtHeightSource
		want   bool
	}{
		{"no direct source", func() retention.AtHeightSource { return nil }, true},
		{"canary fails", func() retention.AtHeightSource { return &Direct{Canary: []bool{false}, At: Const(1)} }, true},
		{"canary inconclusive", func() retention.AtHeightSource {
			return &Direct{CanaryErr: errors.New("timeout"), At: Const(1)}
		}, true},
		{"canary passes", func() retention.AtHeightSource { return &Direct{Canary: []bool{true}, At: Const(1)} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := retention.NewParams(Policy, Ticking("mocha-5", 100, 30, history), tc.direct(), memstore.New(), NewClock(5000))
			require.NoError(t, err)
			require.NoError(t, p.Start(ctx))
			assert.Equal(t, tc.want, p.ObservationsOnly())
		})
	}

	t.Run("a height-ignoring endpoint is never read", func(t *testing.T) {
		d := &Direct{Canary: []bool{false}, At: Const(1)}
		p, _, _, _ := started(t, d)
		_, err := p.FibreRetention(ctx, 115)
		require.NoError(t, err)
		assert.Zero(t, d.Reads())
	})
}

func TestFibreRetentionLatest(t *testing.T) {
	p, latest, st, clk := started(t, nil)
	clk.Advance(30)
	before := latest.Calls()
	got, err := p.FibreRetention(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), got, "height 0 is the latest value")
	assert.Greater(t, latest.Calls(), before)
	last, _, err := st.Last(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), last.RetentionS, "the sample is recorded")
}

func TestFibreRetentionFromObservations(t *testing.T) {
	// Runs after started: 100 sampled at 100 and 130, 50 at 160.
	cases := []struct {
		name   string
		height uint64
		want   uint64
		err    error
	}{
		{"first sampled height", 100, 100, nil},
		{"inside the first run", 115, 100, nil},
		{"between samples of different values: the minimum", 145, 50, nil},
		{"below the first sample", 99, 0, retention.ErrNotCovered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, _ := started(t, nil)
			got, err := p.FibreRetention(ctx, tc.height)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("above the newest run takes a sample on demand", func(t *testing.T) {
		p, _, _, _ := started(t, nil)
		got, err := p.FibreRetention(ctx, 175)
		require.NoError(t, err)
		assert.Equal(t, uint64(7), got, "both neighbours of the change may hold, the minimum counts")
	})

	t.Run("above the head with a dead source is unavailable", func(t *testing.T) {
		p, latest, _, _ := started(t, nil)
		boom := errors.New("down")
		latest.Fn = func(int) (retention.Sample, error) { return retention.Sample{}, boom }
		got, err := p.FibreRetention(ctx, 100_000)
		require.Error(t, err)
		assert.Zero(t, got)
	})
}

func TestFibreRetentionDirect(t *testing.T) {
	honest := func(v uint64) *Direct { return &Direct{Canary: []bool{true}, At: Const(v)} }
	cases := []struct {
		name   string
		d      *Direct
		height uint64
		want   uint64
		err    bool
	}{
		{"direct below the observations wins", honest(80), 115, 80, false},
		{"direct above the observations loses", honest(500), 115, 100, false},
		{"direct alone below the observations", honest(80), 99, 80, false},
		{"direct failing falls back to observations", &Direct{Canary: []bool{true}, At: func(uint64) (uint64, error) { return 0, errors.New("pruned") }}, 115, 100, false},
		{"direct failing and nothing observed is unavailable", &Direct{Canary: []bool{true}, At: func(uint64) (uint64, error) { return 0, errors.New("pruned") }}, 99, 0, true},
		{"failed paired canary discards the read", &Direct{Canary: []bool{true, false}, At: Const(5)}, 115, 100, false},
		{"failed paired canary and nothing observed", &Direct{Canary: []bool{true, false}, At: Const(5)}, 99, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.d
			p, _, _, _ := started(t, d)
			require.False(t, p.ObservationsOnly())
			got, err := p.FibreRetention(ctx, tc.height)
			if tc.err {
				require.Error(t, err)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDirectReadWithInconclusiveCanaryIsDiscarded(t *testing.T) {
	d := &Direct{Canary: []bool{true}}
	d.At = func(uint64) (uint64, error) { d.CanaryErr = errors.New("timeout"); return 5, nil }
	p, _, _, _ := started(t, d)
	require.False(t, p.ObservationsOnly())
	_, err := p.FibreRetention(ctx, 99)
	require.Error(t, err)
	got, err := p.FibreRetention(ctx, 115)
	require.NoError(t, err)
	assert.Equal(t, uint64(100), got)
}

func TestZeroAndHugeRetention(t *testing.T) {
	vals := func(n int) uint64 {
		if n < 2 {
			return 0
		}
		return 1<<64 - 1
	}
	clk := NewClock(5000)
	p, err := retention.NewParams(Policy, Ticking("mocha-5", 100, 30, vals), nil, memstore.New(), clk)
	require.NoError(t, err)
	require.NoError(t, p.Start(ctx))
	require.NoError(t, p.Observe(ctx))
	got, err := p.FibreRetention(ctx, 115)
	require.NoError(t, err)
	assert.Zero(t, got, "an observed zero is a value, not a hole to fill with the latest")

	d := &Direct{Canary: []bool{true}, At: Const(0)}
	p2, err := retention.NewParams(Policy, Ticking("mocha-5", 100, 30, func(int) uint64 { return 1<<64 - 1 }), d, memstore.New(), clk)
	require.NoError(t, err)
	require.NoError(t, p2.Start(ctx))
	require.NoError(t, p2.Observe(ctx))
	got, err = p2.FibreRetention(ctx, 115)
	require.NoError(t, err)
	assert.Zero(t, got, "the minimum with a direct zero")
}

func TestRestart(t *testing.T) {
	boot := func(t *testing.T, st retention.Store, clk *Clock, base uint64) *retention.Params {
		p, err := retention.NewParams(Policy, Ticking("mocha-5", base, 0, func(int) uint64 { return 100 }), nil, st, clk)
		require.NoError(t, err)
		require.NoError(t, p.Start(ctx))
		return p
	}

	t.Run("within both gaps the segment continues", func(t *testing.T) {
		st := memstore.New()
		clk := NewClock(5000)
		boot(t, st, clk, 100)
		clk.Advance(60)
		p := boot(t, st, clk, 190)
		got, err := p.FibreRetention(ctx, 150)
		require.NoError(t, err)
		assert.Equal(t, uint64(100), got)
	})

	t.Run("beyond the gaps only the downtime is uncovered", func(t *testing.T) {
		st := memstore.New()
		clk := NewClock(5000)
		boot(t, st, clk, 100)
		clk.Advance(5000)
		p := boot(t, st, clk, 500)
		_, err := p.FibreRetention(ctx, 300)
		require.ErrorIs(t, err, retention.ErrNotCovered)
		got, err := p.FibreRetention(ctx, 100)
		require.NoError(t, err)
		assert.Equal(t, uint64(100), got, "the history before the downtime stays")
		got, err = p.FibreRetention(ctx, 500)
		require.NoError(t, err)
		assert.Equal(t, uint64(100), got)
	})

	t.Run("a restart beyond the time gap only", func(t *testing.T) {
		st := memstore.New()
		clk := NewClock(5000)
		boot(t, st, clk, 100)
		clk.Advance(301)
		p := boot(t, st, clk, 150)
		_, err := p.FibreRetention(ctx, 125)
		require.ErrorIs(t, err, retention.ErrNotCovered)
	})

	t.Run("a restart beyond the block gap only", func(t *testing.T) {
		st := memstore.New()
		clk := NewClock(5000)
		boot(t, st, clk, 100)
		clk.Advance(10)
		p := boot(t, st, clk, 201)
		_, err := p.FibreRetention(ctx, 150)
		require.ErrorIs(t, err, retention.ErrNotCovered)
	})

	t.Run("the clock stepping back opens a segment", func(t *testing.T) {
		st := memstore.New()
		clk := NewClock(5000)
		boot(t, st, clk, 100)
		clk.Set(4000)
		p := boot(t, st, clk, 150)
		_, err := p.FibreRetention(ctx, 125)
		require.ErrorIs(t, err, retention.ErrNotCovered)
	})
}
