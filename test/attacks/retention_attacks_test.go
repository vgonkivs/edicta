package attacks_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	rf "github.com/vgonkivs/edicta/test/retentionfix"
)

var _ gate.ChainParams = (*retention.Params)(nil)

func startParams(t *testing.T, latest retention.LatestSource, direct retention.AtHeightSource) (*retention.Params, retention.Store) {
	t.Helper()
	st := memstore.New()
	p, err := retention.NewParams(rf.Policy, latest, direct, st, rf.NewClock(5000))
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	return p, st
}

// A latest source that flips between a high and a low value cannot make the
// at-height value higher than the low one wherever a flip may have happened.
func TestRetentionAttackFlippingLatestSource(t *testing.T) {
	ctx := context.Background()
	const high, low = uint64(14400), uint64(60)
	flip := func(n int) uint64 {
		if n%2 == 0 {
			return high
		}
		return low
	}
	p, _ := startParams(t, rf.Ticking("mocha-5", 100, 50, flip), nil)
	for range 9 {
		require.NoError(t, p.Observe(ctx))
	}
	for h := uint64(150); h <= 500; h += 7 {
		got, err := p.FibreRetention(ctx, h)
		require.NoError(t, err, "height %d", h)
		assert.Equal(t, low, got, "height %d is next to a flip and must take the lower value", h)
	}
}

// The latest value is never the answer for a height the history does not
// cover, whether the source is lying, silent or ignoring heights.
func TestRetentionAttackLatestNeverFillsAHole(t *testing.T) {
	ctx := context.Background()
	const latestVal = uint64(14400)
	lying := &rf.Direct{Canary: []bool{true, false}, At: rf.Const(latestVal)}
	ignoring := &rf.Direct{Canary: []bool{false}, At: rf.Const(latestVal)}
	for name, d := range map[string]retention.AtHeightSource{"none": nil, "ignoring": ignoring, "failing paired canary": lying} {
		t.Run(name, func(t *testing.T) {
			p, _ := startParams(t, rf.Ticking("mocha-5", 10_000, 1, func(int) uint64 { return latestVal }), d)
			for _, h := range []uint64{1, 9_999, 5_000_000, math.MaxUint64} {
				got, err := p.FibreRetention(ctx, h)
				require.Error(t, err, "height %d", h)
				assert.Zero(t, got)
			}
		})
	}
}

func TestRetentionAttackDirectSourceThatPassesTheCanaryOnceThenLies(t *testing.T) {
	ctx := context.Background()
	d := &rf.Direct{Canary: []bool{true, false}, At: rf.Const(math.MaxUint64)}
	p, _ := startParams(t, rf.Ticking("mocha-5", 10_000, 1, func(int) uint64 { return 14400 }), d)
	require.False(t, p.ObservationsOnly())
	_, err := p.FibreRetention(ctx, 5_000)
	require.Error(t, err, "a read followed by a failed canary is discarded")
}

func TestRetentionAttackHugeAndZeroRetention(t *testing.T) {
	ctx := context.Background()
	cases := map[string]uint64{"zero": 0, "huge": math.MaxUint64}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := startParams(t, rf.Ticking("mocha-5", 100, 30, func(int) uint64 { return v }), nil)
			require.NoError(t, p.Observe(ctx))
			got, err := p.FibreRetention(ctx, 120)
			require.NoError(t, err)
			assert.Equal(t, v, got, "the observed value is reported as it is; the gate's minimum and margin decide")
		})
	}

	t.Run("zero history is not raised by a large latest value", func(t *testing.T) {
		p, _ := startParams(t, rf.Ticking("mocha-5", 100, 30, func(n int) uint64 {
			if n < 2 {
				return 0
			}
			return math.MaxUint64
		}), nil)
		require.NoError(t, p.Observe(ctx))
		got, err := p.FibreRetention(ctx, 115)
		require.NoError(t, err)
		assert.Zero(t, got)
	})
}

func TestRetentionAttackHeightsNearMaxUint64(t *testing.T) {
	ctx := context.Background()
	top := uint64(math.MaxUint64)

	t.Run("head near the maximum", func(t *testing.T) {
		p, _ := startParams(t, rf.Ticking("mocha-5", top-10, 1, func(int) uint64 { return 7 }), nil)
		require.NoError(t, p.Observe(ctx))
		got, err := p.FibreRetention(ctx, top-10)
		require.NoError(t, err)
		assert.Equal(t, uint64(7), got)
		_, err = p.FibreRetention(ctx, top)
		require.Error(t, err, "no sample reaches the maximum, so it is not covered")
		_, err = p.FibreRetention(ctx, top-100)
		require.Error(t, err)
	})

	t.Run("a head that wraps is a regression, not a continuation", func(t *testing.T) {
		vals := func(int) uint64 { return 7 }
		l := rf.NewLatest("mocha-5")
		l.Fn = func(n int) (retention.Sample, error) {
			if n == 0 {
				return rf.S(top-1, top, 7, 0), nil
			}
			return rf.S(0, 3, vals(n), 0), nil
		}
		p, st := startParams(t, l, nil)
		require.NoError(t, p.Observe(ctx))
		runs, err := st.Segment(ctx, top)
		require.NoError(t, err)
		for _, r := range runs {
			assert.GreaterOrEqual(t, r.LastFrom, r.FirstFrom, "no run may span the wrap")
		}
		_, err = p.FibreRetention(ctx, 1<<63)
		require.Error(t, err)
	})
}

// Concurrent checks and observations on one Params and one store are race
// free, and a covered height only reads values sampled around it.
func TestRetentionAttackConcurrentUse(t *testing.T) {
	ctx := context.Background()
	p, _ := startParams(t, rf.Ticking("mocha-5", 100, 1, func(n int) uint64 {
		if n == 0 {
			return 100
		}
		return 5
	}), nil)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := p.Observe(ctx); err != nil {
					errs <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				got, err := p.FibreRetention(ctx, 100)
				if err != nil {
					errs <- err
				} else if got != 100 && got != 5 {
					errs <- errors.New("height 100 may only read a value sampled around it")
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}
