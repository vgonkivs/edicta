package retention_test

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

const (
	iterations = 300
	lying      = uint64(99_999)
	headBase   = uint64(1_000_000)
)

// The latest value is a marker outside the history. For a height below the
// first sample taken from the latest source it may never be returned, in any
// mode, whatever the direct source says.
func TestFibreRetentionNeverSubstitutesTheLatest(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 13))
	for i := range iterations {
		st := memstore.New()
		require.NoError(t, st.Bind(ctx, "mocha-5"))

		var values []uint64
		h, at := uint64(1000+rng.IntN(500)), uint64(100)
		for range 1 + rng.IntN(12) {
			v := uint64(1 + rng.IntN(9))
			values = append(values, v)
			require.NoError(t, st.Append(ctx, S(h, h+uint64(rng.IntN(3)), v, at), Policy))
			h += uint64(rng.IntN(250))
			at += uint64(rng.IntN(500))
		}

		var direct retention.AtHeightSource
		switch rng.IntN(3) {
		case 0:
		case 1:
			direct = &Direct{Canary: []bool{false}, At: Const(lying)}
		case 2:
			direct = &Direct{Canary: []bool{true, false}, At: Const(lying)}
		}
		latest := Ticking("mocha-5", headBase, 1, func(int) uint64 { return lying })
		clk := NewClock(int64(at) + 1000)
		p, err := retention.NewParams(Policy, latest, direct, st, clk)
		require.NoError(t, err)
		require.NoError(t, p.Start(ctx))

		for range 20 {
			q := 1 + rng.Uint64N(headBase+50)
			got, err := p.FibreRetention(ctx, q)
			if q < headBase {
				if err == nil {
					require.True(t, slices.Contains(values, got), "iteration %d: height %d returned %d, not from the history %v", i, q, got, values)
				}
				require.NotEqual(t, lying, got, "iteration %d: height %d got the latest", i, q)
			}
		}
	}
}

// Behind a load balancer the head reads and the params read may hit backends
// up to lag blocks apart. Around a retention change at block c, no recorded
// answer may exceed the value really in force at the height asked.
func TestLoadBalancedSourceNeverExceedsTheTrueValue(t *testing.T) {
	const lag = 5
	rng := rand.New(rand.NewPCG(42, 1))
	pol := Policy
	pol.AssumedLagBlocks = lag
	covered := 0
	for i := range 2000 {
		c := uint64(200 + rng.IntN(100))
		before, after := uint64(1+rng.IntN(5)), uint64(1+rng.IntN(5))
		truth := func(h uint64) uint64 {
			if h < c {
				return before
			}
			return after
		}
		head := uint64(150)
		latest := NewLatest("mocha-5")
		latest.Fn = func(int) (retention.Sample, error) {
			head += uint64(rng.IntN(6))
			backend := func() uint64 { return head - uint64(rng.IntN(lag+1)) }
			a, x, b := backend(), backend(), backend()
			return retention.Sample{FromHeight: a, ToHeight: b, RetentionS: truth(x)}, nil
		}
		clk := NewClock(5000)
		p, err := retention.NewParams(pol, latest, nil, memstore.New(), clk)
		require.NoError(t, err)
		require.NoError(t, p.Start(ctx))
		for range 39 {
			clk.Advance(10)
			require.NoError(t, p.Observe(ctx))
		}
		latest.Fn = func(int) (retention.Sample, error) { return retention.Sample{}, errors.New("down") }

		for h := c - 2*lag - 2; h <= c+2*lag+2; h++ {
			got, err := p.FibreRetention(ctx, h)
			if err != nil {
				continue
			}
			covered++
			require.LessOrEqual(t, got, truth(h), "iteration %d: change at %d, height %d returned %d", i, c, h, got)
		}
	}
	require.NotZero(t, covered, "the property must not hold vacuously")
}
