package retention_test

import (
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
