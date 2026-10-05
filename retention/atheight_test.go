package retention_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
)

func run(seg, firstFrom, firstTo, lastFrom, lastTo, v uint64) retention.Run {
	return retention.Run{Segment: seg, FirstFrom: firstFrom, FirstTo: firstTo, LastFrom: lastFrom, LastTo: lastTo, RetentionS: v}
}

func TestAtHeight(t *testing.T) {
	// A holds 100 until the change, B holds 50 after it; the change is
	// somewhere between A's last sample (50) and B's first (62).
	a := run(1, 10, 12, 50, 52, 100)
	b := run(1, 60, 62, 90, 92, 50)
	c := run(1, 100, 100, 100, 100, 70)

	cases := []struct {
		name   string
		runs   []retention.Run
		height uint64
		want   uint64
		err    error
	}{
		{"no runs", nil, 5, 0, retention.ErrNotCovered},
		{"below the first sample", []retention.Run{a, b}, 11, 0, retention.ErrNotCovered},
		{"at the first upper bound", []retention.Run{a, b}, 12, 100, nil},
		{"inside the first run only", []retention.Run{a, b}, 30, 100, nil},
		{"last sample of A: B may already hold", []retention.Run{a, b}, 50, 50, nil},
		{"between samples: both neighbours, the minimum", []retention.Run{a, b}, 55, 50, nil},
		{"B first bound: A may still hold", []retention.Run{a, b}, 62, 50, nil},
		{"after A can no longer hold", []retention.Run{a, b}, 63, 50, nil},
		{"last covered height", []retention.Run{a, b}, 90, 50, nil},
		{"above the last sample", []retention.Run{a, b}, 91, 0, retention.ErrNotCovered},
		{"single run, point sample", []retention.Run{c}, 100, 70, nil},
		{"single run, next height", []retention.Run{c}, 101, 0, retention.ErrNotCovered},
		{"value raised: min picks the lower neighbour", []retention.Run{run(1, 10, 10, 20, 20, 50), run(1, 30, 30, 40, 40, 200)}, 25, 50, nil},
		{"value raised: after the lower run only the higher can hold", []retention.Run{run(1, 10, 10, 20, 20, 50), run(1, 30, 30, 40, 40, 200)}, 35, 200, nil},
		{"zero retention wins", []retention.Run{run(1, 10, 10, 20, 20, 0), run(1, 30, 30, 40, 40, 9)}, 25, 0, nil},
		{"huge retention is returned as is", []retention.Run{run(1, 10, 10, 40, 40, math.MaxUint64)}, 20, math.MaxUint64, nil},
		{"max height covered", []retention.Run{run(1, math.MaxUint64-5, math.MaxUint64-5, math.MaxUint64, math.MaxUint64, 8)}, math.MaxUint64, 8, nil},
		{"max height uncovered", []retention.Run{run(1, 10, 10, 40, 40, 8)}, math.MaxUint64, 0, retention.ErrNotCovered},
		{"height zero uncovered", []retention.Run{run(1, 10, 10, 40, 40, 8)}, 0, 0, retention.ErrNotCovered},
		{
			// A lag of 40 blocks makes each sample a wide bracket: B's first
			// sample may have been taken at 60, so A may hold up to 100.
			"lag widens the bracket", []retention.Run{run(1, 10, 52, 20, 60, 50), run(1, 60, 100, 150, 190, 100)}, 80, 50, nil,
		},
		{"lag widened bracket ends where B is certain", []retention.Run{run(1, 10, 52, 20, 60, 50), run(1, 60, 100, 150, 190, 100)}, 101, 100, nil},
		{"lag widened bracket leaves early heights uncovered", []retention.Run{run(1, 10, 52, 20, 60, 50), run(1, 60, 100, 150, 190, 100)}, 30, 0, retention.ErrNotCovered},
		{
			"gap between segments is not covered",
			[]retention.Run{run(1, 10, 10, 50, 50, 100), run(2, 500, 500, 600, 600, 100)}, 300, 0, retention.ErrNotCovered,
		},
		{
			"segments are evaluated apart",
			[]retention.Run{run(1, 10, 10, 50, 50, 100), run(2, 500, 500, 600, 600, 20)}, 30, 100, nil,
		},
		{
			"second segment does not leak into the first",
			[]retention.Run{run(1, 10, 10, 50, 50, 100), run(2, 500, 500, 600, 600, 20)}, 550, 20, nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := retention.AtHeight(tc.runs, tc.height)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("change and revert inside one gap is missed", func(t *testing.T) {
		// Known residual: 100 -> 10 -> 100 between two samples leaves one
		// run of 100, so the too high value is returned, never an error and
		// never the latest.
		merged := run(1, 10, 12, 90, 92, 100)
		got, err := retention.AtHeight([]retention.Run{merged}, 50)
		require.NoError(t, err)
		assert.Equal(t, uint64(100), got)
	})

	t.Run("one change between samples is covered", func(t *testing.T) {
		before := run(1, 10, 12, 50, 52, 100)
		after := run(1, 90, 92, 120, 122, 10)
		for _, h := range []uint64{50, 70, 92} {
			got, err := retention.AtHeight([]retention.Run{before, after}, h)
			require.NoError(t, err)
			assert.Equal(t, uint64(10), got, "height %d", h)
		}
	})

	t.Run("input is not modified", func(t *testing.T) {
		in := []retention.Run{a, b}
		_, err := retention.AtHeight(in, 55)
		require.NoError(t, err)
		assert.Equal(t, []retention.Run{a, b}, in)
	})
}
