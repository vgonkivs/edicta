package retention_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/retention"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

func TestNext(t *testing.T) {
	last := retention.Run{
		Segment: 3, FirstFrom: 10, FirstTo: 12, LastFrom: 40, LastTo: 42,
		RetentionS: 100, FirstAt: 1000, LastAt: 1030,
	}
	extended := func(s retention.Sample) retention.Run {
		r := last
		r.LastFrom, r.LastTo, r.LastAt = s.FromHeight, s.ToHeight, s.ObservedAt
		return r
	}
	fresh := func(seg uint64, s retention.Sample) retention.Run {
		return retention.Run{
			Segment: seg, FirstFrom: s.FromHeight, FirstTo: s.ToHeight, LastFrom: s.FromHeight, LastTo: s.ToHeight,
			RetentionS: s.RetentionS, FirstAt: s.ObservedAt, LastAt: s.ObservedAt,
		}
	}

	cases := []struct {
		name      string
		s         retention.Sample
		wantRun   func(retention.Sample) retention.Run
		appendNew bool
	}{
		{"same value extends the run", S(50, 52, 100, 1060), extended, false},
		{"same height and time still extend", S(40, 42, 100, 1030), extended, false},
		{"restart within both gaps continues", S(140, 142, 100, 1330), extended, false},
		{"block gap above the limit opens a segment", S(141, 143, 100, 1330), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"time gap above the limit opens a segment", S(50, 52, 100, 1331), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"restart beyond both gaps opens a segment", S(5000, 5002, 100, 9000), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"heights regress", S(30, 32, 100, 1060), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"clock goes backwards", S(50, 52, 100, 1029), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"value changed between samples keeps the segment", S(50, 52, 80, 1060), func(s retention.Sample) retention.Run { return fresh(3, s) }, true},
		{"value raised between samples keeps the segment", S(50, 52, 200, 1060), func(s retention.Sample) retention.Run { return fresh(3, s) }, true},
		{"change and regress opens a segment", S(30, 32, 80, 1060), func(s retention.Sample) retention.Run { return fresh(4, s) }, true},
		{"zero retention is a value", S(50, 52, 0, 1060), func(s retention.Sample) retention.Run { return fresh(3, s) }, true},
		{"huge retention is a value", S(50, 52, math.MaxUint64, 1060), func(s retention.Sample) retention.Run { return fresh(3, s) }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, appendNew := retention.Next(last, true, tc.s, Policy)
			assert.Equal(t, tc.wantRun(tc.s), got)
			assert.Equal(t, tc.appendNew, appendNew)
		})
	}

	t.Run("first sample", func(t *testing.T) {
		s := S(50, 52, 100, 1060)
		got, appendNew := retention.Next(retention.Run{}, false, s, Policy)
		assert.True(t, appendNew)
		want := fresh(got.Segment, s)
		assert.Equal(t, want, got)
	})

	t.Run("change and revert inside one gap is merged", func(t *testing.T) {
		// Known residual: a value that changed and came back between two
		// samples leaves no trace; the run simply continues.
		got, appendNew := retention.Next(last, true, S(80, 82, 100, 1100), Policy)
		assert.False(t, appendNew)
		assert.Equal(t, uint64(100), got.RetentionS)
		assert.Equal(t, uint64(80), got.LastFrom)
	})

	t.Run("heights near the maximum do not overflow", func(t *testing.T) {
		top := retention.Run{Segment: 1, FirstFrom: math.MaxUint64 - 10, FirstTo: math.MaxUint64 - 9,
			LastFrom: math.MaxUint64 - 10, LastTo: math.MaxUint64 - 9, RetentionS: 5, FirstAt: 1, LastAt: 1}
		got, appendNew := retention.Next(top, true, S(math.MaxUint64-1, math.MaxUint64, 5, 2), Policy)
		assert.False(t, appendNew)
		assert.Equal(t, uint64(math.MaxUint64), got.LastTo)

		low := retention.Run{Segment: 1, FirstFrom: 0, FirstTo: 0, LastFrom: 0, LastTo: 0, RetentionS: 5, FirstAt: 1, LastAt: 1}
		got, appendNew = retention.Next(low, true, S(math.MaxUint64, math.MaxUint64, 5, 2), Policy)
		assert.True(t, appendNew, "a jump to the top is a gap, not a wrapped small difference")
		assert.Equal(t, uint64(2), got.Segment)

		got, appendNew = retention.Next(top, true, S(0, 0, 5, 2), Policy)
		assert.True(t, appendNew)
		assert.Equal(t, uint64(2), got.Segment)
	})

	t.Run("time near the maximum does not overflow", func(t *testing.T) {
		late := last
		late.LastAt = math.MaxUint64 - 5
		got, appendNew := retention.Next(late, true, S(50, 52, 100, math.MaxUint64), Policy)
		assert.False(t, appendNew)
		assert.Equal(t, uint64(math.MaxUint64), got.LastAt)
		got, appendNew = retention.Next(last, true, S(50, 52, 100, math.MaxUint64), Policy)
		assert.True(t, appendNew)
		assert.Equal(t, uint64(4), got.Segment)
	})
}
