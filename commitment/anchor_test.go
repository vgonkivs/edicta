package commitment_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func anchorParams(skew uint64) commitment.Params {
	return commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: skew}
}

// TestSignedBeforeAnchorVectors: issued_at + skew must reach the block time.
func TestSignedBeforeAnchorVectors(t *testing.T) {
	var af struct {
		K1 []struct {
			ID          string `json:"id"`
			IssuedAt    string `json:"issued_at"`
			BlockTime   string `json:"block_time"`
			SkewS       string `json:"skew_s"`
			ExpectError string `json:"expect_error"`
		} `json:"k1"`
	}
	loadJSON(t, "anchor.json", &af)
	require.GreaterOrEqualf(t, len(af.K1), 6, "%d vectors", len(af.K1))
	for _, v := range af.K1 {
		t.Run(v.ID, func(t *testing.T) {
			c := &commitment.Commitment{IssuedAt: u64(t, v.IssuedAt)}
			err := commitment.CheckAnchorTime(c, u64(t, v.BlockTime), anchorParams(u64(t, v.SkewS)))
			if v.ExpectError == "" {
				require.NoError(t, err)
				return
			}
			assertSentinel(t, err, v.ExpectError)
		})
	}
}

func TestSignedBeforeAnchorSentinelHasVector(t *testing.T) {
	var af struct {
		K1 []struct {
			ExpectError string `json:"expect_error"`
		} `json:"k1"`
	}
	loadJSON(t, "anchor.json", &af)
	for _, v := range af.K1 {
		if v.ExpectError == "ErrIssuedBeforeAnchor" {
			return
		}
	}
	require.FailNow(t, "no anchor vector expects ErrIssuedBeforeAnchor")
}

func TestSignedBeforeAnchorSaturates(t *testing.T) {
	// issued_at + skew must not wrap around.
	c := &commitment.Commitment{IssuedAt: ^uint64(0) - 10}
	err := commitment.CheckAnchorTime(c, ^uint64(0), anchorParams(300))
	require.NoError(t, err, "saturated sum should reach the maximum block time")
}

// TestRetentionWindowVectors: margin and the window inequality.
func TestRetentionWindowVectors(t *testing.T) {
	var af struct {
		MarginCap string `json:"margin_cap"`
		K2        []struct {
			ID         string `json:"id"`
			ValidUntil string `json:"valid_until"`
			Expect     struct {
				Within *bool   `json:"within"`
				R      *string `json:"r"`
				Start  *string `json:"start"`
				Margin *string `json:"margin"`
			} `json:"expect"`
		} `json:"k2"`
	}
	loadJSON(t, "anchor.json", &af)
	checked := 0
	for _, v := range af.K2 {
		if v.Expect.R == nil || v.Expect.Start == nil || v.Expect.Within == nil {
			continue
		}
		checked++
		t.Run(v.ID, func(t *testing.T) {
			r, start := u64(t, *v.Expect.R), u64(t, *v.Expect.Start)
			got, want := commitment.RetentionMargin(r), u64(t, *v.Expect.Margin)
			require.Equal(t, want, got)
			c := &commitment.Commitment{ValidUntil: u64(t, v.ValidUntil)}
			within := commitment.WithinRetention(c, start, r)
			require.Equal(t, *v.Expect.Within, within)
		})
	}
	require.GreaterOrEqualf(t, checked, 12, "only %d window vectors checked", checked)
	require.EqualValues(t, 600, u64(t, af.MarginCap), "margin cap")
}

func TestRetentionMarginTable(t *testing.T) {
	for _, tc := range []struct{ r, want uint64 }{
		{0, 0}, {1, 0}, {7, 0}, {8, 1}, {600, 75}, {4799, 599}, {4800, 600}, {14400, 600}, {^uint64(0), 600},
	} {
		got := commitment.RetentionMargin(tc.r)
		assert.Equal(t, tc.want, got)
	}
}

func TestWithinRetentionBoundaryAndSaturation(t *testing.T) {
	const start, r = uint64(1000), uint64(14400)
	limit := start + r - commitment.RetentionMargin(r)
	assert.True(t, commitment.WithinRetention(&commitment.Commitment{ValidUntil: limit}, start, r), "equality must be within")
	assert.False(t, commitment.WithinRetention(&commitment.Commitment{ValidUntil: limit + 1}, start, r), "one second over must be outside")
	assert.True(t, commitment.WithinRetention(&commitment.Commitment{ValidUntil: 1 << 62}, ^uint64(0)-5, 14400), "start + retention must saturate, not wrap")
	assert.False(t, commitment.WithinRetention(nil, start, r), "nil commitment is never within the window")
}
