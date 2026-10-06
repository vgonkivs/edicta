package retention_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

func TestFibreRetentionSourced(t *testing.T) {
	honest := func(v uint64) *Direct { return &Direct{Canary: []bool{true}, At: Const(v)} }
	failing := &Direct{Canary: []bool{true}, At: func(uint64) (uint64, error) { return 0, errors.New("pruned") }}
	cases := []struct {
		name   string
		direct func() *Direct
		height uint64
		want   uint64
		src    retention.Source
	}{
		{"observations only", nil, 115, 100, retention.SourceObserved},
		{"observations only, between samples", nil, 145, 50, retention.SourceObserved},
		{"direct below the observations: both, minimum taken", func() *Direct { return honest(80) }, 115, 80, retention.SourceBoth},
		{"direct above the observations: both, minimum taken", func() *Direct { return honest(500) }, 115, 100, retention.SourceBoth},
		{"direct alone below the observations", func() *Direct { return honest(80) }, 99, 80, retention.SourceDirect},
		{"direct failing: observations", func() *Direct { return failing }, 115, 100, retention.SourceObserved},
		{"failed paired canary discards the read", func() *Direct {
			return &Direct{Canary: []bool{true, false}, At: Const(5)}
		}, 115, 100, retention.SourceObserved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var d retention.AtHeightSource
			if tc.direct != nil {
				d = tc.direct()
			}
			p, _, _, _ := started(t, d)
			got, src, err := p.FibreRetentionSourced(ctx, tc.height)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.src, src)

			plain, err := p.FibreRetention(ctx, tc.height)
			require.NoError(t, err)
			assert.Equal(t, got, plain, "FibreRetention keeps its contract")
		})
	}

	t.Run("errors carry no source", func(t *testing.T) {
		p, _, _, _ := started(t, nil)
		got, src, err := p.FibreRetentionSourced(ctx, 99)
		require.ErrorIs(t, err, retention.ErrNotCovered)
		assert.Zero(t, got)
		assert.Zero(t, src)
	})

	t.Run("latest at height zero equals FibreRetention", func(t *testing.T) {
		p, _, _, _ := started(t, nil)
		got, _, err := p.FibreRetentionSourced(ctx, 0)
		require.NoError(t, err)
		want, err := p.FibreRetention(ctx, 0)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("source values", func(t *testing.T) {
		assert.EqualValues(t, 1, retention.SourceDirect)
		assert.EqualValues(t, 2, retention.SourceObserved)
		assert.EqualValues(t, 3, retention.SourceBoth)
	})
}
