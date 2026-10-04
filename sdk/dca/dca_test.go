package dca_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/sdk/dca"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func TestVectorValid(t *testing.T) {
	v := sdkfix.Load(t)
	require.Len(t, v.DCAValid, 2)
	for _, c := range v.DCAValid {
		t.Run(c.ID, func(t *testing.T) {
			ctx, err := dca.Decode(c.CBOR)
			require.NoError(t, err)
			require.NotNil(t, ctx)
			assert.Equal(t, "dca-spy-weekly", ctx.StrategyID)
			assert.Equal(t, "USD", ctx.Budget.Currency)
			assert.EqualValues(t, 20000, ctx.Order.Qty)
			assert.EqualValues(t, 57250000000, ctx.Order.LimitPrice)
			back, err := dca.Encode(ctx)
			require.NoError(t, err)
			assert.Equal(t, c.CBOR, back, "canonical round trip")
		})
	}
	t.Run("last_fills", func(t *testing.T) {
		withFills, err := dca.Decode(v.DCAValid[1].CBOR)
		require.NoError(t, err)
		assert.Len(t, withFills.LastFills, 2)
		minimal, err := dca.Decode(v.DCAValid[0].CBOR)
		require.NoError(t, err)
		assert.Empty(t, minimal.LastFills)
	})
}

func TestVectorRejects(t *testing.T) {
	v := sdkfix.Load(t)
	require.Len(t, v.DCARejects, 10)
	for _, c := range v.DCARejects {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "dca.ErrMalformed", c.Expect)
			ctx, err := dca.Decode(c.CBOR)
			require.ErrorIs(t, err, dca.ErrMalformed)
			assert.Nil(t, ctx)
		})
	}
}

func TestEveryTruncationIsMalformed(t *testing.T) {
	v := sdkfix.Load(t)
	for _, c := range v.DCAValid {
		for n := range c.CBOR {
			_, err := dca.Decode(c.CBOR[:n])
			require.ErrorIsf(t, err, dca.ErrMalformed, "prefix of %d bytes", n)
		}
		_, err := dca.Decode(append(append([]byte{}, c.CBOR...), 0x00))
		require.ErrorIs(t, err, dca.ErrMalformed, "trailing byte")
	}
	_, err := dca.Decode(nil)
	require.ErrorIs(t, err, dca.ErrMalformed)
}

func FuzzDecode(f *testing.F) {
	v := sdkfix.Load(f)
	for _, c := range v.DCAValid {
		f.Add(c.CBOR)
	}
	for _, c := range v.DCARejects {
		f.Add(c.CBOR)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		ctx, err := dca.Decode(in)
		if err != nil {
			require.ErrorIs(t, err, dca.ErrMalformed)
			return
		}
		out, err := dca.Encode(ctx)
		require.NoError(t, err)
		require.Equal(t, in, out)
	})
}
