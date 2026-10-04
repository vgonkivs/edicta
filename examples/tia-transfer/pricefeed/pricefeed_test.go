package pricefeed_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

var bg = context.Background()

var _ pricefeed.Feed = (*pricefeed.Fake)(nil)

func obs(price uint64) pricefeed.Observation {
	return pricefeed.Observation{
		Source: "fake:tia", AssetID: "celestia", Quote: "USD",
		Price: price, ObservedAt: 1791000000, FetchedAt: 1791000001,
	}
}

func TestFakeReplaysItsScriptInOrder(t *testing.T) {
	f := pricefeed.NewFake()
	f.Push(obs(100_00000000))
	f.Push(obs(101_00000000))

	got, err := f.Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, obs(100_00000000), got)
	got, err = f.Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, obs(101_00000000), got)
	assert.Equal(t, 2, f.Calls())
}

func TestFakeErrors(t *testing.T) {
	boom := errors.New("upstream down")
	f := pricefeed.NewFake()
	f.PushErr(boom)
	f.Push(obs(1))

	_, err := f.Observe(bg)
	require.ErrorIs(t, err, boom)
	got, err := f.Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), got.Price)

	_, err = f.Observe(bg)
	require.ErrorIs(t, err, pricefeed.ErrExhausted, "an empty script is an error, never a made-up price")
}

func TestFakeHonoursCancelledContext(t *testing.T) {
	f := pricefeed.NewFake()
	f.Push(obs(1))
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err := f.Observe(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestParseDecimal(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{"1", 1_00000000},
		{"1.5", 1_50000000},
		{"0.00000001", 1},
		{"4.12345678", 4_12345678},
		{"123.4", 123_40000000},
		{"0.5", 50000000},
		{"184467440737", 184467440737_00000000},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := pricefeed.ParseDecimal(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseDecimalRejects(t *testing.T) {
	for _, in := range []string{
		"", "0", "0.0", "-1", "+1", "1e5", "1E-3", "abc", "1.2.3", "1,5", " 1", "1 ",
		"NaN", "Inf", "18446744073709551616", "999999999999999999999",
		"184467440738",
	} {
		t.Run(in, func(t *testing.T) {
			_, err := pricefeed.ParseDecimal(in)
			require.ErrorIs(t, err, pricefeed.ErrPrice)
		})
	}
}

func FuzzParseDecimal(f *testing.F) {
	for _, s := range []string{"1", "0.00000001", "1e5", "-0", "", "1.", ".5", "00.1", "9999999999999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := pricefeed.ParseDecimal(s)
		if err != nil {
			require.ErrorIs(t, err, pricefeed.ErrPrice)
			return
		}
		assert.NotZero(t, v)
	})
}
