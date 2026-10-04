package dca_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/dca-agent/dca"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

const vectorPath = "../../../spec/vectors/profiles/dca-agent/dca_context.json"

type vecCase struct {
	ID     string `json:"id"`
	CBOR   string `json:"cbor_hex"`
	Expect string `json:"expect_error"`
}

type consistencyCase struct {
	ID     string   `json:"id"`
	DCA    string   `json:"dca_cbor_hex"`
	Order  string   `json:"order_cbor_hex"`
	Failed []string `json:"expect_failed"`
}

type vecFile struct {
	MediaType   string            `json:"media_type"`
	Cases       []vecCase         `json:"cases"`
	Reject      []vecCase         `json:"reject"`
	Consistency []consistencyCase `json:"consistency"`
}

func load(tb testing.TB) vecFile {
	tb.Helper()
	raw, err := os.ReadFile(vectorPath)
	require.NoError(tb, err)
	var v vecFile
	require.NoError(tb, json.Unmarshal(raw, &v))
	return v
}

func unhex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(tb, err)
	return b
}

func TestMediaType(t *testing.T) {
	assert.Equal(t, "application/vnd.edicta.dca.v0+cbor", dca.MediaType)
	assert.Equal(t, load(t).MediaType, dca.MediaType)
}

func TestVectorValid(t *testing.T) {
	v := load(t)
	require.Len(t, v.Cases, 2)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b := unhex(t, c.CBOR)
			ctx, err := dca.Decode(b)
			require.NoError(t, err)
			assert.Equal(t, "dca-spy-weekly", ctx.StrategyID)
			assert.Equal(t, "USD", ctx.Budget.Currency)
			assert.EqualValues(t, 20000, ctx.Order.Qty)
			assert.EqualValues(t, 57250000000, ctx.Order.LimitPrice)
			back, err := dca.Encode(ctx)
			require.NoError(t, err)
			assert.Equal(t, b, back, "canonical round trip")
		})
	}
	withFills, err := dca.Decode(unhex(t, v.Cases[1].CBOR))
	require.NoError(t, err)
	assert.Len(t, withFills.LastFills, 2)
	minimal, err := dca.Decode(unhex(t, v.Cases[0].CBOR))
	require.NoError(t, err)
	assert.Empty(t, minimal.LastFills)
}

func TestVectorRejects(t *testing.T) {
	v := load(t)
	require.Len(t, v.Reject, 10)
	for _, c := range v.Reject {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "dca.ErrMalformed", c.Expect)
			ctx, err := dca.Decode(unhex(t, c.CBOR))
			require.ErrorIs(t, err, dca.ErrMalformed)
			assert.Nil(t, ctx)
		})
	}
}

func TestEveryTruncationIsMalformed(t *testing.T) {
	for _, c := range load(t).Cases {
		b := unhex(t, c.CBOR)
		for n := range b {
			_, err := dca.Decode(b[:n])
			require.ErrorIsf(t, err, dca.ErrMalformed, "prefix of %d bytes", n)
		}
		_, err := dca.Decode(append(append([]byte{}, b...), 0x00))
		require.ErrorIs(t, err, dca.ErrMalformed, "trailing byte")
	}
	_, err := dca.Decode(nil)
	require.ErrorIs(t, err, dca.ErrMalformed)
}

var checkSentinel = map[string]error{
	"DCA1": dca.ErrOrderDiffers,
	"DCA2": dca.ErrConidDiffers,
	"DCA3": dca.ErrCurrencyDiffers,
	"DCA4": dca.ErrSpentOverBudget,
	"DCA5": dca.ErrNotionalOverRemaining,
}

func TestVectorConsistency(t *testing.T) {
	v := load(t)
	require.Len(t, v.Consistency, 7)
	for _, c := range v.Consistency {
		t.Run(c.ID, func(t *testing.T) {
			ctx, err := dca.Decode(unhex(t, c.DCA))
			require.NoError(t, err)
			o, err := ibkrorder.Decode(unhex(t, c.Order))
			require.NoError(t, err)

			err = dca.CheckConsistency(ctx, o)
			if len(c.Failed) == 0 {
				require.NoError(t, err)
				return
			}
			require.Len(t, c.Failed, 1)
			require.ErrorIs(t, err, checkSentinel[c.Failed[0]])
			for id, s := range checkSentinel {
				if id != c.Failed[0] {
					assert.NotErrorIs(t, err, s)
				}
			}
		})
	}
}

func TestConsistencyTable(t *testing.T) {
	v := load(t)
	var consistent consistencyCase
	for _, c := range v.Consistency {
		if c.ID == "dca_consistent" {
			consistent = c
		}
	}
	require.NotEmpty(t, consistent.ID)
	base := func(t *testing.T) (*dca.Context, *ibkrorder.Order) {
		ctx, err := dca.Decode(unhex(t, consistent.DCA))
		require.NoError(t, err)
		o, err := ibkrorder.Decode(unhex(t, consistent.Order))
		require.NoError(t, err)
		return ctx, o
	}
	tests := []struct {
		name string
		mut  func(c *dca.Context, o *ibkrorder.Order)
		want error
	}{
		{"consistent", func(*dca.Context, *ibkrorder.Order) {}, nil},
		{"side differs", func(c *dca.Context, o *ibkrorder.Order) { c.Order.Side = 2 }, dca.ErrOrderDiffers},
		{"limit price differs", func(c *dca.Context, o *ibkrorder.Order) { c.Order.LimitPrice++ }, dca.ErrOrderDiffers},
		{"conid differs", func(c *dca.Context, o *ibkrorder.Order) { o.ConID++ }, dca.ErrConidDiffers},
		{"currency differs", func(c *dca.Context, o *ibkrorder.Order) { c.Budget.Currency = "EUR" }, dca.ErrCurrencyDiffers},
		{"spent over budget skips the notional check", func(c *dca.Context, o *ibkrorder.Order) {
			c.Budget.Spent = c.Budget.PerPeriod + 1
		}, dca.ErrSpentOverBudget},
		{"notional over remaining", func(c *dca.Context, o *ibkrorder.Order) {
			c.Budget.Spent = c.Budget.PerPeriod - 1
		}, dca.ErrNotionalOverRemaining},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, o := base(t)
			tc.mut(c, o)
			err := dca.CheckConsistency(c, o)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
			if tc.want == dca.ErrSpentOverBudget {
				assert.NotErrorIs(t, err, dca.ErrNotionalOverRemaining)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	v := load(f)
	for _, c := range v.Cases {
		f.Add(unhex(f, c.CBOR))
	}
	for _, c := range v.Reject {
		f.Add(unhex(f, c.CBOR))
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
