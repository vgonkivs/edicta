package ibkrorder_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

const vectorPath = "../../../spec/vectors/profiles/dca-agent/ibkr_order.json"

type vecCase struct {
	ID           string            `json:"id"`
	Input        map[string]string `json:"input"`
	CBORHex      string            `json:"cbor_hex"`
	ActionHash   string            `json:"action_hash_hex"`
	ActionSalt   string            `json:"action_salt_hex"`
	QtyDecimal   string            `json:"qty_decimal"`
	PriceDecimal string            `json:"limit_price_decimal"`
	Expect       string            `json:"expect_error"`
}

type vecFile struct {
	ActionType string    `json:"action_type"`
	Cases      []vecCase `json:"cases"`
	Malformed  []vecCase `json:"malformed"`
	Invalid    []vecCase `json:"invalid"`
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

func u64(tb testing.TB, s string) uint64 {
	tb.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	require.NoError(tb, err)
	return n
}

func orderFromInput(tb testing.TB, in map[string]string) *ibkrorder.Order {
	tb.Helper()
	o := &ibkrorder.Order{
		Account:   in["account"],
		ConID:     u64(tb, in["conid"]),
		Symbol:    in["symbol"],
		Side:      u64(tb, in["side"]),
		Qty:       u64(tb, in["qty"]),
		OrderType: u64(tb, in["order_type"]),
		Currency:  in["currency"],
		TIF:       u64(tb, in["tif"]),
	}
	if p, ok := in["limit_price"]; ok {
		n := u64(tb, p)
		o.LimitPrice = &n
	}
	return o
}

func TestActionType(t *testing.T) {
	assert.Equal(t, "application/vnd.edicta.ibkr.order.v0+cbor", ibkrorder.ActionType)
	assert.Equal(t, load(t).ActionType, ibkrorder.ActionType)
}

func TestVectorEncodeDecodeRoundTrip(t *testing.T) {
	v := load(t)
	require.Len(t, v.Cases, 6)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			want := unhex(t, c.CBORHex)

			enc, err := ibkrorder.Encode(orderFromInput(t, c.Input))
			require.NoError(t, err)
			assert.Equal(t, want, enc)

			o, err := ibkrorder.Decode(want)
			require.NoError(t, err)
			assert.Equal(t, orderFromInput(t, c.Input), o)
			require.NoError(t, ibkrorder.Validate(o))

			back, err := ibkrorder.Encode(o)
			require.NoError(t, err)
			assert.Equal(t, want, back, "decode then encode is the identity")
		})
	}
}

func TestVectorActionHash(t *testing.T) {
	v := load(t)
	for _, c := range v.Cases {
		t.Run(c.ID, func(t *testing.T) {
			pre := []byte{0x10}
			pre = append(pre, "edicta/v1/action"...)
			pre = append(pre, byte(len(v.ActionType)))
			pre = append(pre, v.ActionType...)
			pre = append(pre, unhex(t, c.ActionSalt)...)
			pre = append(pre, unhex(t, c.CBORHex)...)
			sum := sha256.Sum256(pre)
			assert.Equal(t, c.ActionHash, hex.EncodeToString(sum[:]))
		})
	}
}

func TestVectorDecimalText(t *testing.T) {
	for _, c := range load(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			o, err := ibkrorder.Decode(unhex(t, c.CBORHex))
			require.NoError(t, err)
			assert.Equal(t, c.QtyDecimal, ibkrorder.FormatQty(o.Qty))
			require.NotNil(t, o.LimitPrice)
			assert.Equal(t, c.PriceDecimal, ibkrorder.FormatPrice(*o.LimitPrice))
		})
	}
}

func TestFormatTable(t *testing.T) {
	tests := []struct {
		name  string
		qty   uint64
		price uint64
		wantQ string
		wantP string
	}{
		{"smallest units", 1, 1, "0.0001", "0.00000001"},
		{"whole", 10000, 100000000, "1", "1"},
		{"trailing zeros trimmed", 15000, 150000000, "1.5", "1.5"},
		{"no float rounding", 9007199254740993, 9007199254740993, "900719925474.0993", "90071992.54740993"},
		{"max", 1<<63 - 1, 1<<63 - 1, "922337203685477.5807", "92233720368.54775807"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantQ, ibkrorder.FormatQty(tc.qty))
			assert.Equal(t, tc.wantP, ibkrorder.FormatPrice(tc.price))
		})
	}
}

func TestVectorMalformed(t *testing.T) {
	v := load(t)
	require.Len(t, v.Malformed, 21)
	for _, c := range v.Malformed {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "ibkrorder.ErrMalformed", c.Expect)
			o, err := ibkrorder.Decode(unhex(t, c.CBORHex))
			require.ErrorIs(t, err, ibkrorder.ErrMalformed)
			assert.Nil(t, o)
		})
	}
}

func TestVectorInvalid(t *testing.T) {
	v := load(t)
	require.Len(t, v.Invalid, 10)
	for _, c := range v.Invalid {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "ibkrorder.ErrInvalid", c.Expect)
			o, err := ibkrorder.Decode(unhex(t, c.CBORHex))
			require.NoError(t, err, "canonical bodies decode; validation refuses them")
			require.ErrorIs(t, ibkrorder.Validate(o), ibkrorder.ErrInvalid)
		})
	}
}

func TestEveryTruncationAndExtensionIsMalformed(t *testing.T) {
	for _, c := range load(t).Cases {
		b := unhex(t, c.CBORHex)
		for n := range b {
			_, err := ibkrorder.Decode(b[:n])
			require.ErrorIsf(t, err, ibkrorder.ErrMalformed, "%s prefix of %d bytes", c.ID, n)
		}
		_, err := ibkrorder.Decode(append(append([]byte{}, b...), 0x00))
		require.ErrorIs(t, err, ibkrorder.ErrMalformed, "%s trailing byte", c.ID)
	}
	_, err := ibkrorder.Decode(nil)
	require.ErrorIs(t, err, ibkrorder.ErrMalformed)
}

func TestValidateTable(t *testing.T) {
	base := func() *ibkrorder.Order {
		p := uint64(19050000000)
		return &ibkrorder.Order{Account: "DU1", ConID: 1, Side: 1, Qty: 1, OrderType: 1, LimitPrice: &p, Currency: "USD", TIF: 1}
	}
	zero := uint64(0)
	big := uint64(1 << 63)
	tests := []struct {
		name string
		mut  func(o *ibkrorder.Order)
		ok   bool
	}{
		{"valid", func(*ibkrorder.Order) {}, true},
		{"sell", func(o *ibkrorder.Order) { o.Side = 2 }, true},
		{"ioc", func(o *ibkrorder.Order) { o.TIF = 3 }, true},
		{"side 3", func(o *ibkrorder.Order) { o.Side = 3 }, false},
		{"tif 0", func(o *ibkrorder.Order) { o.TIF = 0 }, false},
		{"type 0", func(o *ibkrorder.Order) { o.OrderType = 0 }, false},
		{"market refused", func(o *ibkrorder.Order) { o.OrderType = 2; o.LimitPrice = nil }, false},
		{"limit without price", func(o *ibkrorder.Order) { o.LimitPrice = nil }, false},
		{"zero price", func(o *ibkrorder.Order) { o.LimitPrice = &zero }, false},
		{"zero conid", func(o *ibkrorder.Order) { o.ConID = 0 }, false},
		{"zero qty", func(o *ibkrorder.Order) { o.Qty = 0 }, false},
		{"qty above int63", func(o *ibkrorder.Order) { o.Qty = big }, false},
		{"price above int63", func(o *ibkrorder.Order) { o.LimitPrice = &big }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			tc.mut(o)
			err := ibkrorder.Validate(o)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ibkrorder.ErrInvalid)
		})
	}
}

func TestEncodeRefusesSchemaViolations(t *testing.T) {
	p := uint64(1)
	good := ibkrorder.Order{Account: "DU1", ConID: 1, Side: 1, Qty: 1, OrderType: 1, LimitPrice: &p, Currency: "USD", TIF: 1}
	tests := []struct {
		name string
		mut  func(o *ibkrorder.Order)
	}{
		{"empty account", func(o *ibkrorder.Order) { o.Account = "" }},
		{"account 33 chars", func(o *ibkrorder.Order) { o.Account = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
		{"currency lowercase", func(o *ibkrorder.Order) { o.Currency = "usd" }},
		{"currency 4 chars", func(o *ibkrorder.Order) { o.Currency = "USDT" }},
		{"symbol control char", func(o *ibkrorder.Order) { o.Symbol = "A\x01" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := good
			tc.mut(&o)
			_, err := ibkrorder.Encode(&o)
			require.ErrorIs(t, err, ibkrorder.ErrMalformed)
		})
	}
	_, err := ibkrorder.Encode(nil)
	require.ErrorIs(t, err, ibkrorder.ErrMalformed)
}

func TestNotionalAtMost(t *testing.T) {
	tests := []struct {
		name  string
		qty   uint64
		price uint64
		limit uint64
		want  bool
	}{
		{"exact equal", 100000, 19050000000, 190500000000, true},
		{"one below", 100000, 19050000000, 190499999999, false},
		{"limit zero means nothing fits", 1, 1, 0, false},
		{"uint64 wrap", 1 << 32, 1 << 32, 1, false},
		{"max operands against max limit", 1<<63 - 1, 1<<63 - 1, 1<<63 - 1, false},
		{"tiny", 1, 1, 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ibkrorder.NotionalAtMost(tc.qty, tc.price, tc.limit))
		})
	}
}

func FuzzDecode(f *testing.F) {
	v := load(f)
	for _, c := range v.Cases {
		f.Add(unhex(f, c.CBORHex))
	}
	for _, c := range v.Malformed {
		f.Add(unhex(f, c.CBORHex))
	}
	for _, c := range v.Invalid {
		f.Add(unhex(f, c.CBORHex))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		o, err := ibkrorder.Decode(in)
		if err != nil {
			require.ErrorIs(t, err, ibkrorder.ErrMalformed)
			require.Nil(t, o)
			return
		}
		out, err := ibkrorder.Encode(o)
		require.NoError(t, err)
		require.Equal(t, in, out, "accepted bytes are the unique encoding")
		if err := ibkrorder.Validate(o); err != nil {
			require.ErrorIs(t, err, ibkrorder.ErrInvalid)
		}
	})
}
