package bankmsg_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/test/bankvec"
)

func toMsg(t *testing.T, in bankvec.MsgInput) bankmsg.MsgSend {
	t.Helper()
	return bankmsg.MsgSend{
		From:   in.From,
		To:     in.To,
		Denom:  in.Amount.Denom,
		Amount: bankvec.U64(t, in.Amount.Amount),
	}
}

func TestEncodeMatchesVectors(t *testing.T) {
	f := bankvec.Msgs(t)
	require.Len(t, f.Cases, 6)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := bankmsg.Encode(toMsg(t, c.Input), c.HRP)
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.MsgHex), got)
		})
	}
}

func TestDecodeRoundTripsVectors(t *testing.T) {
	for _, c := range bankvec.Msgs(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			raw := bankvec.Hex(t, c.MsgHex)
			got, err := bankmsg.Decode(raw, c.HRP)
			require.NoError(t, err)
			assert.Equal(t, toMsg(t, c.Input), got)

			again, err := bankmsg.Encode(got, c.HRP)
			require.NoError(t, err)
			assert.Equal(t, raw, again)
		})
	}
}

func TestRejectVectors(t *testing.T) {
	f := bankvec.Msgs(t)
	require.Len(t, f.Reject, 39)
	laxer := 0
	for _, r := range f.Reject {
		require.Equal(t, "bankmsg.ErrMalformed", r.ExpectErr, r.ID)
		if r.SDKAccepts {
			laxer++
		}
		t.Run(r.ID, func(t *testing.T) {
			_, err := bankmsg.Decode(bankvec.Hex(t, r.MsgHex), r.HRP)
			require.ErrorIs(t, err, bankmsg.ErrMalformed)
		})
	}
	assert.Equal(t, 34, laxer, "the vectors must keep the cases that a plain protobuf parser accepts")
}

func TestDecodeWrongHRP(t *testing.T) {
	for _, c := range bankvec.Msgs(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			_, err := bankmsg.Decode(bankvec.Hex(t, c.MsgHex), c.HRP+"x")
			require.ErrorIs(t, err, bankmsg.ErrMalformed)
		})
	}
}

func TestDecodeNil(t *testing.T) {
	_, err := bankmsg.Decode(nil, "celestia")
	require.ErrorIs(t, err, bankmsg.ErrMalformed)
}

func TestEncodeRefusesInvalid(t *testing.T) {
	base := toMsg(t, bankvec.Msgs(t).Cases[0].Input)
	tests := []struct {
		name string
		mut  func(m *bankmsg.MsgSend)
	}{
		{"zero amount", func(m *bankmsg.MsgSend) { m.Amount = 0 }},
		{"amount 2^63", func(m *bankmsg.MsgSend) { m.Amount = 1 << 63 }},
		{"short denom", func(m *bankmsg.MsgSend) { m.Denom = "ut" }},
		{"denom digit first", func(m *bankmsg.MsgSend) { m.Denom = "1utia" }},
		{"denom 129", func(m *bankmsg.MsgSend) { m.Denom = "a" + string(make([]byte, 128)) }},
		{"from equals to", func(m *bankmsg.MsgSend) { m.To = m.From }},
		{"upper-case from", func(m *bankmsg.MsgSend) { m.From = "CELESTIA1QQP0ZTYWUVN8AGQN6ZNR4K35EDA494VV7KLWTC" }},
		{"empty to", func(m *bankmsg.MsgSend) { m.To = "" }},
		{"bad checksum", func(m *bankmsg.MsgSend) { m.To = m.To[:len(m.To)-1] + "q" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			tc.mut(&m)
			_, err := bankmsg.Encode(m, "celestia")
			require.ErrorIs(t, err, bankmsg.ErrMalformed)
		})
	}
}

func TestAmountBounds(t *testing.T) {
	m := toMsg(t, bankvec.Msgs(t).Cases[0].Input)
	for _, a := range []uint64{1, 9, 10, 1<<63 - 1} {
		m.Amount = a
		raw, err := bankmsg.Encode(m, "celestia")
		require.NoError(t, err)
		got, err := bankmsg.Decode(raw, "celestia")
		require.NoError(t, err)
		assert.Equal(t, a, got.Amount)
	}
}

func TestAddressVectors(t *testing.T) {
	for _, c := range bankvec.Msgs(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			from, err := bankmsg.DecodeAddress(c.HRP, c.Input.From)
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.FromHex), from)
			to, err := bankmsg.DecodeAddress(c.HRP, c.Input.To)
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.ToHex), to)

			s, err := bankmsg.EncodeAddress(c.HRP, from)
			require.NoError(t, err)
			assert.Equal(t, c.Input.From, s)
		})
	}
}

func TestAddressRejects(t *testing.T) {
	good := bankvec.Msgs(t).Cases[0].Input.From
	tests := []struct{ name, hrp, addr string }{
		{"upper", "celestia", "CELESTIA1QQP0ZTYWUVN8AGQN6ZNR4K35EDA494VV7KLWTC"},
		{"other hrp", "cosmos", good},
		{"bad checksum", "celestia", good[:len(good)-1] + "q"},
		{"empty", "celestia", ""},
		{"no separator", "celestia", "celestiaqqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bankmsg.DecodeAddress(tc.hrp, tc.addr)
			require.Error(t, err)
		})
	}
}

func FuzzDecode(f *testing.F) {
	vf := bankvec.Msgs(f)
	for _, c := range vf.Cases {
		f.Add(bankvec.Hex(f, c.MsgHex))
	}
	for _, r := range vf.Reject {
		f.Add(bankvec.Hex(f, r.MsgHex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := bankmsg.Decode(b, "celestia")
		if err != nil {
			require.ErrorIs(t, err, bankmsg.ErrMalformed)
			return
		}
		again, err := bankmsg.Encode(m, "celestia")
		require.NoError(t, err)
		require.Equal(t, b, again, "accepted bytes must be the canonical encoding")
		assert.NotEqual(t, m.From, m.To)
		assert.NotZero(t, m.Amount)
		assert.LessOrEqual(t, m.Amount, uint64(1<<63-1))
	})
}
