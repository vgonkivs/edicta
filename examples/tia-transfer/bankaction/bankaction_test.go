package bankaction_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/test/bankvec"
)

var sentinels = map[string]error{
	"bankaction.ErrMalformed":    bankaction.ErrMalformed,
	"bankaction.ErrBodyMismatch": bankaction.ErrBodyMismatch,
	"transfer.ErrExpired":        bankaction.ErrExpired,
	"transfer.ErrChainMismatch":  bankaction.ErrChainMismatch,
	"transfer.ErrSenderMismatch": bankaction.ErrSenderMismatch,
	"transfer.ErrDenomMismatch":  bankaction.ErrDenomMismatch,
	"transfer.ErrDestination":    bankaction.ErrDestination,
	"transfer.ErrRiskLimit":      bankaction.ErrRiskLimit,
	"bankmsg.ErrMalformed":       bankmsg.ErrMalformed,
}

func sentinel(t *testing.T, name string) error {
	t.Helper()
	e, ok := sentinels[name]
	require.True(t, ok, "unknown sentinel %s", name)
	return e
}

func hashOf(t *testing.T, hexs string) commitment.Hash {
	t.Helper()
	b := bankvec.Hex(t, hexs)
	require.Len(t, b, 32)
	return commitment.Hash(b)
}

func TestActionType(t *testing.T) {
	assert.Equal(t, "application/vnd.edicta.cosmos.bank-send.v0+cbor", bankaction.ActionType)
	assert.Equal(t, bankaction.ActionType, bankvec.Actions(t).ActionType)
}

func TestEncodeActionVectors(t *testing.T) {
	f := bankvec.Actions(t)
	require.Len(t, f.Cases, 6)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			a := bankaction.Action{ChainID: c.Input.ChainID, Msg: bankvec.Hex(t, c.Input.MsgHex)}
			got, err := bankaction.Encode(a)
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.CBORHex), got)

			h, err := commitment.ActionHash(bankaction.ActionType, got)
			require.NoError(t, err)
			assert.Equal(t, bankvec.Hex(t, c.HashHex), h[:])

			if c.MsgRef != "" {
				msg, _ := bankvec.Msg(t, c.MsgRef)
				assert.Equal(t, msg, a.Msg)
			}
		})
	}
}

func TestDecodeActionRoundTrip(t *testing.T) {
	for _, c := range bankvec.Actions(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			raw := bankvec.Hex(t, c.CBORHex)
			a, err := bankaction.Decode(raw)
			require.NoError(t, err)
			assert.Equal(t, c.Input.ChainID, a.ChainID)
			assert.Equal(t, bankvec.Hex(t, c.Input.MsgHex), a.Msg)

			again, err := bankaction.Encode(a)
			require.NoError(t, err)
			assert.Equal(t, raw, again)
		})
	}
}

func TestDecodeActionRejectVectors(t *testing.T) {
	f := bankvec.Actions(t)
	require.Len(t, f.Reject, 22)
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			require.Equal(t, "bankaction.ErrMalformed", r.ExpectErr)
			_, err := bankaction.Decode(bankvec.Hex(t, r.CBORHex))
			require.ErrorIs(t, err, bankaction.ErrMalformed)
		})
	}
}

func TestEncodeActionRefusesInvalid(t *testing.T) {
	msg, _ := bankvec.Msg(t, "msg_minimal")
	tests := []struct {
		name string
		a    bankaction.Action
	}{
		{"empty chain id", bankaction.Action{Msg: msg}},
		{"chain id 51", bankaction.Action{ChainID: strings.Repeat("a", 51), Msg: msg}},
		{"chain id space", bankaction.Action{ChainID: "mocha 4", Msg: msg}},
		{"chain id slash", bankaction.Action{ChainID: "mocha/4", Msg: msg}},
		{"chain id non-ASCII", bankaction.Action{ChainID: "mochä-4", Msg: msg}},
		{"nil msg", bankaction.Action{ChainID: "mocha-4"}},
		{"msg 1025", bankaction.Action{ChainID: "mocha-4", Msg: make([]byte, 1025)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bankaction.Encode(tc.a)
			require.ErrorIs(t, err, bankaction.ErrMalformed)
		})
	}
}

func TestActionLimitsAccepted(t *testing.T) {
	for _, a := range []bankaction.Action{
		{ChainID: strings.Repeat("a", 50), Msg: []byte{1}},
		{ChainID: "A.b_c-9", Msg: make([]byte, 1024)},
	} {
		raw, err := bankaction.Encode(a)
		require.NoError(t, err)
		got, err := bankaction.Decode(raw)
		require.NoError(t, err)
		assert.Equal(t, a, got)
	}
}

func TestBodyVectors(t *testing.T) {
	f := bankvec.Txs(t)
	require.Len(t, f.Body, 7)
	for _, b := range f.Body {
		t.Run(b.ID, func(t *testing.T) {
			msg, _ := bankvec.Msg(t, b.MsgRef)
			h := hashOf(t, b.HashHex)
			th := bankvec.U64(t, b.TimeoutHeight)
			want := bankvec.Hex(t, b.BodyHex)

			got, err := bankaction.Body(msg, h, th)
			require.NoError(t, err)
			assert.Equal(t, want, got)
			assert.Equal(t, b.HashHex, b.Memo)
			assert.True(t, bytes.Contains(got, []byte(b.Memo)), "memo is the lower-case hex of the hash")

			gotTh, err := bankaction.CheckBody(bankaction.Action{ChainID: "mocha-4", Msg: msg}, h, want)
			require.NoError(t, err)
			assert.Equal(t, th, gotTh)
		})
	}
}

func TestBodyRefusesBadTimeout(t *testing.T) {
	msg, _ := bankvec.Msg(t, "msg_minimal")
	var h commitment.Hash
	_, err := bankaction.Body(msg, h, 0)
	require.Error(t, err)
	_, err = bankaction.Body(msg, h, 1<<63)
	require.Error(t, err)
	_, err = bankaction.Body(msg, h, 1<<63-1)
	require.NoError(t, err)
}

func TestBodyDoesNotAliasMsg(t *testing.T) {
	msg, _ := bankvec.Msg(t, "msg_minimal")
	keep := bytes.Clone(msg)
	var h commitment.Hash
	body, err := bankaction.Body(msg, h, 5)
	require.NoError(t, err)
	body[10] ^= 0xff
	assert.Equal(t, keep, msg)
}

func TestCheckBodyRejectVectors(t *testing.T) {
	f := bankvec.Txs(t)
	require.Len(t, f.Reject, 12)
	for _, r := range f.Reject {
		t.Run(r.ID, func(t *testing.T) {
			msg, _ := bankvec.Msg(t, r.MsgRef)
			_, err := bankaction.CheckBody(
				bankaction.Action{ChainID: "mocha-4", Msg: msg},
				hashOf(t, r.HashHex),
				bankvec.Hex(t, r.BodyHex),
			)
			require.ErrorIs(t, err, sentinel(t, r.ExpectErr))
		})
	}
}

func TestCheckBodyWrongHashOrMsg(t *testing.T) {
	f := bankvec.Txs(t)
	b := f.Body[0]
	msg, _ := bankvec.Msg(t, b.MsgRef)
	body := bankvec.Hex(t, b.BodyHex)
	h := hashOf(t, b.HashHex)

	other := h
	other[0] ^= 1
	_, err := bankaction.CheckBody(bankaction.Action{ChainID: "mocha-4", Msg: msg}, other, body)
	require.ErrorIs(t, err, bankaction.ErrBodyMismatch)

	otherMsg, _ := bankvec.Msg(t, "msg_typical")
	_, err = bankaction.CheckBody(bankaction.Action{ChainID: "mocha-4", Msg: otherMsg}, h, body)
	require.ErrorIs(t, err, bankaction.ErrBodyMismatch)

	_, err = bankaction.CheckBody(bankaction.Action{ChainID: "mocha-4", Msg: msg}, h, nil)
	require.ErrorIs(t, err, bankaction.ErrBodyMismatch)
}

func TestSignedVectorsCarryExactBody(t *testing.T) {
	f := bankvec.Txs(t)
	bodies := map[string]bankvec.Body{}
	for _, b := range f.Body {
		bodies[b.ID] = b
	}
	require.Len(t, f.Signed, 2)
	for _, s := range f.Signed {
		t.Run(s.ID, func(t *testing.T) {
			b := bodies[s.BodyRef]
			msg, _ := bankvec.Msg(t, b.MsgRef)
			raw := bankvec.Hex(t, s.TxRawHex)

			require.Equal(t, byte(0x0a), raw[0])
			n, k := binary.Uvarint(raw[1:])
			require.Positive(t, k)
			bodyBytes := raw[1+k : 1+k+int(n)]

			want, err := bankaction.Body(msg, hashOf(t, b.HashHex), bankvec.U64(t, b.TimeoutHeight))
			require.NoError(t, err)
			assert.Equal(t, want, bodyBytes)

			sum := sha256.Sum256(raw)
			assert.Equal(t, s.TxHash, hex.EncodeToString(sum[:]))
			assert.Equal(t, s.RailRef, s.TxHash)
		})
	}
}

func TestBlockIntervalVectors(t *testing.T) {
	f := bankvec.Timeouts(t)
	require.Len(t, f.Intervals, 4)
	for _, iv := range f.Intervals {
		t.Run(iv.ID, func(t *testing.T) {
			got, err := bankaction.BlockIntervalMs(headers(t, iv.Headers))
			require.NoError(t, err)
			assert.Equal(t, bankvec.U64(t, iv.TauMs), got)
		})
	}
}

func TestBlockIntervalRefusesBadHeaders(t *testing.T) {
	const s = 1_000_000_000
	tests := []struct {
		name string
		hs   []bankaction.Header
	}{
		{"none", nil},
		{"one", []bankaction.Header{{Height: 1, TimeNs: s}}},
		{"gap", []bankaction.Header{{Height: 1, TimeNs: s}, {Height: 3, TimeNs: 13 * s}}},
		{"repeated height", []bankaction.Header{{Height: 1, TimeNs: s}, {Height: 1, TimeNs: 7 * s}}},
		{"descending height", []bankaction.Header{{Height: 2, TimeNs: s}, {Height: 1, TimeNs: 7 * s}}},
		{"time goes back", []bankaction.Header{{Height: 1, TimeNs: 7 * s}, {Height: 2, TimeNs: s}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bankaction.BlockIntervalMs(tc.hs)
			require.ErrorIs(t, err, bankaction.ErrHeaders)
		})
	}
}

func headers(t *testing.T, in []bankvec.Header) []bankaction.Header {
	t.Helper()
	out := make([]bankaction.Header, len(in))
	for i, h := range in {
		out[i] = bankaction.Header{Height: bankvec.U64(t, h.Height), TimeNs: bankvec.U64(t, h.TimeNs)}
	}
	return out
}

func timeoutInput(t *testing.T, c bankvec.TimeoutCase) bankaction.TimeoutInput {
	t.Helper()
	return bankaction.TimeoutInput{
		HeadHeight: bankvec.U64(t, c.HeadHeight),
		HeadTime:   bankvec.U64(t, c.HeadTime),
		TauMs:      bankvec.U64(t, c.TauMs),
		Expires:    bankvec.U64(t, c.Expires),
		SkewS:      bankvec.U64(t, c.SkewS),
		MaxBlocks:  bankvec.U64(t, c.MaxBlocks),
		Now:        bankvec.U64(t, c.Now),
	}
}

func TestTimeoutHeightVectors(t *testing.T) {
	f := bankvec.Timeouts(t)
	require.Equal(t, "2", f.Slowdown)
	require.Len(t, f.Cases, 12)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := bankaction.TimeoutHeight(timeoutInput(t, c))
			if c.ExpectErr != "" {
				require.ErrorIs(t, err, sentinel(t, c.ExpectErr))
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, bankvec.U64(t, c.TimeoutHeight), got)
		})
	}
}

func TestTimeoutHeightNeverPastExpiry(t *testing.T) {
	const tau = 6000
	for _, expires := range []uint64{1791000042, 1791000100, 1791000300, 1791000301, 1791000999} {
		in := bankaction.TimeoutInput{
			HeadHeight: 1000, HeadTime: 1791000000, TauMs: tau,
			Expires: expires, SkewS: 30, MaxBlocks: 10000, Now: 1791000001,
		}
		th, err := bankaction.TimeoutHeight(in)
		if err != nil {
			require.ErrorIs(t, err, bankaction.ErrExpired)
			continue
		}
		n := th - in.HeadHeight
		assert.LessOrEqual(t, in.HeadTime+n*2*tau/1000, expires-in.SkewS,
			"blocks at twice the observed interval still end before expires-skew")
	}
}

func TestTimeoutHeightRefusesBadInputs(t *testing.T) {
	base := bankaction.TimeoutInput{
		HeadHeight: 1000, HeadTime: 1791000000, TauMs: 6000,
		Expires: 1791000300, SkewS: 30, MaxBlocks: 200, Now: 1791000005,
	}
	_, err := bankaction.TimeoutHeight(base)
	require.NoError(t, err)

	tests := []struct {
		name string
		mut  func(in *bankaction.TimeoutInput)
	}{
		{"zero tau", func(in *bankaction.TimeoutInput) { in.TauMs = 0 }},
		{"zero max blocks", func(in *bankaction.TimeoutInput) { in.MaxBlocks = 0 }},
		{"max blocks above the limit", func(in *bankaction.TimeoutInput) { in.MaxBlocks = 10001 }},
		{"height overflow", func(in *bankaction.TimeoutInput) { in.HeadHeight = 1<<63 - 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mut(&in)
			_, err := bankaction.TimeoutHeight(in)
			require.Error(t, err)
		})
	}
}

func TestTimeoutHeightHugeInputsDoNotWrap(t *testing.T) {
	in := bankaction.TimeoutInput{
		HeadHeight: 1, HeadTime: 1, TauMs: 1,
		Expires: 1<<63 - 1, SkewS: 0, MaxBlocks: 10000, Now: 1,
	}
	th, err := bankaction.TimeoutHeight(in)
	require.NoError(t, err)
	assert.Equal(t, uint64(10001), th)
}

func domain(d bankvec.Domain) bankaction.Domain {
	return bankaction.Domain{ChainID: d.ChainID, Denom: d.Denom, HRP: d.HRP, Sender: d.Sender}
}

func TestCheckExecutionVectors(t *testing.T) {
	f := bankvec.Execs(t)
	require.Len(t, f.Cases, 17)
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			raw := bankvec.Hex(t, c.ActionHex)
			lim := bankaction.Limits{Destinations: c.Destinations, MaxAmount: bankvec.U64(t, c.MaxAmount)}

			a, m, err := bankaction.CheckExecution(raw, domain(c.Domain), lim)
			if c.ExpectErr != "" {
				require.ErrorIs(t, err, sentinel(t, c.ExpectErr))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.Domain.ChainID, a.ChainID)
			assert.Equal(t, c.Domain.Sender, m.From)
			assert.Equal(t, c.Domain.Denom, m.Denom)

			again, err := bankaction.Encode(a)
			require.NoError(t, err)
			assert.Equal(t, raw, again, "the checked message is the authorized one, byte for byte")
		})
	}
}

func TestCheckExecutionOneSentinelPerRejection(t *testing.T) {
	all := []error{
		bankaction.ErrMalformed, bankaction.ErrChainMismatch, bankmsg.ErrMalformed, bankaction.ErrSenderMismatch,
		bankaction.ErrDenomMismatch, bankaction.ErrDestination, bankaction.ErrRiskLimit,
	}
	for _, c := range bankvec.Execs(t).Cases {
		if c.ExpectErr == "" {
			continue
		}
		_, _, err := bankaction.CheckExecution(bankvec.Hex(t, c.ActionHex), domain(c.Domain),
			bankaction.Limits{Destinations: c.Destinations, MaxAmount: bankvec.U64(t, c.MaxAmount)})
		hits := 0
		for _, s := range all {
			if errors.Is(err, s) {
				hits++
			}
		}
		assert.Equal(t, 1, hits, c.ID)
	}
}

func FuzzDecodeAction(f *testing.F) {
	af := bankvec.Actions(f)
	for _, c := range af.Cases {
		f.Add(bankvec.Hex(f, c.CBORHex))
	}
	for _, r := range af.Reject {
		f.Add(bankvec.Hex(f, r.CBORHex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := bankaction.Decode(b)
		if err != nil {
			require.ErrorIs(t, err, bankaction.ErrMalformed)
			return
		}
		again, err := bankaction.Encode(a)
		require.NoError(t, err)
		require.Equal(t, b, again)
		assert.NotEmpty(t, a.Msg)
		assert.LessOrEqual(t, len(a.Msg), 1024)
	})
}

func FuzzCheckBody(f *testing.F) {
	tf := bankvec.Txs(f)
	for _, b := range tf.Body {
		f.Add(bankvec.Hex(f, b.BodyHex))
	}
	for _, r := range tf.Reject {
		f.Add(bankvec.Hex(f, r.BodyHex))
	}
	msg, _ := bankvec.Msg(f, "msg_minimal")
	h := commitment.Hash(bankvec.Hex(f, tf.Body[0].HashHex))
	a := bankaction.Action{ChainID: "mocha-4", Msg: msg}
	f.Fuzz(func(t *testing.T, body []byte) {
		th, err := bankaction.CheckBody(a, h, body)
		if err != nil {
			require.ErrorIs(t, err, bankaction.ErrBodyMismatch)
			return
		}
		again, err := bankaction.Body(msg, h, th)
		require.NoError(t, err)
		require.Equal(t, body, again)
	})
}

func FuzzCheckExecution(f *testing.F) {
	for _, c := range bankvec.Execs(f).Cases {
		f.Add(bankvec.Hex(f, c.ActionHex))
	}
	d := bankaction.Domain{
		ChainID: "mocha-4", Denom: "utia", HRP: "celestia",
		Sender: "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc",
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, m, err := bankaction.CheckExecution(raw, d, bankaction.Limits{})
		if err != nil {
			return
		}
		again, err := bankaction.Encode(a)
		require.NoError(t, err)
		require.Equal(t, raw, again)
		assert.Equal(t, d.Sender, m.From)
		assert.Equal(t, d.ChainID, a.ChainID)
	})
}
