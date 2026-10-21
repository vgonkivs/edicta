// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
)

func seedActions(f *testing.F) {
	v := loadJSON[actionFile](f, "action.json")
	for _, c := range v.Cases {
		f.Add(unhex(f, c.CBORHex))
	}
	for _, r := range v.Reject {
		f.Add(unhex(f, r.CBORHex))
	}
}

// Every accepted action is the unique canonical encoding of what it decodes
// to, gives valid facts and has a well-formed table row; every refusal is
// one of the two sentinels.
func FuzzDecodeTxAction(f *testing.F) {
	seedActions(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := DecodeTxAction(b)
		if err != nil {
			require.True(t, errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnknownDomain), "%v", err)
			return
		}
		enc, err := EncodeTxAction(a.unsigned, a.Resource, a.RequirementsHash)
		require.NoError(t, err)
		require.Equal(t, b, enc)
		if f, err := a.Facts(); err != nil {
			require.ErrorIs(t, err, policy.ErrFactsInvalid)
			require.Equal(t, "EF3", ruleOf(t, err))
			sum := new(big.Int).Add(new(big.Int).SetBytes(a.Value), a.FeeBound())
			require.Greater(t, sum.BitLen(), 256)
		} else {
			require.NoError(t, f.Validate())
		}
		require.Equal(t, a.Row.Escrow, a.To)
		require.NotEmpty(t, a.Value)
		require.LessOrEqual(t, len(a.unsigned), MaxTxSize)
		require.True(t, bytes.HasPrefix(a.unsigned[1:], rlpListHeader(len(a.items))))
	})
}

// wrapTx builds the four-key action around tx directly, without the
// encoder's own decode, so the fuzzer reaches the transaction rules.
func wrapTx(tx []byte) []byte {
	b := cborHeadBytes(majorMap, 4)
	b = append(b, 0x01, 0x01, 0x02)
	b = append(b, cborHeadBytes(majorBytes, uint64(len(tx)))...)
	b = append(b, tx...)
	b = append(b, 0x03)
	b = append(b, cborHeadBytes(majorText, 5)...)
	b = append(b, "https"...)
	b = append(b, 0x04)
	b = append(b, cborHeadBytes(majorBytes, 32)...)
	return append(b, make([]byte, 32)...)
}

func word(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }

func uintBytes(v uint64) []byte {
	var out []byte
	for ; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

// reencodeTx rebuilds the unsigned transaction from the decoded fields alone.
func reencodeTx(a TxAction) []byte {
	d := a.Deposit
	data := append(bytes.Clone(depositSelector[:]), d.PaymentID[:]...)
	data = append(data, word(d.PayTo[:])...)
	data = append(data, word(d.Facilitator[:])...)
	data = append(data, word(uintBytes(d.ExpiresAt))...)
	data = append(data, word(uintBytes(d.RefundAfter))...)
	data = append(data, d.TIAPriceUSD[:]...)
	var p []byte
	for _, it := range [][]byte{uintBytes(a.ChainID), uintBytes(a.Nonce), a.MaxPriorityFee, a.MaxFeePerGas,
		uintBytes(a.GasLimit), a.To[:], a.Value, data} {
		p = append(p, rlpString(it)...)
	}
	p = append(p, 0xc0)
	return append(append([]byte{txType}, rlpListHeader(len(p))...), p...)
}

// Every transaction the decoder accepts is the unique canonical encoding of
// its decoded fields; every refusal is one of the two sentinels.
func FuzzDecodeTx(f *testing.F) {
	v := loadJSON[actionFile](f, "action.json")
	for _, c := range v.Cases {
		f.Add(unhex(f, c.TxHex))
	}
	f.Fuzz(func(t *testing.T, tx []byte) {
		if len(tx) < 1 || len(tx) > MaxTxSize {
			return
		}
		a, err := DecodeTxAction(wrapTx(tx))
		if err != nil {
			require.True(t, errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnknownDomain), "%v", err)
			return
		}
		require.Equal(t, tx, reencodeTx(a))
		require.Equal(t, tx, a.Unsigned())
	})
}

// ParseSigned never panics on hostile bytes, and whatever it accepts is
// exactly the splice of the signature it returns.
func FuzzParseSigned(f *testing.F) {
	a, _ := f14(f)
	v := loadJSON[signedFile](f, "signed.json")
	for _, c := range v.ExactTx {
		f.Add(unhex(f, c.SignedHex))
	}
	f.Fuzz(func(t *testing.T, signed []byte) {
		sig, payer, err := ParseSigned(a, signed)
		if err != nil {
			require.ErrorIs(t, err, ErrSignedMismatch)
			return
		}
		again, err := a.Splice(sig, payer)
		require.NoError(t, err)
		require.Equal(t, signed, again)
		p, err := RecoverPayer(a.SigHash(), sig)
		require.NoError(t, err)
		require.Equal(t, payer, p)
	})
}

// The strict reader accepts nothing encoding/json would refuse, and every
// accepted /deposit/build answer gives an action that decodes to the
// answer's paymentId; every refusal is one of the decoder's sentinels.
func FuzzActionFromDepositBuild(f *testing.F) {
	v := loadJSON[x402File](f, "x402.json")
	for _, c := range append(v.BuildAccept, v.BuildReject...) {
		f.Add(c.body(f))
	}
	rh := RequirementsHash(readVectorFile(f, v.Build.RequirementsFromFile))
	f.Fuzz(func(t *testing.T, body []byte) {
		if _, err := parseJSON(body); err == nil {
			require.True(t, json.Valid(body), "%q", body)
		}
		action, a, err := ActionFromDepositBuild(body, v.Build.Resource, rh)
		if err != nil {
			require.True(t, errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnknownDomain), "%v", err)
			return
		}
		again, err := DecodeTxAction(action)
		require.NoError(t, err)
		require.Equal(t, a.Unsigned(), again.Unsigned())
		doc, err := parseJSON(body)
		require.NoError(t, err)
		pid, ok := hexString(doc.member("paymentId"), 32)
		require.True(t, ok)
		require.Equal(t, a.Deposit.PaymentID, [32]byte(pid))
	})
}

// Whatever R the checks accept is bound to the action by its hash and
// names the action's paymentId; every refusal is ErrRequirements.
func FuzzCheckRequirements(f *testing.F) {
	v := loadJSON[x402File](f, "x402.json")
	for _, c := range append(v.Requirements.Accept, v.Requirements.Reject...) {
		f.Add(unhex(f, c.RHex))
	}
	r0 := readVectorFile(f, v.Build.RequirementsFromFile)
	_, a, err := ActionFromDepositBuild(readVectorFile(f, v.Build.FromFile), v.Build.Resource, RequirementsHash(r0))
	require.NoError(f, err)
	f.Fuzz(func(t *testing.T, r []byte) {
		// Bind the action to the fuzzed R so the checks past the hash run.
		ra := rebind(t, a, r)
		q, err := CheckRequirements(ra, r, true)
		if err != nil {
			require.ErrorIs(t, err, ErrRequirements)
			return
		}
		require.Equal(t, ra.RequirementsHash, RequirementsHash(r))
		require.Equal(t, ra.Deposit.PaymentID, q.PaymentID())
		require.True(t, json.Valid(r))
	})
}

func rebind(t testing.TB, a TxAction, r []byte) TxAction {
	t.Helper()
	b, err := EncodeTxAction(a.Unsigned(), a.Resource, RequirementsHash(r))
	require.NoError(t, err)
	out, err := DecodeTxAction(b)
	require.NoError(t, err)
	return out
}

// A decoded header is the base64 of exactly what it returns.
func FuzzDecodePaymentRequired(f *testing.F) {
	f.Add("eyJ4NDAyVmVyc2lvbiI6Mn0=")
	f.Add("eyJ4NDAyVmVyc2lvbiI6Mn0")
	f.Add("QQ=")
	f.Add("a\r\nb")
	f.Fuzz(func(t *testing.T, h string) {
		r, err := DecodePaymentRequired(h)
		if err != nil {
			require.ErrorIs(t, err, ErrRequirements)
			return
		}
		require.NotEmpty(t, r)
		require.LessOrEqual(t, len(r), MaxRequirementsSize)
		require.Equal(t, r, mustStdDecode(t, base64.StdEncoding.EncodeToString(r)))
		trimmed := strings.TrimRight(h, "=")
		require.Equal(t, len(base64.RawStdEncoding.EncodeToString(r)), len(trimmed))
	})
}

func mustStdDecode(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

// The strict reader accepts only what encoding/json accepts, never nests
// deeper than its limit, and keeps member names unique.
func FuzzStrictJSON(f *testing.F) {
	v := loadJSON[x402File](f, "x402.json")
	for _, c := range append(v.BuildAccept, v.BuildReject...) {
		f.Add(c.body(f))
	}
	for _, c := range append(v.Requirements.Accept, v.Requirements.Reject...) {
		f.Add(unhex(f, c.RHex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		doc, err := parseJSON(b)
		if err != nil {
			require.ErrorIs(t, err, errJSON)
			return
		}
		require.True(t, json.Valid(b), "%q", b)
		type item struct {
			v     *jsonValue
			depth int
		}
		stack := []item{{doc, 1}}
		for len(stack) > 0 {
			it := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if it.v.kind != jsonObject && it.v.kind != jsonArray {
				continue
			}
			require.LessOrEqual(t, it.depth, maxJSONDepth)
			names := map[string]bool{}
			for _, m := range it.v.members {
				require.False(t, names[m.name], "member %q twice", m.name)
				names[m.name] = true
				stack = append(stack, item{m.value, it.depth + 1})
			}
			for _, e := range it.v.elems {
				stack = append(stack, item{e, it.depth + 1})
			}
		}
	})
}
