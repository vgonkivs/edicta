// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
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
		require.NoError(t, a.Facts().Validate())
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
