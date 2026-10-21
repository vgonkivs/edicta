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
		enc, err := EncodeTxAction(a.Unsigned, a.Resource, a.RequirementsHash)
		require.NoError(t, err)
		require.Equal(t, b, enc)
		require.NoError(t, a.Facts().Validate())
		require.Equal(t, a.Row.Escrow, a.To)
		require.NotEmpty(t, a.Value)
		require.LessOrEqual(t, len(a.Unsigned), MaxTxSize)
		require.True(t, bytes.HasPrefix(a.Unsigned[1:], rlpListHeader(len(a.items))))
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
		again, err := a.Splice(sig)
		require.NoError(t, err)
		require.Equal(t, signed, again)
		p, err := RecoverPayer(a.SigHash(), sig)
		require.NoError(t, err)
		require.Equal(t, payer, p)
	})
}
