// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/policy"
)

// f14 is the vector action tx_f14_714, valid in every build.
func f14(t testing.TB) (TxAction, []byte) {
	t.Helper()
	v := loadJSON[actionFile](t, "action.json")
	b := unhex(t, caseByID(t, v, "tx_f14_714").CBORHex)
	a, err := DecodeTxAction(b)
	require.NoError(t, err)
	return a, b
}

func payerKey(t testing.TB) *secp256k1.PrivateKey {
	t.Helper()
	v := loadJSON[signedFile](t, "signed.json")
	return secp256k1.PrivKeyFromBytes(unhex(t, v.Keys["payer1"].PrivateKeyHex))
}

func payerAddr(t testing.TB) [20]byte {
	t.Helper()
	return Address(payerKey(t).PubKey())
}

func TestDecodedActionDoesNotAliasInput(t *testing.T) {
	_, b := f14(t)
	a, err := DecodeTxAction(b)
	require.NoError(t, err)
	want, err := DecodeTxAction(bytes.Clone(b))
	require.NoError(t, err)
	for i := range b {
		b[i] ^= 0xff
	}
	assert.Equal(t, want, a)
	sig, err := Sign(payerKey(t), a.SigHash())
	require.NoError(t, err)
	signed, err := a.Splice(sig, payerAddr(t))
	require.NoError(t, err)
	wantSigned, err := want.Splice(sig, payerAddr(t))
	require.NoError(t, err)
	assert.Equal(t, wantSigned, signed)
}

func TestRowsIsACopy(t *testing.T) {
	rows := Rows()
	rows[0].Escrow = [20]byte{1}
	r, ok := Lookup(714)
	require.True(t, ok)
	assert.Equal(t, escrowMainnet, r.Escrow)
}

func TestNewIsARegistrableExtractor(t *testing.T) {
	reg, err := policy.NewExtractors(New())
	require.NoError(t, err)
	id, ok := reg.ID(ActionType)
	require.True(t, ok)
	assert.Equal(t, RegisteredExtractorID(), id)
}

func cborMap(pairs ...[]byte) []byte {
	out := cborHeadBytes(majorMap, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func cborBstr(b []byte) []byte { return append(cborHeadBytes(majorBytes, uint64(len(b))), b...) }
func cborTstr(s string) []byte { return append(cborHeadBytes(majorText, uint64(len(s))), s...) }
func cborUint(n uint64) []byte { return cborHeadBytes(majorUint, n) }

func TestDecoderBounds(t *testing.T) {
	a, _ := f14(t)
	req := cborBstr(a.RequirementsHash[:])
	res := cborTstr(a.Resource)
	tx := cborBstr(a.unsigned)
	cases := []struct {
		name string
		in   []byte
		rule string
	}{
		{"4096 bytes reach the schema", cborMap(cborUint(2), cborBstr(make([]byte, 4091))), "EA3"},
		{"nested deeper than four", cborMap(cborUint(1), cborMap(cborUint(1), cborMap(cborUint(1), cborMap(cborUint(1), cborMap())))), "EA2"},
		{"seventeen entries", append(cborHeadBytes(majorArray, 17), bytes.Repeat([]byte{0}, 17)...), "EA2"},
		{"text map key", cborMap(cborTstr("a"), cborUint(1)), "EA2"},
		{"negative map key", cborMap([]byte{0x20}, cborUint(1)), "EA2"},
		{"invalid UTF-8", cborMap(cborUint(3), []byte{0x61, 0xff}), "EA2"},
		{"reserved additional info", []byte{0x1c}, "EA2"},
		{"stray break", []byte{0xff}, "EA2"},
		{"truncated head", []byte{0x19, 0x01}, "EA2"},
		{"negative version", cborMap(cborUint(1), []byte{0x20}, cborUint(2), tx, cborUint(3), res, cborUint(4), req), "EA3"},
		{"version as map", cborMap(cborUint(1), cborMap(), cborUint(2), tx, cborUint(3), res, cborUint(4), req), "EA3"},
		{"key 0", cborMap(cborUint(0), cborUint(1), cborUint(1), cborUint(1), cborUint(2), tx, cborUint(3), res, cborUint(4), req), "EA3"},
		{"requirements 33", cborMap(cborUint(1), cborUint(1), cborUint(2), tx, cborUint(3), res, cborUint(4), cborBstr(make([]byte, 33))), "EA3"},
		{"only a uint", cborUint(1), "EA3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeTxAction(c.in)
			require.ErrorIs(t, err, ErrMalformed)
			assert.Equal(t, c.rule, ruleOf(t, err))
		})
	}
}

// withTx re-wraps the f14 action around another unsigned transaction.
func withTx(t testing.TB, items ...[]byte) []byte {
	t.Helper()
	a, _ := f14(t)
	var p []byte
	for _, it := range items {
		p = append(p, it...)
	}
	tx := append([]byte{txType}, rlpListHeader(len(p))...)
	tx = append(tx, p...)
	return cborMap(cborUint(1), cborUint(1), cborUint(2), cborBstr(tx), cborUint(3), cborTstr(a.Resource),
		cborUint(4), cborBstr(a.RequirementsHash[:]))
}

// f14Items are the canonical item encodings of the f14 transaction.
func f14Items(t testing.TB) [][]byte {
	t.Helper()
	a, _ := f14(t)
	var out [][]byte
	for b := a.items; len(b) > 0; {
		it, rest, err := rlpNext(b)
		require.NoError(t, err)
		out = append(out, it.raw)
		b = rest
	}
	require.Len(t, out, txItems)
	return out
}

func replaced(items [][]byte, i int, b []byte) [][]byte {
	out := append([][]byte(nil), items...)
	out[i] = b
	return out
}

func TestTransactionRules(t *testing.T) {
	it := f14Items(t)
	nested := []byte{0xc0}
	for range maxNesting + 1 {
		nested = append(rlpListHeader(len(nested)), nested...)
	}
	cases := []struct {
		name  string
		items [][]byte
		rule  string
	}{
		{"access list entry not canonical", replaced(it, 8, []byte{0xc2, 0x81, 0x05}), "ET2"},
		{"access list nested too deep", replaced(it, 8, nested), "ET2"},
		{"data as a list", replaced(it, 7, []byte{0xc0}), "ET2"},
		{"to as a list", replaced(it, 5, []byte{0xc0}), "ET2"},
		{"tip above the fee", replaced(it, 2, rlpString([]byte{0x08, 0xfc})), "ET4"},
		{"to of 21 bytes", replaced(it, 5, rlpString(make([]byte, 21))), "ET5"},
		{"empty data", replaced(it, 7, []byte{0x80}), "ET8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeTxAction(withTx(t, c.items...))
			require.ErrorIs(t, err, ErrMalformed)
			assert.Equal(t, c.rule, ruleOf(t, err))
		})
	}

	_, err := DecodeTxAction(withTx(t, replaced(it, 2, it[3])...))
	require.NoError(t, err, "a tip equal to the fee is accepted")
	_, err = DecodeTxAction(withTx(t, replaced(it, 1, []byte{0x88, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})...))
	require.NoError(t, err, "nonce 2^63-1 is accepted")
}

func TestEncodeTxActionRefusesWhatTheDecoderRefuses(t *testing.T) {
	a, b := f14(t)
	got, err := EncodeTxAction(a.unsigned, a.Resource, a.RequirementsHash)
	require.NoError(t, err)
	assert.Equal(t, b, got)

	long := "https://a.example/" + strings.Repeat("a", MaxResourceSize-len("https://a.example/"))
	_, err = EncodeTxAction(a.unsigned, long, a.RequirementsHash)
	require.NoError(t, err, "a resource of exactly the maximum")
	_, err = EncodeTxAction(a.unsigned, long+"a", a.RequirementsHash)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = EncodeTxAction(a.unsigned, "https://a.example/x y", a.RequirementsHash)
	require.ErrorIs(t, err, ErrMalformed)
	_, err = EncodeTxAction(a.unsigned[:len(a.unsigned)-1], a.Resource, a.RequirementsHash)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestSignatureRanges(t *testing.T) {
	a, _ := f14(t)
	sig, err := Sign(payerKey(t), a.SigHash())
	require.NoError(t, err)

	var n [32]byte
	secp256k1.S256().N.FillBytes(n[:])
	var high secp256k1.ModNScalar
	high.SetBytes(&sig.S)
	high.Negate()
	highS := sig
	highS.S = high.Bytes()
	highS.YParity ^= 1

	bad := map[string]Signature{
		"y_parity 2": {YParity: 2, R: sig.R, S: sig.S},
		"r zero":     {YParity: sig.YParity, S: sig.S},
		"s zero":     {YParity: sig.YParity, R: sig.R},
		"r equals n": {YParity: sig.YParity, R: n, S: sig.S},
		"s equals n": {YParity: sig.YParity, R: sig.R, S: n},
		"high s":     highS,
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := RecoverPayer(a.SigHash(), s)
			require.ErrorIs(t, err, ErrSignature)
			_, err = a.Splice(s, payerAddr(t))
			require.ErrorIs(t, err, ErrSignature)
		})
	}

	// The other parity recovers another key (or none): Splice refuses it,
	// so no bytes from an unintended sender ever leave.
	flipped := sig
	flipped.YParity ^= 1
	_, err = a.Splice(flipped, payerAddr(t))
	require.ErrorIs(t, err, ErrSignature)

	// A valid signature by another key is refused too.
	other, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	otherSig, err := Sign(other, a.SigHash())
	require.NoError(t, err)
	_, err = a.Splice(otherSig, payerAddr(t))
	require.ErrorIs(t, err, ErrSignature)
	_, err = a.Splice(otherSig, Address(other.PubKey()))
	require.NoError(t, err)
}

func TestSignTxIsTheSplicedSignature(t *testing.T) {
	a, _ := f14(t)
	signed, sig, err := a.SignTx(payerKey(t))
	require.NoError(t, err)
	want, err := Sign(payerKey(t), a.SigHash())
	require.NoError(t, err)
	assert.Equal(t, want, sig)
	_, payer, err := ParseSigned(a, signed)
	require.NoError(t, err)
	assert.Equal(t, payerAddr(t), payer)

	_, _, err = a.SignTx(nil)
	require.ErrorIs(t, err, ErrSignature)
	var zero TxAction
	_, _, err = zero.SignTx(payerKey(t))
	require.ErrorIs(t, err, ErrMalformed)
}

// Writing into the bytes Unsigned returns changes neither the digest nor the
// signed transaction: only the decoded bytes are ever signed.
func TestUnsignedIsACopy(t *testing.T) {
	a, _ := f14(t)
	h := a.SigHash()
	before, _, err := a.SignTx(payerKey(t))
	require.NoError(t, err)
	u := a.Unsigned()
	for i := range u {
		u[i] ^= 0xff
	}
	assert.Equal(t, h, a.SigHash())
	after, _, err := a.SignTx(payerKey(t))
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assert.NotEqual(t, u, a.Unsigned())
}

func TestUndecodedActionIsRefused(t *testing.T) {
	a, _ := f14(t)
	sig, err := Sign(payerKey(t), a.SigHash())
	require.NoError(t, err)
	signed, err := a.Splice(sig, payerAddr(t))
	require.NoError(t, err)

	var zero TxAction
	_, err = zero.Splice(sig, payerAddr(t))
	require.ErrorIs(t, err, ErrMalformed)
	_, _, err = ParseSigned(zero, signed)
	require.ErrorIs(t, err, ErrSignedMismatch)
	_, err = Sign(nil, a.SigHash())
	require.ErrorIs(t, err, ErrSignature)
}

func TestParseSignedRefusesAnotherAction(t *testing.T) {
	v := loadJSON[actionFile](t, "action.json")
	a, _ := f14(t)
	other, err := DecodeTxAction(unhex(t, caseByID(t, v, "tx_min_714").CBORHex))
	require.NoError(t, err)
	sig, err := Sign(payerKey(t), other.SigHash())
	require.NoError(t, err)
	signed, err := other.Splice(sig, payerAddr(t))
	require.NoError(t, err)
	_, _, err = ParseSigned(a, signed)
	require.ErrorIs(t, err, ErrSignedMismatch)
}
