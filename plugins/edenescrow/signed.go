// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/evm/rlp"
)

// Signature is a secp256k1 signature over a transaction's SigHash. R and S
// are big-endian, left-padded to 32 bytes.
type Signature struct {
	YParity byte
	R, S    [32]byte
}

// Sign signs digest with a deterministic (RFC 6979) low-s signature, so a
// re-sign after a crash gives the same bytes.
func Sign(priv *secp256k1.PrivateKey, digest [32]byte) (Signature, error) {
	if priv == nil {
		return Signature{}, fmt.Errorf("%w: no key", ErrSignature)
	}
	c, err := evm.Sign(priv, digest)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	var sig Signature
	sig.YParity = c[64]
	copy(sig.R[:], c[:32])
	copy(sig.S[:], c[32:64])
	return sig, nil
}

// RecoverPayer returns the address whose key made sig over digest. It
// accepts only y_parity 0 or 1, 1 <= r < n and 1 <= s <= n/2: one signature
// per digest and key, as the execution client requires.
func RecoverPayer(digest [32]byte, sig Signature) ([20]byte, error) {
	if sig.YParity > 1 {
		return [20]byte{}, fmt.Errorf("%w: y_parity %d", ErrSignature, sig.YParity)
	}
	var r, s secp256k1.ModNScalar
	if r.SetBytes(&sig.R) != 0 || r.IsZero() {
		return [20]byte{}, fmt.Errorf("%w: r out of range", ErrSignature)
	}
	if s.SetBytes(&sig.S) != 0 || s.IsZero() || s.IsOverHalfOrder() {
		return [20]byte{}, fmt.Errorf("%w: s not in 1..n/2", ErrSignature)
	}
	var rs [65]byte
	copy(rs[:32], sig.R[:])
	copy(rs[32:64], sig.S[:])
	rs[64] = sig.YParity
	a, err := evm.RecoverAddress(digest, rs)
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return a, nil
}

// Address is the Ethereum address of a public key.
func Address(pub *secp256k1.PublicKey) [20]byte { return evm.Address(pub) }

// SignTx signs the action's SigHash with the payer key and splices the
// signature in. It is the only path a signer needs: the signature is
// checked to recover to the key's own address before any bytes leave.
func (a TxAction) SignTx(priv *secp256k1.PrivateKey) ([]byte, Signature, error) {
	if priv == nil {
		return nil, Signature{}, fmt.Errorf("%w: no key", ErrSignature)
	}
	sig, err := Sign(priv, a.SigHash())
	if err != nil {
		return nil, Signature{}, err
	}
	signed, err := a.Splice(sig, Address(priv.PubKey()))
	if err != nil {
		return nil, Signature{}, err
	}
	return signed, sig, nil
}

// Splice returns the signed transaction: the action's 9 item encodings
// verbatim, then y_parity, r and s, under a new list header. Nothing is
// re-encoded from fields. The signature must recover over SigHash to payer:
// another key, a flipped parity or a signature over another digest would
// yield broadcastable bytes from an unintended sender, and the stored digest
// of the decision would then repeat those bytes.
func (a TxAction) Splice(sig Signature, payer [20]byte) ([]byte, error) {
	if len(a.items) == 0 {
		return nil, fmt.Errorf("%w: the action was not decoded", ErrMalformed)
	}
	got, err := RecoverPayer(a.SigHash(), sig)
	if err != nil {
		return nil, err
	}
	if got != payer {
		return nil, fmt.Errorf("%w: recovers to %x, not the payer %x", ErrSignature, got, payer)
	}
	y := []byte{0x80}
	if sig.YParity == 1 {
		y = []byte{0x01}
	}
	rr := rlp.AppendString(nil, trimZeros(sig.R[:]))
	ss := rlp.AppendString(nil, trimZeros(sig.S[:]))
	return rlp.AppendList([]byte{txType}, a.items, y, rr, ss), nil
}

// ParseSigned checks that signed is exactly the action's transaction with one
// signature spliced in: type 0x02, one canonical RLP list of 12 items and
// nothing after it, the first 9 byte-identical as encodings to the action's,
// then y_parity as 0x80 or 0x01 and canonical r and s that recover a key. It
// returns the signature and the payer. Every failure is ErrSignedMismatch.
func ParseSigned(a TxAction, signed []byte) (Signature, [20]byte, error) {
	fail := func(format string, args ...any) (Signature, [20]byte, error) {
		return Signature{}, [20]byte{}, fmt.Errorf("%w: %s", ErrSignedMismatch, fmt.Sprintf(format, args...))
	}
	if len(a.items) == 0 {
		return fail("the action was not decoded")
	}
	if len(signed) < 1 || signed[0] != txType {
		return fail("not a type 2 transaction")
	}
	top, rest, err := rlp.Next(signed[1:])
	switch {
	case err != nil:
		return fail("%v", err)
	case !top.List:
		return fail("not an RLP list")
	case len(rest) != 0:
		return fail("%d bytes after the list", len(rest))
	case !bytes.HasPrefix(top.Payload, a.items):
		return fail("the first 9 items differ from the authorized transaction")
	}
	var tail [3]rlp.Item
	b := top.Payload[len(a.items):]
	for i := range tail {
		it, r, err := rlp.Next(b)
		if err != nil {
			return fail("signature item %d: %v", i, err)
		}
		if it.List {
			return fail("signature item %d is a list", i)
		}
		tail[i], b = it, r
	}
	if len(b) != 0 {
		return fail("more than 12 items")
	}
	var sig Signature
	switch {
	case bytes.Equal(tail[0].Raw, []byte{0x80}):
	case bytes.Equal(tail[0].Raw, []byte{0x01}):
		sig.YParity = 1
	default:
		return fail("y_parity encoded as %x", tail[0].Raw)
	}
	for i, dst := range []*[32]byte{&sig.R, &sig.S} {
		v := tail[1+i].Payload
		if len(v) > 32 || len(v) > 0 && v[0] == 0 {
			return fail("signature item %d is not a canonical 256-bit integer", 1+i)
		}
		copy(dst[32-len(v):], v)
	}
	payer, err := RecoverPayer(a.SigHash(), sig)
	if err != nil {
		return Signature{}, [20]byte{}, fmt.Errorf("%w: %w", ErrSignedMismatch, err)
	}
	return sig, payer, nil
}

// RailRef is the receipt's rail_ref of a signed transaction: its Eden
// transaction hash as 64 lower-case hex characters, without 0x.
func RailRef(signed []byte) string {
	h := evm.Keccak256(signed)
	return hex.EncodeToString(h[:])
}

// ParseRailRef accepts only the form RailRef produces.
func ParseRailRef(s string) ([32]byte, bool) {
	var h [32]byte
	if len(s) != 64 {
		return h, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return h, false
		}
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return [32]byte{}, false
	}
	return h, true
}

func trimZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}
