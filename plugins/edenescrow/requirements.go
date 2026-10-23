// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/vgonkivs/edicta/internal/evm"
)

// MaxRequirementsSize bounds R, the decoded PAYMENT-REQUIRED document.
const MaxRequirementsSize = 16384

// Scheme is the x402 scheme of an escrow deposit quote.
const Scheme = "escrow-upto"

// DecodePaymentRequired returns R, the bytes of the PAYMENT-REQUIRED header
// value as the HTTP library returns it: standard base64 alphabet, padding
// optional, no other character. Only the decoded bytes are hashed, so two
// spellings of one document bind the same requirements_hash.
func DecodePaymentRequired(value string) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(MaxRequirementsSize) {
		return nil, requirements("S4a", "header of %d characters", len(value))
	}
	body := strings.TrimRight(value, "=")
	if pad := len(value) - len(body); pad > 2 || pad > 0 && len(value)%4 != 0 {
		return nil, requirements("RH", "padding of %d characters", pad)
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return nil, requirements("RH", "character 0x%02x at %d", c, i)
		}
	}
	// The alphabet check above leaves no line break for the decoder to skip.
	r, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		return nil, requirements("RH", "%v", err)
	}
	if len(r) < 1 || len(r) > MaxRequirementsSize {
		return nil, requirements("S4a", "R of %d bytes", len(r))
	}
	return r, nil
}

// Quote is the escrow-upto entry of R that CheckRequirements selected for
// one action. Only CheckRequirements makes one, so a Quote always belongs
// to an R the action's requirements_hash binds.
type Quote struct {
	paymentID        [32]byte
	requirementsHash [32]byte
}

// PaymentID is the quote's paymentId, the action's w0.
func (q Quote) PaymentID() [32]byte { return q.paymentID }

// RequirementsHash is the requirements_hash of the R the quote came from.
func (q Quote) RequirementsHash() [32]byte { return q.requirementsHash }

// CheckRequirements runs the requirements checks on R against a decoded
// action, in order: size, binding to the action's requirements_hash,
// document, exactly one escrow-upto entry for the action's paymentId, that
// entry's fields equal to the deposit, and, when checkServerSignature is
// set, the facilitator's signature over paymentId. Every failure is
// ErrRequirements. The server signs only paymentId, so the field equalities
// show consistency with the quote, not the server's authority over them.
func CheckRequirements(a TxAction, r []byte, checkServerSignature bool) (Quote, error) {
	if len(a.items) == 0 {
		return Quote{}, fmt.Errorf("%w: the action was not decoded", ErrMalformed)
	}
	if len(r) < 1 || len(r) > MaxRequirementsSize {
		return Quote{}, requirements("S4a", "R of %d bytes", len(r))
	}
	if RequirementsHash(r) != a.RequirementsHash {
		return Quote{}, requirements("S4b", "R does not hash to the action's requirements_hash")
	}
	doc, err := parseJSON(r)
	switch {
	case err != nil:
		return Quote{}, requirements("S4c", "%v", err)
	case doc.kind != jsonObject:
		return Quote{}, requirements("S4c", "R is not an object")
	}
	if v := doc.member("x402Version"); v == nil || v.kind != jsonNumber || v.text != "2" {
		return Quote{}, requirements("S4c", "x402Version is not the number 2")
	}
	accepts := doc.member("accepts")
	if accepts == nil || accepts.kind != jsonArray {
		return Quote{}, requirements("S4c", "accepts is not an array")
	}

	d := a.Deposit
	var entry *jsonValue
	for _, e := range accepts.elems {
		if s := e.member("scheme"); !s.isString() || s.text != Scheme {
			continue
		}
		extra := e.member("extra")
		if extra == nil || extra.kind != jsonObject {
			continue
		}
		if pid, ok := hexString(extra.member("paymentId"), 32); !ok || [32]byte(pid) != d.PaymentID {
			continue
		}
		if entry != nil {
			return Quote{}, requirements("S4d", "two %s entries for the action's paymentId", Scheme)
		}
		entry = e
	}
	if entry == nil {
		return Quote{}, requirements("S4d", "no %s entry for the action's paymentId", Scheme)
	}
	extra := entry.member("extra")

	if err := checkEntry(a, entry, extra); err != nil {
		return Quote{}, err
	}
	// extra.nonce is checked for its form only: no server signature covers
	// it, so nothing here ever signs or returns it.
	if n := extra.member("nonce"); n != nil {
		if _, ok := hexString(n, 32); !ok {
			return Quote{}, requirements("S4e", "extra.nonce is not 0x and 64 hex digits")
		}
	}
	q := Quote{paymentID: d.PaymentID, requirementsHash: a.RequirementsHash}
	if checkServerSignature {
		b, ok := hexString(extra.member("serverSignature"), 65)
		if !ok {
			return Quote{}, requirements("S4f", "extra.serverSignature is not 0x and 130 hex digits")
		}
		signer, err := RecoverPersonal(d.PaymentID, [65]byte(b))
		if err != nil {
			return Quote{}, requirements("S4f", "%v", err)
		}
		if signer != d.Facilitator {
			return Quote{}, requirements("S4f", "serverSignature recovers to %x, not the facilitator", signer)
		}
	}
	return q, nil
}

// checkEntry holds every quoted field of the entry to the action, in a
// fixed order.
func checkEntry(a TxAction, entry, extra *jsonValue) error {
	d := a.Deposit
	str := func(v *jsonValue, want string) bool { return v.isString() && v.text == want }
	addr := func(v *jsonValue, want [20]byte) bool {
		b, ok := hexString(v, 20)
		return ok && [20]byte(b) == want
	}
	uintEq := func(v *jsonValue, want uint64) bool {
		n, ok := jsonUint(v)
		return ok && n == want
	}
	bigEq := func(v *jsonValue, want []byte) bool {
		n, ok := decimalString(v)
		return ok && n.Cmp(new(big.Int).SetBytes(want)) == 0
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{"network", str(entry.member("network"), caipChain(a.ChainID))},
		{"asset", str(entry.member("asset"), "native")},
		{"amount", bigEq(entry.member("amount"), a.Value)},
		{"payTo", addr(entry.member("payTo"), d.PayTo)},
		{"extra.escrowContract", addr(extra.member("escrowContract"), a.To)},
		{"extra.facilitator", addr(extra.member("facilitator"), d.Facilitator)},
		{"extra.expiresAt", uintEq(extra.member("expiresAt"), d.ExpiresAt)},
		{"extra.refundAfter", uintEq(extra.member("refundAfter"), d.RefundAfter)},
		{"extra.tiaPriceUsd", bigEq(extra.member("tiaPriceUsd"), d.TIAPriceUSD[:])},
		{"extra.chainId", uintEq(extra.member("chainId"), a.ChainID)},
	}
	for _, c := range checks {
		if !c.ok {
			return requirements("S4e", "%s differs from the action or has the wrong form", c.name)
		}
	}
	return nil
}

// personalPrefix is the EIP-191 version 0x45 prefix for a 32-byte message.
const personalPrefix = "\x19Ethereum Signed Message:\n" + "32"

// PersonalDigest is the personal_sign digest of a 32-byte message:
// keccak256(0x19 || "Ethereum Signed Message:\n32" || m). 0x19 lies in the
// EIP-2718 type range but is neither 0x02, the only type the payer key
// signs, nor an RLP list prefix (a legacy transaction), so the preimage
// never stands for a transaction that key signs.
func PersonalDigest(m [32]byte) [32]byte {
	return evm.Keccak256([]byte(personalPrefix), m[:])
}

// PaymentProofMessage is the message a Payment-Signature covers for a
// decoded action: its paymentId (w0), released only when the committed
// resource names https:// and R passes every requirements check with the
// facilitator's signature enforced, so the 32 bytes are ones the pinned
// facilitator signed, never bytes the agent chose. A nil R is refused.
// Every failure is ErrRequirements.
func PaymentProofMessage(a TxAction, r []byte) ([32]byte, error) {
	if len(a.items) == 0 {
		return [32]byte{}, fmt.Errorf("%w: the action was not decoded", ErrMalformed)
	}
	if !strings.HasPrefix(a.Resource, "https://") {
		return [32]byte{}, requirements("S11c", "the committed resource does not start with https://")
	}
	if r == nil {
		return [32]byte{}, requirements("absent", "no R stored or presented")
	}
	q, err := CheckRequirements(a, r, true)
	if err != nil {
		return [32]byte{}, err
	}
	return q.PaymentID(), nil
}

// RecoverPersonal returns the address whose key made sig, r || s || v, as
// personal_sign over m. v is 0, 1, 27 or 28; r and s are in 1..n-1. A high
// s is accepted: only the signer's identity matters here, not the
// signature's uniqueness.
func RecoverPersonal(m [32]byte, sig [65]byte) ([20]byte, error) {
	v := sig[64]
	switch v {
	case 0, 1:
	case 27, 28:
		v -= 27
	default:
		return [20]byte{}, fmt.Errorf("%w: v %d", ErrSignature, sig[64])
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[:32]) || r.IsZero() {
		return [20]byte{}, fmt.Errorf("%w: r not in 1..n-1", ErrSignature)
	}
	if s.SetByteSlice(sig[32:64]) || s.IsZero() {
		return [20]byte{}, fmt.Errorf("%w: s not in 1..n-1", ErrSignature)
	}
	var compact [65]byte
	compact[0] = 27 + v
	copy(compact[1:], sig[:64])
	digest := PersonalDigest(m)
	pub, _, err := ecdsa.RecoverCompact(compact[:], digest[:])
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return Address(pub), nil
}
