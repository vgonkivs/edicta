// Package principalsig verifies and produces the principal's signature over
// a mandate under the three schemes of policy v1: Ed25519, Cosmos ADR-036
// (Keplr signArbitrary) and EIP-712 (eth_signTypedData_v4). Everything here
// is pure; wallets sign out of process.
package principalsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/vgonkivs/edicta/commitment"
)

// Scheme names a principal signature scheme. The values of Cosmos and EIP-712
// equal the mandate's sig_type; Ed25519 is the absent sig_type.
type Scheme uint8

const (
	Ed25519      Scheme = 1
	CosmosADR036 Scheme = 2
	EIP712       Scheme = 3
)

func (s Scheme) String() string {
	switch s {
	case Ed25519:
		return "ed25519"
	case CosmosADR036:
		return "cosmos-adr036"
	case EIP712:
		return "eip712"
	}
	return fmt.Sprintf("scheme(%d)", uint8(s))
}

var (
	ErrScheme    = errors.New("principalsig: unsupported scheme")
	ErrPrincipal = errors.New("principalsig: invalid principal")
	ErrSignature = errors.New("principalsig: invalid signature")
)

// TagMandateSig is the policy v1 tag of the Ed25519 mandate signature.
const TagMandateSig = "edicta/policy/v1/mandate-sig"

// EIP712Message is what a principal signature binds. Every scheme binds
// MandateHash; EIP-712 also shows and hashes the other fields.
type EIP712Message struct {
	MandateHash [32]byte
	MandateID   [16]byte
	Version     uint64
	GateID      string
}

// Message is the 61-byte Ed25519 signing message: tag(mandate-sig) || mandate_hash.
func Message(mandateHash [32]byte) []byte {
	out := make([]byte, 0, 1+len(TagMandateSig)+32)
	out = append(out, byte(len(TagMandateSig)))
	out = append(out, TagMandateSig...)
	return append(out, mandateHash[:]...)
}

// SignatureSize is the size of a signature under the scheme, or 0.
func SignatureSize(s Scheme) int {
	switch s {
	case Ed25519, CosmosADR036:
		return 64
	case EIP712:
		return 65
	}
	return 0
}

// CheckPrincipal checks the principal's encoding for the scheme: a G0-checked
// Ed25519 key, a compressed secp256k1 point, or a 20-byte address.
func CheckPrincipal(s Scheme, principal []byte) error {
	switch s {
	case Ed25519:
		if err := commitment.CheckPublicKey(principal); err != nil {
			return fmt.Errorf("%w: %w", ErrPrincipal, err)
		}
	case CosmosADR036:
		if _, err := parseCompressed(principal); err != nil {
			return err
		}
	case EIP712:
		if len(principal) != 20 {
			return fmt.Errorf("%w: %d bytes for an address: %w", ErrPrincipal, len(principal), commitment.ErrFieldSize)
		}
	default:
		return ErrScheme
	}
	return nil
}

func parseCompressed(principal []byte) (*secp256k1.PublicKey, error) {
	if len(principal) != secp256k1.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("%w: %d bytes for a compressed key: %w", ErrPrincipal, len(principal), commitment.ErrFieldSize)
	}
	if principal[0] != 0x02 && principal[0] != 0x03 {
		return nil, fmt.Errorf("%w: prefix 0x%02x: %w", ErrPrincipal, principal[0], commitment.ErrInvalidPublicKey)
	}
	pub, err := secp256k1.ParsePubKey(principal)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %v", ErrPrincipal, commitment.ErrInvalidPublicKey, err)
	}
	return pub, nil
}

// Verify checks sig under the scheme. hrp and rendered (the text D, built by
// the caller from a fresh re-render of the mandate, never taken from a
// request) are used by CosmosADR036 only; the ID, version and gate of m by
// EIP712 only.
func Verify(s Scheme, principal []byte, hrp string, m EIP712Message, rendered []byte, sig []byte) error {
	if err := CheckPrincipal(s, principal); err != nil {
		return err
	}
	if len(sig) != SignatureSize(s) {
		return fmt.Errorf("%w: %d bytes", ErrSignature, len(sig))
	}
	switch s {
	case Ed25519:
		// crypto/ed25519 refuses S >= L and verifies cofactorless.
		if !ed25519.Verify(principal, Message(m.MandateHash), sig) {
			return ErrSignature
		}
		return nil
	case CosmosADR036:
		return verifyADR036(principal, hrp, m.MandateHash, rendered, sig)
	default:
		return verifyEIP712(principal, m, sig)
	}
}

// scalars parses r || s, refusing values outside [1, n-1] and a high s: the
// Cosmos SDK and Ethereum nodes refuse high s, and accepting it would give
// two encodings of one signature.
func scalars(rs []byte) (r, s secp256k1.ModNScalar, err error) {
	if r.SetByteSlice(rs[:32]) || r.IsZero() {
		return r, s, fmt.Errorf("%w: r out of range", ErrSignature)
	}
	if s.SetByteSlice(rs[32:64]) || s.IsZero() {
		return r, s, fmt.Errorf("%w: s out of range", ErrSignature)
	}
	if s.IsOverHalfOrder() {
		return r, s, fmt.Errorf("%w: high s", ErrSignature)
	}
	return r, s, nil
}

func verifyADR036(principal []byte, hrp string, mandateHash [32]byte, rendered, sig []byte) error {
	pub, err := parseCompressed(principal)
	if err != nil {
		return err
	}
	if !hasHashLine(rendered, mandateHash) {
		return fmt.Errorf("%w: the signed text does not end in the mandate hash", ErrSignature)
	}
	doc, err := ADR036SignDoc(principal, hrp, rendered)
	if err != nil {
		return err
	}
	r, s, err := scalars(sig)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(doc)
	if !ecdsa.NewSignature(&r, &s).Verify(digest[:], pub) {
		return ErrSignature
	}
	return nil
}

func verifyEIP712(principal []byte, m EIP712Message, sig []byte) error {
	v := sig[64]
	if v != 27 && v != 28 {
		return fmt.Errorf("%w: v = %d", ErrSignature, v)
	}
	if _, _, err := scalars(sig[:64]); err != nil {
		return err
	}
	compact := make([]byte, 0, 65)
	compact = append(compact, v)
	compact = append(compact, sig[:64]...)
	digest := EIP712Digest(m)
	pub, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	addr := ethAddress(pub)
	if subtle.ConstantTimeCompare(addr[:], principal) != 1 {
		return fmt.Errorf("%w: recovered address differs", ErrSignature)
	}
	return nil
}
