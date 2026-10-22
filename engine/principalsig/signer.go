package principalsig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Signer signs mandates with a raw key, for the CLI and tests. rendered is
// the text D (ADR036Data) and is used by CosmosADR036 only.
type Signer interface {
	Scheme() Scheme
	Principal() []byte
	Sign(m EIP712Message, rendered []byte) ([]byte, error)
}

// HRPSigner is a CosmosADR036 signer that names the bech32 prefix of the
// signer address in its sign doc.
type HRPSigner interface {
	Signer
	HRP() string
}

type ed25519Signer struct{ sk ed25519.PrivateKey }

// NewEd25519Signer returns a signer of M with sk.
func NewEd25519Signer(sk ed25519.PrivateKey) Signer { return ed25519Signer{sk: sk} }

func (ed25519Signer) Scheme() Scheme { return Ed25519 }

func (s ed25519Signer) Principal() []byte {
	if len(s.sk) != ed25519.PrivateKeySize {
		return nil
	}
	return append([]byte(nil), s.sk[32:]...)
}

func (s ed25519Signer) Sign(m EIP712Message, _ []byte) ([]byte, error) {
	if len(s.sk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("principalsig: ed25519 private key has %d bytes", len(s.sk))
	}
	return ed25519.Sign(s.sk, Message(m.MandateHash)), nil
}

type secpSigner struct {
	scheme Scheme
	sk     *secp256k1.PrivateKey
	hrp    string
}

// NewSecp256k1Signer returns a CosmosADR036 or EIP712 signer for the 32-byte
// secp256k1 scalar sk. hrp is required for CosmosADR036 and ignored otherwise.
// Nonces are RFC 6979, so signatures are deterministic.
func NewSecp256k1Signer(s Scheme, sk []byte, hrp string) (Signer, error) {
	if s != CosmosADR036 && s != EIP712 {
		return nil, ErrScheme
	}
	var k secp256k1.ModNScalar
	if len(sk) != 32 || k.SetByteSlice(sk) || k.IsZero() {
		return nil, fmt.Errorf("principalsig: secp256k1 private key is not a scalar in [1, n-1]")
	}
	if s == CosmosADR036 && !ValidHRP(hrp) {
		return nil, fmt.Errorf("%w: hrp %q", ErrPrincipal, hrp)
	}
	return &secpSigner{scheme: s, sk: secp256k1.NewPrivateKey(&k), hrp: hrp}, nil
}

func (s *secpSigner) Scheme() Scheme { return s.scheme }

// HRP is the bech32 prefix of a CosmosADR036 signer, empty for EIP712.
func (s *secpSigner) HRP() string { return s.hrp }

func (s *secpSigner) Principal() []byte {
	pub := s.sk.PubKey()
	if s.scheme == CosmosADR036 {
		return pub.SerializeCompressed()
	}
	a := ethAddress(pub)
	return a[:]
}

func (s *secpSigner) Sign(m EIP712Message, rendered []byte) ([]byte, error) {
	if s.scheme == CosmosADR036 {
		if !hasHashLine(rendered, m.MandateHash) {
			return nil, fmt.Errorf("principalsig: the text to sign does not end in the mandate hash")
		}
		doc, err := ADR036SignDoc(s.Principal(), s.hrp, rendered)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(doc)
		sig := ecdsa.Sign(s.sk, digest[:])
		r, ss := sig.R(), sig.S()
		var out [64]byte
		r.PutBytesUnchecked(out[:32])
		ss.PutBytesUnchecked(out[32:])
		return out[:], nil
	}
	digest := EIP712Digest(m)
	c := ecdsa.SignCompact(s.sk, digest[:], false)
	return append(append([]byte(nil), c[1:]...), c[0]), nil
}
