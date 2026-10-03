package commitment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"filippo.io/edwards25519"
)

// tagged builds tag(t) || parts, where tag(t) is one length byte then ASCII.
func tagged(tag string, parts ...[]byte) []byte {
	out := append([]byte{byte(len(tag))}, tag...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// HashCanonical hashes canonical commitment bytes under the domain tag.
func HashCanonical(canon []byte) Hash {
	return sha256.Sum256(tagged(TagCommitment, canon))
}

func HashOf(c *Commitment) (Hash, error) {
	canon, err := Encode(c)
	if err != nil {
		return Hash{}, err
	}
	return HashCanonical(canon), nil
}

// SigningMessage is the exact 45 bytes that get signed (spec 5, G1).
func SigningMessage(h Hash) []byte {
	return tagged(TagSig, h[:])
}

func Sign(priv ed25519.PrivateKey, c *Commitment) (*SignedCommitment, Hash, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, Hash{}, fmt.Errorf("commitment: private key has %d bytes", len(priv))
	}
	if c == nil {
		return nil, Hash{}, errNilCommitment
	}
	if pub, ok := priv.Public().(ed25519.PublicKey); !ok || !bytes.Equal(pub, c.AgentPubKey) {
		return nil, Hash{}, fmt.Errorf("%w: private key does not match agent_pubkey", ErrInvalidPublicKey)
	}
	h, err := HashOf(c)
	if err != nil {
		return nil, Hash{}, err
	}
	sig := ed25519.Sign(priv, SigningMessage(h))
	return &SignedCommitment{Commitment: cloneCommitment(c), Signature: sig}, h, nil
}

// checkPublicKey is rule G0. crypto/ed25519 accepts small-order and
// non-canonical keys, which allows universal forgeries (spec 5).
func checkPublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %d bytes", ErrInvalidPublicKey, len(pub))
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	// SetBytes tolerates y >= p and x = 0 with the sign bit; RFC 8032 does not.
	if !bytes.Equal(p.Bytes(), pub) {
		return fmt.Errorf("%w: non-canonical encoding", ErrInvalidPublicKey)
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return fmt.Errorf("%w: small order", ErrInvalidPublicKey)
	}
	return nil
}

// Verify checks the signature over the signing message with agent_pubkey.
// It is meaningful only for DecodeSigned output; it does not re-run schema
// validation. VerifyForGate is the normative pipeline.
// ed25519.Verify rejects a non-canonical S (G2).
func Verify(s *SignedCommitment) (Hash, error) {
	if s == nil {
		return Hash{}, fmt.Errorf("%w: nil envelope", ErrSignatureInvalid)
	}
	h, err := HashOf(&s.Commitment)
	if err != nil {
		return Hash{}, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	pub := s.Commitment.AgentPubKey
	if err := checkPublicKey(pub); err != nil {
		return Hash{}, err
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return Hash{}, fmt.Errorf("%w: signature size", ErrSignatureInvalid)
	}
	if !ed25519.Verify(pub, SigningMessage(h), s.Signature) {
		return Hash{}, ErrSignatureInvalid
	}
	return h, nil
}

func cloneCommitment(c *Commitment) Commitment {
	out := *c
	out.AgentPubKey = bytes.Clone(c.AgentPubKey)
	out.Nonce = bytes.Clone(c.Nonce)
	out.PayloadRef.Namespace = bytes.Clone(c.PayloadRef.Namespace)
	out.PayloadRef.Commitment = bytes.Clone(c.PayloadRef.Commitment)
	out.PayloadRef.Signer = bytes.Clone(c.PayloadRef.Signer)
	out.CiphertextHash = bytes.Clone(c.CiphertextHash)
	out.PlaintextHash = bytes.Clone(c.PlaintextHash)
	if c.Scope.ChainID != nil {
		v := *c.Scope.ChainID
		out.Scope.ChainID = &v
	}
	if c.Action.IBKROrder != nil {
		o := *c.Action.IBKROrder
		out.Action.IBKROrder = &o
	}
	return out
}
