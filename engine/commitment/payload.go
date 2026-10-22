package commitment

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// CheckPayload compares size first, which is cheap, then the hash.
func CheckPayload(c *Commitment, blob []byte) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrPayloadSizeMismatch)
	}
	if uint64(len(blob)) != c.PayloadSize {
		return fmt.Errorf("%w: got %d bytes, committed %d", ErrPayloadSizeMismatch, len(blob), c.PayloadSize)
	}
	sum := sha256.Sum256(blob)
	if subtle.ConstantTimeCompare(sum[:], c.CiphertextHash) != 1 {
		return ErrPayloadHashMismatch
	}
	return nil
}

// PlaintextHash is H(salt || plaintext), deliberately without a domain tag.
func PlaintextHash(salt [32]byte, plaintext []byte) Hash {
	h := sha256.New()
	h.Write(salt[:])
	h.Write(plaintext)
	var out Hash
	h.Sum(out[:0])
	return out
}
