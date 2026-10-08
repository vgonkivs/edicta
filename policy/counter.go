package policy

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

func hashRaw(b []byte) commitment.Hash { return sha256.Sum256(b) }

// Counter is the value of a registry cell: the mandate in force, the chain
// head and the ledger. A cell lives under the mandate's counter key and is
// never pruned.
type Counter struct {
	Format         uint64 `cbor:"1,keyasint"`
	MandateID      []byte `cbor:"2,keyasint"`
	Version        uint64 `cbor:"3,keyasint"`
	MandateHash    []byte `cbor:"4,keyasint"`
	HeadCommitment []byte `cbor:"5,keyasint,omitempty"`
	HeadVerdict    []byte `cbor:"6,keyasint,omitempty"`
	Ledger         Ledger `cbor:"7,keyasint"`
}

func (c *Counter) Validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrCounterInvalid, fmt.Sprintf(f, a...)) }
	if c.Format != 1 || len(c.MandateID) != 16 || c.Version < 1 || c.Version > maxInt {
		return bad("header")
	}
	if err := checkHash(c.MandateHash, "mandate_hash"); err != nil {
		return bad("%v", err)
	}
	linked := c.Ledger.State.Seq >= 1
	if linked != (len(c.HeadCommitment) == 32) || linked != (len(c.HeadVerdict) == 32) {
		return bad("chain head and seq disagree")
	}
	if err := c.Ledger.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrCounterInvalid, err)
	}
	return nil
}

func EncodeCounter(c *Counter) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return marshal(c)
}

func DecodeCounter(b []byte) (*Counter, error) {
	var c Counter
	if err := decodeStrict(b, maxCounterSize, &c, ErrCounterInvalid); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(&c) }, ErrCounterInvalid); err != nil {
		return nil, err
	}
	return &c, nil
}

// NewCounter is the genesis cell of a mandate.
func NewCounter(m *Mandate, mandateHash commitment.Hash) *Counter {
	return &Counter{Format: 1, MandateID: bytes.Clone(m.MandateID), Version: m.Version, MandateHash: mandateHash[:], Ledger: GenesisLedger()}
}
