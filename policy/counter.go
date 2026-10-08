package policy

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// MaxScales bounds the scale map of a counter cell, the strict decoder's
// per-map limit, so the gate never writes a cell it cannot read back.
const MaxScales = 1024

func hashRaw(b []byte) commitment.Hash { return sha256.Sum256(b) }

// Counter is the value of a registry cell: the mandate in force, the chain
// head and the ledger. A cell lives under the mandate's counter key and is
// never pruned.
//
// Scales holds the scale of every asset any adopted version of the mandate
// listed. It is gate-local: it is not part of the state, the state hash or
// any verdict.
type Counter struct {
	Format         uint64            `cbor:"1,keyasint"`
	MandateID      []byte            `cbor:"2,keyasint"`
	Version        uint64            `cbor:"3,keyasint"`
	MandateHash    []byte            `cbor:"4,keyasint"`
	HeadCommitment []byte            `cbor:"5,keyasint,omitempty"`
	HeadVerdict    []byte            `cbor:"6,keyasint,omitempty"`
	Ledger         Ledger            `cbor:"7,keyasint"`
	Scales         map[string]uint64 `cbor:"8,keyasint"`
}

func (c *Counter) Validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrCounterInvalid, fmt.Sprintf(f, a...)) }
	if c.Format != 1 || len(c.MandateID) != 16 || c.Version < 1 || c.Version > maxInt {
		return bad("header")
	}
	if err := checkHash(c.MandateHash, "mandate_hash"); err != nil {
		return bad("%v", err)
	}
	if len(c.Scales) == 0 {
		return bad("no asset scales")
	}
	if len(c.Scales) > MaxScales {
		return bad("more than %d asset scales", MaxScales)
	}
	for a, sc := range c.Scales {
		if !isPrintable(a, 1, 128) || sc > 255 {
			return bad("scale of an asset")
		}
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
	c := &Counter{Format: 1, MandateID: bytes.Clone(m.MandateID), Version: m.Version, MandateHash: bytes.Clone(mandateHash[:]), Ledger: GenesisLedger()}
	c.Scales = map[string]uint64{}
	for _, a := range m.Assets {
		c.Scales[a.Asset] = a.Scale
	}
	return c
}

// Adopt switches the counter to a later version of its mandate. The new
// version must give every asset the counter has ever listed the same scale,
// whether or not the asset was spent or an intermediate version dropped it.
// A union of more than MaxScales assets is refused with ErrScalesFull. On
// either error the counter is unchanged.
func (c *Counter) Adopt(m *Mandate, mandateHash commitment.Hash) error {
	for _, a := range m.Assets {
		if old, ok := c.Scales[a.Asset]; ok && old != a.Scale {
			return fmt.Errorf("%w: %s has scale %d in the counter, %d in the mandate", ErrScaleChanged, a.Asset, old, a.Scale)
		}
	}
	scales := make(map[string]uint64, len(c.Scales)+len(m.Assets))
	for a, sc := range c.Scales {
		scales[a] = sc
	}
	for _, a := range m.Assets {
		scales[a.Asset] = a.Scale
	}
	if len(scales) > MaxScales {
		return fmt.Errorf("%w: %d assets, at most %d", ErrScalesFull, len(scales), MaxScales)
	}
	c.Version, c.MandateHash, c.Scales = m.Version, bytes.Clone(mandateHash[:]), scales
	return nil
}
