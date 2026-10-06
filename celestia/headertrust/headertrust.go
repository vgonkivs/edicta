// Package headertrust ties header hashes to the chain from one trusted
// header, without validator signatures: the hash chain from the trusted
// header down to the needed height is checked link by link, so the headers
// in between may come from any untrusted source.
package headertrust

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/verifier"
)

var (
	ErrCheckpointTooLow   = errors.New("headertrust: checkpoint is below the needed height")
	ErrCheckpointMismatch = errors.New("headertrust: checkpoint header does not match its hash or height")
	ErrChainBroken        = errors.New("headertrust: header chain does not link to the trusted header")
	ErrCrossCheckMismatch = errors.New("headertrust: another node serves a different header")
	ErrChainTooLong       = errors.New("headertrust: needed height is too far below the checkpoint")
)

// MaxChainLength bounds how many headers one check fetches. The needed
// height comes from a signed decision, so it is not trusted to be near the
// checkpoint.
const MaxChainLength = 100_000

// Checkpoint is the trusted header, obtained out of band. Header is the
// protobuf tendermint.types.Header.
type Checkpoint struct {
	Height uint64
	Hash   []byte
	Header []byte
}

// HeaderChain serves protobuf headers by height. It is untrusted: every
// header from it is checked against the chain.
type HeaderChain interface {
	Header(ctx context.Context, height uint64) ([]byte, error)
}

// decode parses a protobuf header and requires the encoding to be the
// canonical one, so equal hashes mean equal bytes.
func decode(b []byte) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	if again, err := ph.Marshal(); err != nil || !bytes.Equal(again, b) {
		return core.Header{}, errors.New("header encoding is not canonical")
	}
	h, err := core.HeaderFromProto(&ph)
	if err != nil {
		return core.Header{}, err
	}
	if h.Height < 1 {
		return core.Header{}, fmt.Errorf("header height %d", h.Height)
	}
	return h, nil
}

// hashOf is the block hash of h. It is never empty.
func hashOf(h core.Header) ([]byte, error) {
	sum := h.Hash()
	if len(sum) != 32 {
		return nil, errors.New("header has no hash")
	}
	return sum, nil
}

// VerifyBackwards checks that hash is the hash of the header at height, given
// the trusted header cp and the encoded headers height .. cp.Height-1 in
// ascending order: each header's hash must equal the last_block_id hash of
// its successor. No signature is checked.
func VerifyBackwards(cp Checkpoint, headers [][]byte, height uint64, hash []byte) error {
	if cp.Height < height {
		return fmt.Errorf("%w: checkpoint %d, needed %d", ErrCheckpointTooLow, cp.Height, height)
	}
	top, err := decode(cp.Header)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCheckpointMismatch, err)
	}
	topHash, err := hashOf(top)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCheckpointMismatch, err)
	}
	if uint64(top.Height) != cp.Height || !bytes.Equal(topHash, cp.Hash) {
		return fmt.Errorf("%w: height %d", ErrCheckpointMismatch, cp.Height)
	}
	if uint64(len(headers)) != cp.Height-height {
		return fmt.Errorf("%w: %d headers for %d links", ErrChainBroken, len(headers), cp.Height-height)
	}

	want := top.LastBlockID.Hash
	got := topHash
	for i := len(headers) - 1; i >= 0; i-- {
		h, err := decode(headers[i])
		if err != nil {
			return fmt.Errorf("%w: header %d: %w", ErrChainBroken, height+uint64(i), err)
		}
		if uint64(h.Height) != height+uint64(i) {
			return fmt.Errorf("%w: header %d claims height %d", ErrChainBroken, height+uint64(i), h.Height)
		}
		sum, err := hashOf(h)
		if err != nil {
			return fmt.Errorf("%w: header %d: %w", ErrChainBroken, height+uint64(i), err)
		}
		if !bytes.Equal(sum, want) {
			return fmt.Errorf("%w: header %d does not match the link from %d", ErrChainBroken, height+uint64(i), height+uint64(i)+1)
		}
		want, got = h.LastBlockID.Hash, sum
	}
	if !bytes.Equal(got, hash) {
		return fmt.Errorf("%w: hash at height %d differs from the chain's", ErrChainBroken, height)
	}
	return nil
}

type trust struct {
	cp    Checkpoint
	chain HeaderChain
	cross []HeaderChain
}

// New returns a header trust anchored at cp. chain supplies the headers
// between the needed height and cp; cross, if any, are independent nodes
// whose header at the needed height is compared.
func New(cp Checkpoint, chain HeaderChain, cross []HeaderChain) verifier.HeaderTrust {
	return &trust{cp: cp, chain: chain, cross: cross}
}

func (t *trust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	if err := ctx.Err(); err != nil {
		return verifier.TrustResult{}, fmt.Errorf("headertrust: %w", err)
	}
	if t.cp.Height < height {
		return verifier.TrustResult{}, fmt.Errorf("%w: checkpoint %d, needed %d", ErrCheckpointTooLow, t.cp.Height, height)
	}
	if t.cp.Height-height > MaxChainLength {
		return verifier.TrustResult{}, fmt.Errorf("%w: %d links", ErrChainTooLong, t.cp.Height-height)
	}
	headers := make([][]byte, 0, t.cp.Height-height)
	for h := height; h < t.cp.Height; h++ {
		b, err := t.chain.Header(ctx, h)
		if err != nil {
			return verifier.TrustResult{}, fmt.Errorf("headertrust: header %d: %w", h, err)
		}
		headers = append(headers, b)
	}
	if err := VerifyBackwards(t.cp, headers, height, hash); err != nil {
		return verifier.TrustResult{}, err
	}
	res := verifier.TrustResult{
		Checked:        true,
		CheckpointH:    t.cp.Height,
		CheckpointHash: bytes.Clone(t.cp.Hash),
		CrossCheck:     "off",
	}
	if len(t.cross) == 0 {
		return res, nil
	}
	res.CrossCheck = t.crossCheck(ctx, height, hash)
	if res.CrossCheck == "mismatch" {
		return res, fmt.Errorf("%w: height %d", ErrCrossCheckMismatch, height)
	}
	return res, nil
}

// crossCheck asks every node. A node that cannot answer, or answers for
// another height, counts as unavailable; any node with another hash is a
// mismatch whatever the others say.
func (t *trust) crossCheck(ctx context.Context, height uint64, hash []byte) string {
	result := "pass"
	for _, c := range t.cross {
		b, err := c.Header(ctx, height)
		if err != nil {
			result = worse(result, "unavailable")
			continue
		}
		h, err := decode(b)
		if err != nil || uint64(h.Height) != height {
			result = worse(result, "unavailable")
			continue
		}
		sum, err := hashOf(h)
		if err != nil {
			result = worse(result, "unavailable")
			continue
		}
		if !bytes.Equal(sum, hash) {
			return "mismatch"
		}
	}
	return result
}

func worse(a, b string) string {
	if a == "pass" {
		return b
	}
	return a
}
