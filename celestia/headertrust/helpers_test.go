package headertrust_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
)

const firstHeight = uint64(100)

// chain is a linked run of headers: every header carries the hash of its
// predecessor in last_block_id.
type chain struct {
	hdrs map[uint64]core.Header
}

func filler(tag string, h uint64) []byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", tag, h)))
	return s[:]
}

func mkHeader(h uint64, prev []byte, app string) core.Header {
	return core.Header{
		Version:            cmtversion.Consensus{Block: 11, App: 6},
		ChainID:            "test-1",
		Height:             int64(h),
		Time:               time.Unix(1_790_000_000+int64(h)*3, 0).UTC(),
		LastBlockID:        core.BlockID{Hash: prev, PartSetHeader: core.PartSetHeader{Total: 1, Hash: filler("psh", h)}},
		LastCommitHash:     filler("lc", h),
		DataHash:           filler("data", h),
		ValidatorsHash:     filler("vals", 0),
		NextValidatorsHash: filler("vals", 0),
		ConsensusHash:      filler("cons", 0),
		AppHash:            filler(app, h),
		LastResultsHash:    filler("res", h),
		EvidenceHash:       filler("ev", 0),
		ProposerAddress:    filler("prop", 0)[:20],
	}
}

func buildChain(from, to uint64) *chain {
	c := &chain{hdrs: map[uint64]core.Header{}}
	prev := filler("genesis", from)
	for h := from; h <= to; h++ {
		hd := mkHeader(h, prev, "app")
		c.hdrs[h] = hd
		prev = hd.Hash()
	}
	return c
}

func (c *chain) hash(h uint64) []byte {
	hd := c.hdrs[h]
	return hd.Hash()
}

func encode(t testing.TB, h core.Header) []byte {
	t.Helper()
	p := h.ToProto()
	b, err := p.Marshal()
	require.NoError(t, err)
	return b
}

func (c *chain) raw(t testing.TB, h uint64) []byte {
	t.Helper()
	hd, ok := c.hdrs[h]
	require.True(t, ok)
	return encode(t, hd)
}

// run returns the encoded headers from..to inclusive.
func (c *chain) run(t testing.TB, from, to uint64) [][]byte {
	t.Helper()
	var out [][]byte
	for h := from; h <= to; h++ {
		out = append(out, c.raw(t, h))
	}
	return out
}

func (c *chain) checkpoint(t testing.TB, h uint64) headertrust.Checkpoint {
	t.Helper()
	return headertrust.Checkpoint{Height: h, Hash: c.hash(h), Header: c.raw(t, h)}
}

// forged is a header at the same height with different content, as an
// untrusted source could serve in place of the real one.
func forged(c *chain, h uint64) core.Header {
	hd := c.hdrs[h]
	return mkHeader(h, hd.LastBlockID.Hash, "forged")
}

// fakeChain serves encoded headers by height and counts reads.
type fakeChain struct {
	t     testing.TB
	byH   map[uint64][]byte
	err   error
	reads []uint64
}

func (f *fakeChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.reads = append(f.reads, h)
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.byH[h]
	if !ok {
		return nil, fmt.Errorf("fake chain: no header at %d", h)
	}
	return bytes.Clone(b), nil
}

func (c *chain) serve(t testing.TB, from, to uint64) *fakeChain {
	t.Helper()
	f := &fakeChain{t: t, byH: map[uint64][]byte{}}
	for h := from; h <= to; h++ {
		f.byH[h] = c.raw(t, h)
	}
	return f
}
