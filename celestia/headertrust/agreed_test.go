package headertrust_test

import (
	"context"
	"errors"
	"testing"

	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/verifier"
)

var bg = context.Background()

// named is a source with a host and a latest height.
type named struct {
	*fakeChain
	name      string
	latest    uint64
	latestErr error
}

func (n *named) Name() string { return n.name }

func (n *named) Latest(context.Context) (uint64, error) {
	if n.latestErr != nil {
		return 0, n.latestErr
	}
	return n.latest, nil
}

// identified also reports the node id its status gives.
type identified struct {
	*named
	id    string
	idErr error
}

func (i *identified) NodeID(context.Context) (string, error) { return i.id, i.idErr }

var (
	_ headertrust.NamedChain = (*named)(nil)
	_ headertrust.NamedChain = (*identified)(nil)
)

func hashOfHeader(h core.Header) []byte { return h.Hash() }

func fork(c *chain, from, to uint64) *chain {
	o := buildChain(from, to)
	for h := from; h <= to; h++ {
		hd := o.hdrs[h]
		hd.AppHash = filler("fork", h)
		o.hdrs[h] = hd
	}
	prev := filler("genesis", from)
	for h := from; h <= to; h++ {
		hd := o.hdrs[h]
		hd.LastBlockID.Hash = prev
		o.hdrs[h] = hd
		prev = hd.Hash()
	}
	return o
}

func src(t *testing.T, c *chain, name string, latest uint64) *named {
	t.Helper()
	return &named{fakeChain: c.serve(t, firstHeight, latest), name: name, latest: latest}
}

func withID(n *named, id string) *identified { return &identified{named: n, id: id} }

func TestAgreedCheckpointOneSourceQuorumOne(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	a := src(t, c, "a.example", firstHeight+30)
	cp, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{a}, 1)
	require.NoError(t, err)

	assert.Equal(t, firstHeight+30, cp.Height)
	assert.Equal(t, c.hash(firstHeight+30), cp.Hash)
	assert.Equal(t, c.raw(t, firstHeight+30), cp.Header)
	assert.Equal(t, headertrust.CheckpointReport{
		Height: firstHeight + 30, Hash: c.hash(firstHeight + 30), Sources: []string{"a.example"}, Agreed: 1, Quorum: 1,
	}, rep)

	tr := headertrust.New(cp, c.serve(t, firstHeight, firstHeight+30), nil)
	res, err := tr.Trusted(bg, firstHeight+5, c.hash(firstHeight+5))
	require.NoError(t, err, "the agreed checkpoint anchors a chain walk")
	assert.True(t, res.Checked)
}

func TestAgreedCheckpointIsTheLowestLatestHeight(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	a := src(t, c, "a.example", firstHeight+30)
	b := src(t, c, "b.example", firstHeight+22)
	cp, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{a, b}, 2)
	require.NoError(t, err)
	assert.Equal(t, firstHeight+22, cp.Height, "the highest height every answering source has")
	assert.Equal(t, 2, rep.Agreed)
	assert.Equal(t, 2, rep.Quorum)
	assert.ElementsMatch(t, []string{"a.example", "b.example"}, rep.Sources)
	assert.Equal(t, []uint64{firstHeight + 22}, a.reads)
	assert.Equal(t, []uint64{firstHeight + 22}, b.reads)
}

func TestAgreedCheckpointTooFewAnsweringSourcesIsUnchecked(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	down := errors.New("down")
	tests := []struct {
		name   string
		srcs   func() []headertrust.NamedChain
		quorum int
	}{
		{"the other source is down", func() []headertrust.NamedChain {
			b := src(t, c, "b.example", firstHeight+30)
			b.latestErr = down
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), b}
		}, 2},
		{"the other source cannot serve the header", func() []headertrust.NamedChain {
			b := src(t, c, "b.example", firstHeight+30)
			b.err = down
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), b}
		}, 2},
		{"the other source reports no height", func() []headertrust.NamedChain {
			b := src(t, c, "b.example", 0)
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), b}
		}, 2},
		{"one host twice", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, c, "a.example", firstHeight+30)}
		}, 2},
		{"two host names, one node", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{
				withID(src(t, c, "rpc-1.example", firstHeight+30), "43e9da04"),
				withID(src(t, c, "rpc-2.example", firstHeight+30), "43e9da04"),
			}
		}, 2},
		{"every source is down", func() []headertrust.NamedChain {
			a := src(t, c, "a.example", firstHeight+30)
			a.latestErr = down
			return []headertrust.NamedChain{a}
		}, 1},
		{"the only header is of another height", func() []headertrust.NamedChain {
			a := src(t, c, "a.example", firstHeight+30)
			a.byH[firstHeight+30] = c.raw(t, firstHeight+29)
			return []headertrust.NamedChain{a}
		}, 1},
		{"the only header does not decode", func() []headertrust.NamedChain {
			a := src(t, c, "a.example", firstHeight+30)
			a.byH[firstHeight+30] = []byte{0xff, 0x01}
			return []headertrust.NamedChain{a}
		}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, rep, err := headertrust.AgreedCheckpoint(bg, tc.srcs(), tc.quorum)
			require.ErrorIs(t, err, verifier.ErrTrustInput)
			assert.NotErrorIs(t, err, headertrust.ErrCheckpointDisagree)
			assert.Equal(t, headertrust.Checkpoint{}, cp)
			assert.Less(t, rep.Agreed, tc.quorum)
			assert.Equal(t, tc.quorum, rep.Quorum)
		})
	}
}

func TestAgreedCheckpointCountsDistinctOperatorsOnly(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	t.Run("one host twice at quorum one", func(t *testing.T) {
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{
			src(t, c, "a.example", firstHeight+30), src(t, c, "a.example", firstHeight+30),
		}, 1)
		require.NoError(t, err)
		assert.Equal(t, 1, rep.Agreed)
		assert.Equal(t, []string{"a.example"}, rep.Sources)
	})
	t.Run("one node under two names at quorum one", func(t *testing.T) {
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{
			withID(src(t, c, "rpc-1.example", firstHeight+30), "43e9da04"),
			withID(src(t, c, "rpc-2.example", firstHeight+30), "43e9da04"),
		}, 1)
		require.NoError(t, err)
		assert.Equal(t, 1, rep.Agreed)
		assert.Len(t, rep.Sources, 1)
	})
	t.Run("different nodes pass quorum two", func(t *testing.T) {
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{
			withID(src(t, c, "a.example", firstHeight+30), "aa"),
			withID(src(t, c, "b.example", firstHeight+30), "bb"),
		}, 2)
		require.NoError(t, err)
		assert.Equal(t, 2, rep.Agreed)
	})
	t.Run("sources without a node id count by host", func(t *testing.T) {
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{
			src(t, c, "a.example", firstHeight+30), src(t, c, "b.example", firstHeight+30),
		}, 2)
		require.NoError(t, err)
		assert.Equal(t, 2, rep.Agreed)
	})
	t.Run("an unreadable node id leaves the host rule", func(t *testing.T) {
		b := withID(src(t, c, "b.example", firstHeight+30), "")
		b.idErr = errors.New("status unavailable")
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{
			withID(src(t, c, "a.example", firstHeight+30), "aa"), b,
		}, 2)
		require.NoError(t, err)
		assert.Equal(t, 2, rep.Agreed)
	})
}

func TestAgreedCheckpointAnyDifferingHashFails(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	f := fork(c, firstHeight, firstHeight+31)
	require.NotEqual(t, c.hash(firstHeight+30), f.hash(firstHeight+30))
	tests := []struct {
		name   string
		srcs   func() []headertrust.NamedChain
		quorum int
	}{
		{"two sources, quorum one", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, f, "b.example", firstHeight+30)}
		}, 1},
		{"two sources, quorum two", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, f, "b.example", firstHeight+30)}
		}, 2},
		{"two agree and one differs, quorum two", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{
				src(t, c, "a.example", firstHeight+30), src(t, c, "b.example", firstHeight+30), src(t, f, "c.example", firstHeight+30),
			}
		}, 2},
		{"the same host answers twice with different hashes", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, f, "a.example", firstHeight+30)}
		}, 1},
		{"a node under two names with different hashes", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{
				withID(src(t, c, "a.example", firstHeight+30), "aa"), withID(src(t, f, "b.example", firstHeight+30), "aa"),
			}
		}, 1},
		{"the differing source is ahead and still contradicts", func() []headertrust.NamedChain {
			return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, f, "b.example", firstHeight+31)}
		}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, _, err := headertrust.AgreedCheckpoint(bg, tc.srcs(), tc.quorum)
			require.ErrorIs(t, err, headertrust.ErrCheckpointDisagree)
			assert.NotErrorIs(t, err, verifier.ErrTrustInput, "a contradiction is not a lack of input")
			assert.Equal(t, headertrust.Checkpoint{}, cp)
		})
	}
}

func TestAgreedCheckpointIgnoresASourceThatFailsWhileOthersAnswer(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	down := errors.New("down")
	broken := []struct {
		name string
		mod  func(n *named)
	}{
		{"status down", func(n *named) { n.latestErr = down }},
		{"header down", func(n *named) { n.err = down }},
		{"header of another height", func(n *named) { n.byH[firstHeight+30] = c.raw(t, firstHeight+29) }},
		{"header does not decode", func(n *named) { n.byH[firstHeight+30] = []byte{0xff, 0x01} }},
	}
	for _, tc := range broken {
		t.Run(tc.name, func(t *testing.T) {
			bad := src(t, c, "b.example", firstHeight+30)
			tc.mod(bad)
			_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), bad}, 1)
			require.NoError(t, err)
			assert.Equal(t, 1, rep.Agreed)
			assert.Equal(t, []string{"a.example"}, rep.Sources, "a source that did not answer is not named as agreeing")
		})
	}
}

func TestAgreedCheckpointRefusesBadConfiguration(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	one := func() []headertrust.NamedChain {
		return []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30)}
	}
	tests := []struct {
		name   string
		srcs   []headertrust.NamedChain
		quorum int
	}{
		{"quorum zero", one(), 0},
		{"quorum negative", one(), -1},
		{"no sources", nil, 1},
		{"empty list", []headertrust.NamedChain{}, 1},
		{"a nil source", []headertrust.NamedChain{nil}, 1},
		{"a nil source among others", []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), nil}, 1},
		{"quorum above the number of sources", one(), 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				cp, _, err := headertrust.AgreedCheckpoint(bg, tc.srcs, tc.quorum)
				require.Error(t, err)
				assert.NotErrorIs(t, err, headertrust.ErrCheckpointDisagree)
				assert.Equal(t, headertrust.Checkpoint{}, cp)
			})
		})
	}
	t.Run("zero and negative quorum are not unchecked", func(t *testing.T) {
		for _, q := range []int{0, -3} {
			_, _, err := headertrust.AgreedCheckpoint(bg, one(), q)
			assert.NotErrorIs(t, err, verifier.ErrTrustInput, "a bad flag is the operator's mistake, not missing evidence")
		}
	})
}

func TestAgreedCheckpointStopsOnACancelledContext(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, _, err := headertrust.AgreedCheckpoint(ctx, []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30)}, 1)
	require.ErrorIs(t, err, context.Canceled)
}

func TestAgreedCheckpointDoesNotDrawTheCheckpointFromCrossChecks(t *testing.T) {
	const top = firstHeight + 30
	c := buildChain(firstHeight, top)
	f := fork(c, firstHeight, top)
	cp, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{src(t, c, "a.example", top)}, 1)
	require.NoError(t, err)
	require.Equal(t, 1, rep.Agreed)

	need := firstHeight + 4
	tr := headertrust.New(cp, c.serve(t, firstHeight, top-1), []headertrust.HeaderChain{f.serve(t, firstHeight, top)})
	res, err := tr.Trusted(bg, need, c.hash(need))
	require.ErrorIs(t, err, headertrust.ErrCrossCheckMismatch, "one operator at quorum one, and a cross-check that disagrees: the verdict fails")
	assert.Equal(t, "mismatch", res.CrossCheck)
	assert.Equal(t, top, res.CheckpointH)
}

func TestPreferServesKnownHeadersFirst(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+10)
	online := c.serve(t, firstHeight, firstHeight+10)
	known := map[uint64][]byte{firstHeight + 3: c.raw(t, firstHeight+3)}
	p := headertrust.Prefer(known, online)

	got, err := p.Header(bg, firstHeight+3)
	require.NoError(t, err)
	assert.Equal(t, c.raw(t, firstHeight+3), got)
	assert.Empty(t, online.reads, "a known header is not fetched")

	got, err = p.Header(bg, firstHeight+4)
	require.NoError(t, err)
	assert.Equal(t, c.raw(t, firstHeight+4), got)
	assert.Equal(t, []uint64{firstHeight + 4}, online.reads)

	got[0] ^= 0xff
	got, err = p.Header(bg, firstHeight+3)
	require.NoError(t, err)
	assert.Equal(t, c.raw(t, firstHeight+3), got, "callers cannot change what is served")
	known[firstHeight+3][0] ^= 0xff
	got, err = p.Header(bg, firstHeight+3)
	require.NoError(t, err)
	assert.Equal(t, c.raw(t, firstHeight+3), got, "nor can a later change of the map")
}

func TestPreferWithNothingKnownIsTheChain(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+5)
	for _, known := range []map[uint64][]byte{nil, {}} {
		p := headertrust.Prefer(known, c.serve(t, firstHeight, firstHeight+5))
		got, err := p.Header(bg, firstHeight+2)
		require.NoError(t, err)
		assert.Equal(t, c.raw(t, firstHeight+2), got)
		_, err = p.Header(bg, firstHeight+50)
		assert.Error(t, err)
	}
}

func TestPreferAttributesABrokenLinkToItsSource(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	need := firstHeight + 2
	ctx := bg

	t.Run("an archived header that links passes", func(t *testing.T) {
		online := c.serve(t, firstHeight, top-1)
		p := headertrust.Prefer(map[uint64][]byte{need: c.raw(t, need)}, online)
		res, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.NoError(t, err)
		assert.True(t, res.Checked)
		assert.NotContains(t, online.reads, need)
	})
	t.Run("an archived header that does not link fails", func(t *testing.T) {
		f := forged(c, need)
		p := headertrust.Prefer(map[uint64][]byte{need: encode(t, f)}, c.serve(t, firstHeight, top-1))
		res, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, f.Hash())
		require.ErrorIs(t, err, headertrust.ErrChainBroken, "the archive presents a header the chain does not have")
		assert.NotErrorIs(t, err, verifier.ErrTrustInput)
		assert.False(t, res.Checked)
	})
	t.Run("an archived header that does not link, whatever the online source serves", func(t *testing.T) {
		f := forged(c, need)
		online := c.serve(t, firstHeight, top-1)
		p := headertrust.Prefer(map[uint64][]byte{need: encode(t, f)}, online)
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, f.Hash())
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.NotContains(t, online.reads, need, "the real header is never consulted to excuse the archive")
	})
	t.Run("an archived header at an intermediate height that does not link fails", func(t *testing.T) {
		mid := firstHeight + 6
		p := headertrust.Prefer(map[uint64][]byte{mid: encode(t, forged(c, mid))}, c.serve(t, firstHeight, top-1))
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.NotErrorIs(t, err, verifier.ErrTrustInput)
	})
	t.Run("an online header that does not link is that source's fault", func(t *testing.T) {
		online := c.serve(t, firstHeight, top-1)
		online.byH[firstHeight+5] = encode(t, forged(c, firstHeight+5))
		p := headertrust.Prefer(nil, online)
		res, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, verifier.ErrTrustInput)
		assert.False(t, res.Checked)
		assert.Equal(t, top, res.CheckpointH)
	})
	t.Run("an online header of another height is that source's fault", func(t *testing.T) {
		online := c.serve(t, firstHeight, top-1)
		online.byH[firstHeight+4] = online.byH[firstHeight+5]
		p := headertrust.Prefer(nil, online)
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, verifier.ErrTrustInput)
	})
	t.Run("an online header that does not decode is that source's fault", func(t *testing.T) {
		online := c.serve(t, firstHeight, top-1)
		online.byH[firstHeight+4] = []byte{0xff, 0xff}
		p := headertrust.Prefer(nil, online)
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, verifier.ErrTrustInput)
	})
	t.Run("a real online chain and a claimed hash that is not the chain's still fails", func(t *testing.T) {
		p := headertrust.Prefer(nil, c.serve(t, firstHeight, top-1))
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, hashOfHeader(forged(c, need)))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.NotErrorIs(t, err, verifier.ErrTrustInput, "the claim came from the archive, not from the online source")
	})
	t.Run("a plain chain keeps failing", func(t *testing.T) {
		online := c.serve(t, firstHeight, top-1)
		online.byH[firstHeight+5] = encode(t, forged(c, firstHeight+5))
		_, err := headertrust.New(c.checkpoint(t, top), online, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrChainBroken, "headers the auditor supplied are not a source's fault")
	})
	t.Run("an unreachable online source is unchecked", func(t *testing.T) {
		p := headertrust.Prefer(nil, &fakeChain{t: t, err: errors.New("down")})
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		require.ErrorIs(t, err, verifier.ErrTrustInput)
	})
}
