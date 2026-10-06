package headertrust_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/verifier"
)

func TestVerifyBackwardsAccepts(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+20)
	tests := []struct {
		name         string
		cp           uint64
		height       uint64
		headersUpTo  uint64
		wantHeaders  int
		expectedHash []byte
	}{
		{"checkpoint ten above", firstHeight + 10, firstHeight, firstHeight + 9, 10, c.hash(firstHeight)},
		{"checkpoint one above", firstHeight + 1, firstHeight, firstHeight, 1, c.hash(firstHeight)},
		{"checkpoint at the needed height", firstHeight + 5, firstHeight + 5, 0, 0, c.hash(firstHeight + 5)},
		{"needed height in the middle", firstHeight + 20, firstHeight + 7, firstHeight + 19, 13, c.hash(firstHeight + 7)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hs [][]byte
			if tc.wantHeaders > 0 {
				hs = c.run(t, tc.height, tc.headersUpTo)
			}
			require.Len(t, hs, tc.wantHeaders)
			require.NoError(t, headertrust.VerifyBackwards(c.checkpoint(t, tc.cp), hs, tc.height, tc.expectedHash))
		})
	}
}

func TestVerifyBackwardsCheckpointBelowTheNeededHeight(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+20)
	cp := c.checkpoint(t, firstHeight+5)
	err := headertrust.VerifyBackwards(cp, nil, firstHeight+6, c.hash(firstHeight+6))
	require.ErrorIs(t, err, headertrust.ErrCheckpointTooLow)
	assert.NotErrorIs(t, err, headertrust.ErrChainBroken)
}

func TestVerifyBackwardsRefusesBrokenChains(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	good := func() [][]byte { return c.run(t, firstHeight, top-1) }

	t.Run("header substituted at every height", func(t *testing.T) {
		for h := firstHeight; h < top; h++ {
			hs := good()
			hs[h-firstHeight] = encode(t, forged(c, h))
			err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
			require.ErrorIsf(t, err, headertrust.ErrChainBroken, "substituted at %d", h)
		}
	})
	t.Run("substituted header with a repaired link to its successor", func(t *testing.T) {
		hs := good()
		f := forged(c, firstHeight+3)
		hs[3] = encode(t, f)
		// the attacker rewrites the successor so that the link matches
		next := c.hdrs[firstHeight+4]
		next.LastBlockID.Hash = f.Hash()
		hs[4] = encode(t, next)
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken, "the repair moves the break one link up")
	})
	t.Run("reordered links", func(t *testing.T) {
		hs := good()
		hs[3], hs[4] = hs[4], hs[3]
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("missing link", func(t *testing.T) {
		hs := good()
		hs = append(hs[:4], hs[5:]...)
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("extra link", func(t *testing.T) {
		hs := append(good(), c.raw(t, top))
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("no links at all", func(t *testing.T) {
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), nil, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("hash of the needed height differs", func(t *testing.T) {
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), good(), firstHeight, c.hash(firstHeight+1))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("hash of the needed height is empty", func(t *testing.T) {
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), good(), firstHeight, nil)
		require.Error(t, err)
	})
	t.Run("malformed header", func(t *testing.T) {
		hs := good()
		hs[2] = []byte{0xff, 0xff, 0xff}
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.Error(t, err)
	})
	t.Run("header of another height in place", func(t *testing.T) {
		other := buildChain(firstHeight+500, firstHeight+510)
		hs := good()
		hs[2] = other.raw(t, firstHeight+502)
		err := headertrust.VerifyBackwards(c.checkpoint(t, top), hs, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
}

func TestVerifyBackwardsRefusesAForgedCheckpoint(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)

	t.Run("header differs from the hash in the file", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Header = encode(t, forged(c, top))
		err := headertrust.VerifyBackwards(cp, c.run(t, firstHeight, top-1), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrCheckpointMismatch)
	})
	t.Run("hash in the file differs from the header", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Hash = c.hash(top - 1)
		err := headertrust.VerifyBackwards(cp, c.run(t, firstHeight, top-1), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrCheckpointMismatch)
	})
	t.Run("file height differs from the header height", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Height = top + 1
		err := headertrust.VerifyBackwards(cp, c.run(t, firstHeight, top), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrCheckpointMismatch)
	})
	t.Run("forged chain under a forged checkpoint still needs the real hash", func(t *testing.T) {
		fc := buildChain(firstHeight, top)
		for h := firstHeight; h <= top; h++ {
			hd := fc.hdrs[h]
			hd.AppHash = filler("other", h)
			fc.hdrs[h] = hd
		}
		// relink: a fully consistent but different history
		prev := filler("genesis", firstHeight)
		for h := firstHeight; h <= top; h++ {
			hd := fc.hdrs[h]
			hd.LastBlockID.Hash = prev
			fc.hdrs[h] = hd
			prev = hd.Hash()
		}
		cp := c.checkpoint(t, top)
		err := headertrust.VerifyBackwards(cp, fc.run(t, firstHeight, top-1), firstHeight, fc.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken, "the real checkpoint does not link to the other history")
	})
}

func FuzzVerifyBackwards(f *testing.F) {
	c := buildChain(firstHeight, firstHeight+4)
	var enc [][]byte
	for h := firstHeight; h < firstHeight+4; h++ {
		enc = append(enc, c.raw(f, h))
	}
	f.Add(enc[0], enc[1], enc[2], enc[3], c.hash(firstHeight))
	f.Add([]byte{}, []byte{1}, []byte{0xff}, []byte("x"), []byte{})
	cp := c.checkpoint(f, firstHeight+4)
	f.Fuzz(func(t *testing.T, a, b, d, e, hash []byte) {
		err := headertrust.VerifyBackwards(cp, [][]byte{a, b, d, e}, firstHeight, hash)
		if err == nil {
			assert.Equal(t, enc, [][]byte{a, b, d, e}, "only the real chain is accepted")
		}
	})
}

func TestTrustedOffline(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	tr := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), nil)

	res, err := tr.Trusted(context.Background(), firstHeight+2, c.hash(firstHeight+2))
	require.NoError(t, err)
	assert.True(t, res.Checked)
	assert.Equal(t, top, res.CheckpointH)
	assert.Equal(t, c.hash(top), res.CheckpointHash)
	assert.Equal(t, "off", res.CrossCheck)
}

func TestTrustedAtTheCheckpointNeedsNoChain(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	chain := &fakeChain{t: t, byH: map[uint64][]byte{}}
	tr := headertrust.New(c.checkpoint(t, top), chain, nil)

	res, err := tr.Trusted(context.Background(), top, c.hash(top))
	require.NoError(t, err)
	assert.True(t, res.Checked)
	assert.Empty(t, chain.reads)
}

func TestTrustedFailures(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)

	t.Run("checkpoint below the needed height", func(t *testing.T) {
		tr := headertrust.New(c.checkpoint(t, firstHeight+3), c.serve(t, firstHeight, top), nil)
		res, err := tr.Trusted(context.Background(), firstHeight+4, c.hash(firstHeight+4))
		require.ErrorIs(t, err, headertrust.ErrCheckpointTooLow)
		assert.False(t, res.Checked)
	})
	t.Run("source substitutes a header", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		src.byH[firstHeight+4] = encode(t, forged(c, firstHeight+4))
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		res, err := tr.Trusted(context.Background(), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.False(t, res.Checked)
	})
	t.Run("the claimed hash is not the chain's", func(t *testing.T) {
		tr := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), nil)
		res, err := tr.Trusted(context.Background(), firstHeight, c.hash(firstHeight+1))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.False(t, res.Checked)
	})
	t.Run("source cannot serve a header", func(t *testing.T) {
		boom := errors.New("node unreachable")
		src := &fakeChain{t: t, err: boom}
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		res, err := tr.Trusted(context.Background(), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, boom)
		assert.NotErrorIs(t, err, headertrust.ErrChainBroken)
		assert.False(t, res.Checked)
	})
	t.Run("source serves another height", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		src.byH[firstHeight+2] = src.byH[firstHeight+3]
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		_, err := tr.Trusted(context.Background(), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		tr := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), nil)
		_, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("forged checkpoint", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Header = encode(t, forged(c, top))
		tr := headertrust.New(cp, c.serve(t, firstHeight, top-1), nil)
		res, err := tr.Trusted(context.Background(), firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrCheckpointMismatch)
		assert.False(t, res.Checked)
	})
}

func TestCrossCheck(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	other := buildChain(firstHeight, top)
	for h := firstHeight; h <= top; h++ {
		hd := other.hdrs[h]
		hd.AppHash = filler("fork", h)
		other.hdrs[h] = hd
	}
	need := firstHeight + 2
	mk := func(cross ...headertrust.HeaderChain) verifier.HeaderTrust {
		return headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), cross)
	}

	t.Run("agreeing node passes", func(t *testing.T) {
		tr := mk(c.serve(t, firstHeight, top))
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.NoError(t, err)
		assert.Equal(t, "pass", res.CrossCheck)
		assert.True(t, res.Checked)
	})
	t.Run("two agreeing nodes pass", func(t *testing.T) {
		tr := mk(c.serve(t, firstHeight, top), c.serve(t, firstHeight, top))
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.NoError(t, err)
		assert.Equal(t, "pass", res.CrossCheck)
	})
	t.Run("a node with another header fails", func(t *testing.T) {
		tr := mk(other.serve(t, firstHeight, top))
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrCrossCheckMismatch)
		assert.Equal(t, "mismatch", res.CrossCheck)
	})
	t.Run("one honest and one disagreeing node fails", func(t *testing.T) {
		tr := mk(c.serve(t, firstHeight, top), other.serve(t, firstHeight, top))
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrCrossCheckMismatch)
		assert.Equal(t, "mismatch", res.CrossCheck)
	})
	t.Run("a mismatch is not hidden by an unreachable node", func(t *testing.T) {
		down := &fakeChain{t: t, err: errors.New("down")}
		tr := mk(down, other.serve(t, firstHeight, top))
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrCrossCheckMismatch)
		assert.Equal(t, "mismatch", res.CrossCheck)
	})
	t.Run("unreachable node is reported and does not fail", func(t *testing.T) {
		down := &fakeChain{t: t, err: errors.New("down")}
		tr := mk(down)
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.NoError(t, err)
		assert.True(t, res.Checked)
		assert.Equal(t, "unavailable", res.CrossCheck)
	})
	t.Run("a node that lacks the header is unavailable", func(t *testing.T) {
		tr := mk(&fakeChain{t: t, byH: map[uint64][]byte{}})
		res, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.NoError(t, err)
		assert.Equal(t, "unavailable", res.CrossCheck)
	})
	t.Run("cross-check does not rescue a broken chain", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		src.byH[firstHeight+5] = encode(t, forged(c, firstHeight+5))
		tr := headertrust.New(c.checkpoint(t, top), src, []headertrust.HeaderChain{c.serve(t, firstHeight, top)})
		_, err := tr.Trusted(context.Background(), need, c.hash(need))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
}

func TestTrustedSeparatesAuditorInputProblemsFromForgery(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	ctx := context.Background()

	t.Run("input problems wrap the verifier sentinel and report the checkpoint", func(t *testing.T) {
		boom := errors.New("node unreachable")
		tooLong := headertrust.Checkpoint{Height: firstHeight + headertrust.MaxChainLength + 1, Hash: c.hash(top)}
		tests := []struct {
			name string
			tr   verifier.HeaderTrust
			cp   headertrust.Checkpoint
			at   uint64
			want error
		}{
			{"checkpoint too low", headertrust.New(c.checkpoint(t, firstHeight+3), c.serve(t, firstHeight, top), nil), c.checkpoint(t, firstHeight+3), firstHeight + 4, headertrust.ErrCheckpointTooLow},
			{"chain too long", headertrust.New(tooLong, c.serve(t, firstHeight, top), nil), tooLong, firstHeight, headertrust.ErrChainTooLong},
			{"headers not available", headertrust.New(c.checkpoint(t, top), &fakeChain{t: t, err: boom}, nil), c.checkpoint(t, top), firstHeight + 4, boom},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				res, err := tc.tr.Trusted(ctx, tc.at, c.hash(tc.at))
				require.ErrorIs(t, err, verifier.ErrTrustInput)
				require.ErrorIs(t, err, tc.want)
				assert.False(t, res.Checked)
				assert.Equal(t, tc.cp.Height, res.CheckpointH)
				assert.Equal(t, tc.cp.Hash, res.CheckpointHash)
			})
		}
	})
	t.Run("a forged chain is not an input problem", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		src.byH[firstHeight+4] = encode(t, forged(c, firstHeight+4))
		tr := headertrust.New(c.checkpoint(t, top), src, nil)
		res, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		assert.NotErrorIs(t, err, verifier.ErrTrustInput)
		assert.Equal(t, top, res.CheckpointH, "the checkpoint is reported on failure too")
	})
	t.Run("a forged checkpoint is not an input problem", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Header = encode(t, forged(c, top))
		_, err := headertrust.New(cp, c.serve(t, firstHeight, top-1), nil).Trusted(ctx, firstHeight, c.hash(firstHeight))
		require.ErrorIs(t, err, headertrust.ErrCheckpointMismatch)
		assert.NotErrorIs(t, err, verifier.ErrTrustInput)
	})
}
