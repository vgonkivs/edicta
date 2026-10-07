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

func reasonOf(t testing.TB, err error, want verifier.Reason) []string {
	t.Helper()
	got, srcs, ok := verifier.ReasonOf(err)
	require.True(t, ok, "the error carries a reason: %v", err)
	require.Equal(t, want, got)
	return srcs
}

// namedChain is an online header source that says who it is.
type namedChain struct {
	*fakeChain
	name string
}

func (n namedChain) Name() string { return n.name }

// Every problem of header trust is a source problem with one reason of the
// closed set, and never a finding about the decision.
func TestTrustedReasons(t *testing.T) {
	const top = firstHeight + 10
	c := buildChain(firstHeight, top)
	ctx := context.Background()
	need := firstHeight + 2

	t.Run("checkpoint below the needed height", func(t *testing.T) {
		tr := headertrust.New(c.checkpoint(t, firstHeight+3), c.serve(t, firstHeight, top), nil)
		_, err := tr.Trusted(ctx, firstHeight+4, c.hash(firstHeight+4))
		reasonOf(t, err, verifier.ReasonHeaderAboveCheckpoint)
		require.ErrorIs(t, err, headertrust.ErrCheckpointTooLow)
	})
	t.Run("a chain too long to walk", func(t *testing.T) {
		cp := headertrust.Checkpoint{Height: firstHeight + headertrust.MaxChainLength + 1, Hash: c.hash(top)}
		_, err := headertrust.New(cp, c.serve(t, firstHeight, top), nil).Trusted(ctx, firstHeight, c.hash(firstHeight))
		reasonOf(t, err, verifier.ReasonHeaderSourceUnavailable)
		require.ErrorIs(t, err, headertrust.ErrChainTooLong)
	})
	t.Run("the source cannot serve a header", func(t *testing.T) {
		src := namedChain{&fakeChain{t: t, err: errors.New("down")}, "rpc.example"}
		_, err := headertrust.New(c.checkpoint(t, top), src, nil).Trusted(ctx, need, c.hash(need))
		assert.Equal(t, []string{"rpc.example"}, reasonOf(t, err, verifier.ReasonHeaderSourceUnavailable))
	})
	t.Run("an online header that does not link names its source", func(t *testing.T) {
		online := namedChain{c.serve(t, firstHeight, top-1), "rpc.example"}
		online.byH[firstHeight+5] = encode(t, forged(c, firstHeight+5))
		p := headertrust.Prefer(nil, online)
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, c.hash(need))
		assert.Equal(t, []string{"rpc.example"}, reasonOf(t, err, verifier.ReasonHeaderNotLinking))
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
		require.ErrorIs(t, err, verifier.ErrTrustInput)
	})
	t.Run("an archived header that does not link", func(t *testing.T) {
		f := forged(c, need)
		p := headertrust.Prefer(map[uint64][]byte{need: encode(t, f)}, c.serve(t, firstHeight, top-1))
		_, err := headertrust.New(c.checkpoint(t, top), p, nil).Trusted(ctx, need, f.Hash())
		reasonOf(t, err, verifier.ReasonChainMismatch)
		require.ErrorIs(t, err, headertrust.ErrChainBroken)
	})
	t.Run("a claimed hash that is not the chain's", func(t *testing.T) {
		tr := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), nil)
		_, err := tr.Trusted(ctx, firstHeight, c.hash(firstHeight+1))
		reasonOf(t, err, verifier.ReasonChainMismatch)
	})
	t.Run("headers the auditor supplied that do not link", func(t *testing.T) {
		src := c.serve(t, firstHeight, top-1)
		src.byH[firstHeight+5] = encode(t, forged(c, firstHeight+5))
		_, err := headertrust.New(c.checkpoint(t, top), src, nil).Trusted(ctx, need, c.hash(need))
		reasonOf(t, err, verifier.ReasonChainMismatch)
	})
	t.Run("a checkpoint header that is not its hash", func(t *testing.T) {
		cp := c.checkpoint(t, top)
		cp.Header = encode(t, forged(c, top))
		_, err := headertrust.New(cp, c.serve(t, firstHeight, top-1), nil).Trusted(ctx, need, c.hash(need))
		reasonOf(t, err, verifier.ReasonNoTrustedHeader)
	})
	t.Run("a cross source with another header is a disagreement, and says who", func(t *testing.T) {
		other := namedChain{fork(c, firstHeight, top).serve(t, firstHeight, top), "other.example"}
		tr := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), []headertrust.HeaderChain{other})
		res, err := tr.Trusted(ctx, need, c.hash(need))
		assert.Equal(t, []string{"other.example"}, reasonOf(t, err, verifier.ReasonHeaderDisagreement))
		require.ErrorIs(t, err, headertrust.ErrCrossCheckMismatch)
		assert.Contains(t, err.Error(), verifier.DisagreementText)
		assert.Equal(t, "mismatch", res.CrossCheck)
		assert.True(t, res.Checked, "the walk linked; it is the other source that differs")
	})
	t.Run("a cancelled run is not a source problem", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := headertrust.New(c.checkpoint(t, top), c.serve(t, firstHeight, top-1), nil).Trusted(cctx, need, c.hash(need))
		require.ErrorIs(t, err, context.Canceled)
		_, _, has := verifier.ReasonOf(err)
		assert.False(t, has)
	})
}

func TestAgreedCheckpointReasons(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+30)
	f := fork(c, firstHeight, firstHeight+31)

	t.Run("sources that disagree name both", func(t *testing.T) {
		_, _, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), src(t, f, "b.example", firstHeight+30)}, 1)
		assert.ElementsMatch(t, []string{"a.example", "b.example"}, reasonOf(t, err, verifier.ReasonHeaderDisagreement))
		assert.Contains(t, err.Error(), verifier.DisagreementText)
	})
	t.Run("no source answers", func(t *testing.T) {
		down := src(t, c, "a.example", firstHeight+30)
		down.latestErr = errors.New("down")
		_, _, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{down}, 1)
		reasonOf(t, err, verifier.ReasonHeaderSourceUnavailable)
		require.ErrorIs(t, err, verifier.ErrTrustInput)
	})
	t.Run("the headers cannot be read", func(t *testing.T) {
		broken := src(t, c, "a.example", firstHeight+30)
		broken.err = errors.New("down")
		_, _, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{broken}, 1)
		reasonOf(t, err, verifier.ReasonHeaderSourceUnavailable)
	})
	t.Run("fewer sources agree than the quorum", func(t *testing.T) {
		broken := src(t, c, "b.example", firstHeight+30)
		broken.err = errors.New("down")
		_, rep, err := headertrust.AgreedCheckpoint(bg, []headertrust.NamedChain{src(t, c, "a.example", firstHeight+30), broken}, 2)
		reasonOf(t, err, verifier.ReasonCheckpointQuorum)
		require.ErrorIs(t, err, verifier.ErrTrustInput)
		assert.Equal(t, 1, rep.Agreed)
	})
}
