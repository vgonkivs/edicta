package inclusion_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	_ sdk.InclusionVerifier    = (*inclusion.CrossCheck)(nil)
	_ sdk.IndependenceReporter = (*inclusion.CrossCheck)(nil)
)

const h = 5

func headerNode(t *testing.T, mut func(*node.Header)) *nodefake.Chain {
	c := nodefake.NewChain(nil)
	hd := nodeHeader(h)
	if mut != nil {
		mut(&hd)
	}
	c.AddHeader(hd)
	return c
}

func source(name string, c *nodefake.Chain) inclusion.Source {
	return inclusion.Source{Name: name, Headers: c}
}

func crossRig(t *testing.T, srcs ...inclusion.Source) (*inclusion.CrossCheck, *fakeProof, error) {
	chain, p := proofChain(h, dataRootAt(h))
	cc, err := inclusion.NewCrossCheck(inclusion.CrossCheckConfig{ChainID: chainID, Sources: srcs, Proofs: chain})
	return cc, p, err
}

func TestCrossCheckAgreementPasses(t *testing.T) {
	for _, n := range []int{2, 3} {
		var srcs []inclusion.Source
		for i := 0; i < n; i++ {
			srcs = append(srcs, source(string(rune('a'+i)), headerNode(t, nil)))
		}
		cc, p, err := crossRig(t, srcs...)
		require.NoError(t, err)
		got, err := cc.VerifyInclusion(bg, ref(h))
		require.NoError(t, err)
		assert.Equal(t, uint64(blockTime(h).Unix()), got)
		assert.Equal(t, dataRootAt(h), p.gotRoot)
		assert.Equal(t, comm, p.gotCommitment)
	}
}

func TestCrossCheckDisagreementFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*node.Header)
	}{
		{"data root", func(hd *node.Header) { hd.DataRoot = sum("fork") }},
		{"time", func(hd *node.Header) { hd.Time = hd.Time.Add(time.Second) }},
		{"chain id", func(hd *node.Header) { hd.ChainID = "other-1" }},
		{"height", func(hd *node.Header) { hd.Height++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc, p, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)), source("c", headerNode(t, tc.mut)))
			require.NoError(t, err)
			got, err := cc.VerifyInclusion(bg, ref(h))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Zero(t, got)
			assert.Nil(t, p.gotRoot, "no proof is checked against a disputed root")
		})
	}
}

func TestCrossCheckAgreeingOnWrongChainFails(t *testing.T) {
	wrong := func(hd *node.Header) { hd.ChainID = "other-1" }
	cc, _, err := crossRig(t, source("a", headerNode(t, wrong)), source("b", headerNode(t, wrong)))
	require.NoError(t, err)
	_, err = cc.VerifyInclusion(bg, ref(h))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
}

func TestCrossCheckProviderFailures(t *testing.T) {
	missing := nodefake.NewChain(nil)
	down := headerNode(t, nil)
	down.Fail = errors.New("boom")
	for name, bad := range map[string]*nodefake.Chain{"header missing": missing, "provider failing": down} {
		t.Run(name, func(t *testing.T) {
			cc, p, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)), source("c", bad))
			require.NoError(t, err)
			_, err = cc.VerifyInclusion(bg, ref(h))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Nil(t, p.gotRoot)
		})
	}
}

func TestCrossCheckProofFailures(t *testing.T) {
	for name, mut := range map[string]func(*fakeProof){
		"tampered proof":  func(p *fakeProof) { p.wantCommitment = sum("x") },
		"other data root": func(p *fakeProof) { p.wantRoot = sum("x") },
	} {
		t.Run(name, func(t *testing.T) {
			cc, p, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)))
			require.NoError(t, err)
			mut(p)
			_, err = cc.VerifyInclusion(bg, ref(h))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
		})
	}
	t.Run("proof verify panics", func(t *testing.T) {
		cc, p, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)))
		require.NoError(t, err)
		p.panics = true
		assert.NotPanics(t, func() {
			got, err := cc.VerifyInclusion(bg, ref(h))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Zero(t, got)
		})
	})
}

func TestCrossCheckConfigErrors(t *testing.T) {
	a := headerNode(t, nil)
	submitter := source("submitter", headerNode(t, nil))
	submitter.SubmitterControlled = true
	for _, tc := range []struct {
		name string
		srcs []inclusion.Source
	}{
		{"none", nil},
		{"one", []inclusion.Source{source("a", a)}},
		{"same reader twice is one provider", []inclusion.Source{source("a", a), source("b", a)}},
		{"submitter's node does not count as independent", []inclusion.Source{source("a", a), submitter}},
		{"nil reader", []inclusion.Source{source("a", a), {Name: "b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc, _, err := crossRig(t, tc.srcs...)
			require.ErrorIs(t, err, inclusion.ErrConfig)
			assert.Nil(t, cc)
		})
	}
	t.Run("no proof source", func(t *testing.T) {
		_, err := inclusion.NewCrossCheck(inclusion.CrossCheckConfig{ChainID: chainID,
			Sources: []inclusion.Source{source("a", a), source("b", headerNode(t, nil))}})
		require.ErrorIs(t, err, inclusion.ErrConfig)
	})
	t.Run("no chain id", func(t *testing.T) {
		_, err := inclusion.NewCrossCheck(inclusion.CrossCheckConfig{Proofs: a,
			Sources: []inclusion.Source{source("a", a), source("b", headerNode(t, nil))}})
		require.ErrorIs(t, err, inclusion.ErrConfig)
	})
}

// The submitter's own node may be listed, but it only adds a vote that has to
// agree: with two independent providers present, a lying submitter node
// blocks acceptance and an honest one changes nothing.
func TestCrossCheckSubmitterNodeCountsOnlyAsExtraVote(t *testing.T) {
	sub := func(c *nodefake.Chain) inclusion.Source {
		s := source("submitter", c)
		s.SubmitterControlled = true
		return s
	}
	cc, _, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)), sub(headerNode(t, nil)))
	require.NoError(t, err)
	_, err = cc.VerifyInclusion(bg, ref(h))
	require.NoError(t, err)

	lie := func(hd *node.Header) { hd.DataRoot = sum("lie") }
	cc, _, err = crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)), sub(headerNode(t, lie)))
	require.NoError(t, err)
	_, err = cc.VerifyInclusion(bg, ref(h))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
}

// Independent of the submitter, but weaker than Light: the two facts are
// reported separately so a caller cannot mistake one for the other.
func TestCrossCheckIndependentButWeaker(t *testing.T) {
	cc, _, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)))
	require.NoError(t, err)
	assert.True(t, cc.Independent())
	assert.Equal(t, inclusion.LevelCrossCheck, cc.Level())
	assert.NotEqual(t, inclusion.LevelLight, cc.Level())
	assert.Contains(t, inclusion.LevelCrossCheck.String(), "weaker")
}

func TestCrossCheckBadRef(t *testing.T) {
	cc, _, err := crossRig(t, source("a", headerNode(t, nil)), source("b", headerNode(t, nil)))
	require.NoError(t, err)
	_, err = cc.VerifyInclusion(bg, ref(0))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	r := ref(h)
	r.Commitment = nil
	_, err = cc.VerifyInclusion(bg, r)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
}
