package inclusion_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	_ sdk.InclusionVerifier    = (*inclusion.SelfCheck)(nil)
	_ sdk.IndependenceReporter = (*inclusion.SelfCheck)(nil)
)

func selfNode() (*nodefake.Chain, *fakeProof) {
	c, p := proofChain(h, dataRootAt(h))
	c.AddHeader(nodeHeader(h))
	return c, p
}

func TestSelfCheckAccepts(t *testing.T) {
	c, p := selfNode()
	s, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: chainID, Node: c})
	require.NoError(t, err)
	got, err := s.VerifyInclusion(bg, ref(h))
	require.NoError(t, err)
	assert.Equal(t, uint64(blockTime(h).Unix()), got)
	assert.Equal(t, dataRootAt(h), p.gotRoot)
}

// The report is what makes the SDK refuse this verifier for an untrusted
// submitter (see the root sdk tests).
func TestSelfCheckIsNotIndependent(t *testing.T) {
	c, _ := selfNode()
	s, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: chainID, Node: c})
	require.NoError(t, err)
	assert.False(t, s.Independent())
	assert.Equal(t, inclusion.LevelSelfCheck, s.Level())
}

func TestSelfCheckRejects(t *testing.T) {
	for name, mut := range map[string]func(*nodefake.Chain, *fakeProof){
		"header missing":  func(c *nodefake.Chain, _ *fakeProof) { *c = *nodefake.NewChain(nil) },
		"node failing":    func(c *nodefake.Chain, _ *fakeProof) { c.Fail = node.ErrUnavailable },
		"tampered proof":  func(_ *nodefake.Chain, p *fakeProof) { p.wantCommitment = sum("x") },
		"other data root": func(_ *nodefake.Chain, p *fakeProof) { p.wantRoot = sum("x") },
		"proof panics":    func(_ *nodefake.Chain, p *fakeProof) { p.panics = true },
		"wrong chain id":  func(c *nodefake.Chain, _ *fakeProof) { hd := nodeHeader(h); hd.ChainID = "x"; c.AddHeader(hd) },
	} {
		t.Run(name, func(t *testing.T) {
			c, p := selfNode()
			s, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: chainID, Node: c})
			require.NoError(t, err)
			mut(c, p)
			assert.NotPanics(t, func() {
				got, err := s.VerifyInclusion(bg, ref(h))
				require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
				assert.Zero(t, got)
			})
		})
	}
}

func TestSelfCheckConfigErrors(t *testing.T) {
	_, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: chainID})
	require.ErrorIs(t, err, inclusion.ErrConfig)
	c, _ := selfNode()
	_, err = inclusion.NewSelfCheck(inclusion.SelfCheckConfig{Node: c})
	require.ErrorIs(t, err, inclusion.ErrConfig)
}

func TestLevelsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range []inclusion.Level{inclusion.LevelLight, inclusion.LevelCrossCheck, inclusion.LevelSelfCheck} {
		require.NotEmpty(t, l.String())
		assert.False(t, seen[l.String()])
		seen[l.String()] = true
	}
}
