package inclusion_test

import (
	"context"
	"testing"
	"time"

	"github.com/cometbft/cometbft/light"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	_ sdk.InclusionVerifier    = (*inclusion.Light)(nil)
	_ sdk.IndependenceReporter = (*inclusion.Light)(nil)
)

// lightRig wires a Light over fake providers; the trust anchor is height 1.
type lightRig struct {
	c       *testChain
	primary *fakeProvider
	wit     []*fakeProvider
	proofs  node.Reader
	proof   *fakeProof
	cfg     inclusion.LightConfig
}

func newLightRig(t *testing.T, target int64, o blockOpts) *lightRig {
	c := newTestChain()
	r := &lightRig{c: c, primary: override(t, c, 12, target, o)}
	r.wit = []*fakeProvider{override(t, c, 12, target, o)}
	r.reset(t, target)
	return r
}

func (r *lightRig) reset(t *testing.T, target int64) {
	chain, proof := proofChain(uint64(target), dataRootAt(target))
	r.proofs, r.proof = chain, proof
	r.cfg = inclusion.LightConfig{
		ChainID: chainID,
		Trust:   light.TrustOptions{Period: time.Hour, Height: 1, Hash: r.c.block(t, 1, blockOpts{}).Hash()},
		Primary: r.primary,
		Proofs:  r.proofs,
		Now:     func() time.Time { return base.Add(5 * time.Minute) },
	}
	for _, w := range r.wit {
		r.cfg.Witnesses = append(r.cfg.Witnesses, w)
	}
}

// run builds the verifier and verifies the blob at h. A failure to build is
// a rejection as much as a failed verification: nothing gets signed.
func (r *lightRig) run(h uint64) (uint64, error) {
	l, err := inclusion.NewLight(bg, r.cfg)
	if err != nil {
		return 0, err
	}
	return l.VerifyInclusion(bg, ref(h))
}

func TestLightAccepts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		target     int64
		sequential bool
	}{
		{"adjacent", 2, false},
		{"skipping with bisection", 10, false},
		{"sequential", 10, true},
		{"the anchor itself", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLightRig(t, tc.target, blockOpts{})
			r.cfg.Sequential = tc.sequential
			got, err := r.run(uint64(tc.target))
			require.NoError(t, err)
			assert.Equal(t, uint64(blockTime(tc.target).Unix()), got, "header time floored to seconds")
			assert.Equal(t, dataRootAt(tc.target), r.proof.gotRoot, "proof checked against the verified data root")
			assert.Equal(t, comm, r.proof.gotCommitment)
		})
	}
}

// The target set shares no key with the anchor's: a direct skip cannot be
// trusted, so the client must walk through intermediate headers.
func TestLightBisectionNeedsIntermediateHeaders(t *testing.T) {
	r := newLightRig(t, 10, blockOpts{})
	_, err := r.run(10)
	require.NoError(t, err)
	assert.Greater(t, len(r.primary.calls), 2, "intermediate headers were fetched")
}

func TestLightIndependent(t *testing.T) {
	r := newLightRig(t, 3, blockOpts{})
	l, err := inclusion.NewLight(bg, r.cfg)
	require.NoError(t, err)
	assert.True(t, l.Independent())
	assert.Equal(t, inclusion.LevelLight, l.Level())
}

func TestLightPowerThreshold(t *testing.T) {
	// 6 equal validators: 4 is exactly 2/3 and is not more than 2/3.
	for _, tc := range []struct {
		name    string
		signers int
		ok      bool
	}{
		{"all", 6, true},
		{"5 of 6", 5, true},
		{"exactly 2/3", 4, false},
		{"half", 3, false},
		{"one", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLightRig(t, 2, blockOpts{signers: tc.signers})
			_, err := r.run(2)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestLightRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target int64
		opts   blockOpts
	}{
		{"bad signatures leave too little power", 2, blockOpts{signers: 6, badSigs: 3}},
		{"signed by keys outside the set", 2, blockOpts{forged: true}},
		{"wrong chain id in the header", 2, blockOpts{chainID: "other-1"}},
		{"header from the future", 2, blockOpts{time: base.Add(2 * time.Hour)}},
		{"data root changed after signing", 2, blockOpts{swapRoot: sum("swapped")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLightRig(t, tc.target, tc.opts)
			// Primary and witness agree on the bad block: only the checks can reject it.
			_, err := r.run(uint64(tc.target))
			require.Error(t, err)
		})
	}
}

// A data root swapped after signing must not be taken from a header whose
// commit still names the original hash, even when the proof fits the swap.
func TestLightSwappedDataRootRejectedEvenWithMatchingProof(t *testing.T) {
	swapped := sum("swapped")
	r := newLightRig(t, 2, blockOpts{swapRoot: swapped})
	chain, proof := proofChain(2, swapped)
	r.cfg.Proofs = chain
	_, err := r.run(2)
	require.Error(t, err)
	assert.Nil(t, proof.gotRoot, "proof was never consulted for an unverified header")
}

func TestLightTrustingPeriod(t *testing.T) {
	r := newLightRig(t, 2, blockOpts{})
	r.cfg.Now = func() time.Time { return base.Add(2 * time.Hour) }
	_, err := r.run(2)
	require.Error(t, err)

	r = newLightRig(t, 2, blockOpts{})
	r.cfg.Now = func() time.Time { return base.Add(time.Hour + time.Minute) }
	_, err = r.run(2)
	require.Error(t, err)
}

func TestLightHeightBeyondProviders(t *testing.T) {
	r := newLightRig(t, 2, blockOpts{})
	l, err := inclusion.NewLight(bg, r.cfg)
	require.NoError(t, err)
	_, err = l.VerifyInclusion(bg, ref(99))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
}

func TestLightWrongTrustAnchorHash(t *testing.T) {
	r := newLightRig(t, 2, blockOpts{})
	r.cfg.Trust.Hash = sum("not the anchor")
	_, err := r.run(2)
	require.Error(t, err)
}

func TestLightConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*inclusion.LightConfig)
	}{
		{"no witness", func(c *inclusion.LightConfig) { c.Witnesses = nil }},
		{"no primary", func(c *inclusion.LightConfig) { c.Primary = nil }},
		{"no proof source", func(c *inclusion.LightConfig) { c.Proofs = nil }},
		{"no chain id", func(c *inclusion.LightConfig) { c.ChainID = "" }},
		{"zero trusting period", func(c *inclusion.LightConfig) { c.Trust.Period = 0 }},
		{"short anchor hash", func(c *inclusion.LightConfig) { c.Trust.Hash = []byte{1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLightRig(t, 2, blockOpts{})
			tc.mut(&r.cfg)
			l, err := inclusion.NewLight(bg, r.cfg)
			require.ErrorIs(t, err, inclusion.ErrConfig)
			assert.Nil(t, l)
		})
	}
}

// Two providers that each serve a validly signed, different header for one
// height mean equivocation: verification stops, nothing is signed.
func TestLightWitnessDivergenceFailsClosed(t *testing.T) {
	r := newLightRig(t, 3, blockOpts{})
	r.primary = honest(t, r.c, 12)
	r.wit = []*fakeProvider{override(t, r.c, 12, 3, blockOpts{dataRoot: sum("fork")})}
	r.reset(t, 3)
	_, err := r.run(3)
	require.Error(t, err)
	assert.Nil(t, r.proof.gotRoot)
}

func TestLightProofFailures(t *testing.T) {
	t.Run("tampered proof", func(t *testing.T) {
		r := newLightRig(t, 3, blockOpts{})
		r.proof.wantCommitment = sum("other")
		_, err := r.run(3)
		require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	})
	t.Run("proof for another data root", func(t *testing.T) {
		r := newLightRig(t, 3, blockOpts{})
		r.proof.wantRoot = sum("other root")
		_, err := r.run(3)
		require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	})
	t.Run("proof unavailable", func(t *testing.T) {
		r := newLightRig(t, 3, blockOpts{})
		r.cfg.Proofs, _ = proofChain(4, dataRootAt(4)) // proof exists only for another height
		_, err := r.run(3)
		require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	})
	t.Run("proof source failing", func(t *testing.T) {
		r := newLightRig(t, 3, blockOpts{})
		chain, _ := proofChain(3, dataRootAt(3))
		chain.Fail = node.ErrUnavailable
		r.cfg.Proofs = chain
		_, err := r.run(3)
		require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	})
	t.Run("proof verify panics", func(t *testing.T) {
		r := newLightRig(t, 3, blockOpts{})
		r.proof.panics = true
		assert.NotPanics(t, func() {
			bt, err := r.run(3)
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Zero(t, bt)
		})
	})
}

func TestLightProviderPanicIsAnError(t *testing.T) {
	r := newLightRig(t, 3, blockOpts{})
	l, err := inclusion.NewLight(bg, r.cfg)
	require.NoError(t, err)
	r.primary.panics = true
	assert.NotPanics(t, func() {
		bt, err := l.VerifyInclusion(bg, ref(9))
		require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
		assert.Zero(t, bt)
	})
}

func TestLightBadRefAndContext(t *testing.T) {
	r := newLightRig(t, 3, blockOpts{})
	l, err := inclusion.NewLight(bg, r.cfg)
	require.NoError(t, err)

	zero := ref(0)
	_, err = l.VerifyInclusion(bg, zero)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)

	noC := ref(3)
	noC.Commitment = nil
	_, err = l.VerifyInclusion(bg, noC)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)

	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err = l.VerifyInclusion(ctx, ref(3))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
}

func TestLightErrorsWrapCause(t *testing.T) {
	r := newLightRig(t, 3, blockOpts{})
	chain, _ := proofChain(3, dataRootAt(3))
	chain.Fail = node.ErrUnavailable
	r.cfg.Proofs = chain
	l, err := inclusion.NewLight(bg, r.cfg)
	require.NoError(t, err)
	_, err = l.VerifyInclusion(bg, ref(3))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.ErrorIs(t, err, node.ErrUnavailable)
}

// A header that validators signed with another data root is honest: the
// proof for that root is the right one to accept.
func TestLightAcceptsSignedHeaderWithOtherDataRoot(t *testing.T) {
	other := sum("signed other root")
	r := newLightRig(t, 2, blockOpts{dataRoot: other})
	chain, proof := proofChain(2, other)
	r.cfg.Proofs = chain
	_, err := r.run(2)
	require.NoError(t, err)
	assert.Equal(t, other, proof.gotRoot)
}
