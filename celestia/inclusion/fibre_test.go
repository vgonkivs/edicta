package inclusion_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

var _ sdk.InclusionVerifier = (*inclusion.Fibre)(nil)

func fibreVerifier(t *testing.T, c *nodefake.FibreChain, chain string) *inclusion.Fibre {
	t.Helper()
	v, err := inclusion.NewFibre(inclusion.FibreConfig{Anchors: gatechain.NewFibreAnchors(c, chain, gatechain.FibreAnchorOptions{})})
	require.NoError(t, err)
	return v
}

func TestFibreAcceptsTheLivePFF(t *testing.T) {
	l := loadFbLive(t)
	v := fibreVerifier(t, l.chain(), fbChain)
	bt, err := v.VerifyInclusion(context.Background(), l.ref())
	require.NoError(t, err)
	assert.EqualValues(t, fbHeaderTime.Unix(), bt, "block time of the verified header")
}

func TestFibreRefusesWhatIsNotAnchored(t *testing.T) {
	l := loadFbLive(t)
	cases := []struct {
		name  string
		chain func(t *testing.T) *nodefake.FibreChain
		id    string
		ref   func(r *commitment.PayloadRef)
		cause error
	}{
		{name: "no PFF in the block", id: fbChain, chain: func(t *testing.T) *nodefake.FibreChain { return l.chainWithTxs(t) }},
		{name: "only other txs in the PFF namespace", id: fbChain,
			chain: func(t *testing.T) *nodefake.FibreChain { return l.chainWithTxs(t, []byte("a"), []byte("b")) }},
		{name: "certificate below the network rule", id: fbChain, cause: fibrecert.ErrCertificateInsufficient,
			chain: func(t *testing.T) *nodefake.FibreChain { return l.chainWithTxs(t, l.strippedPFF(t, 5)) }},
		{name: "certificate without any signature", id: fbChain, cause: fibrecert.ErrCertificateInsufficient,
			chain: func(t *testing.T) *nodefake.FibreChain { return l.chainWithTxs(t, l.strippedPFF(t, 0)) }},
		{name: "another chain", id: "mocha-4", chain: func(*testing.T) *nodefake.FibreChain { return l.chain() }},
		{name: "another commitment", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain { return l.chain() },
			ref: func(r *commitment.PayloadRef) { r.Commitment[0] ^= 1 }},
		{name: "another namespace", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain { return l.chain() },
			ref: func(r *commitment.PayloadRef) { r.Namespace[len(r.Namespace)-1] ^= 1 }},
		{name: "reference of a celestia_blob payload", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain { return l.chain() },
			ref: func(r *commitment.PayloadRef) { r.DA = commitment.DACelestiaBlob }},
		{name: "height zero", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain { return l.chain() },
			ref: func(r *commitment.PayloadRef) { r.Height = 0 }},
		{name: "endpoint ignores the requested height", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain {
			c := l.chain()
			c.AddHeader(l.pffHeight+1, l.dataHash, fbHeaderTime)
			c.IgnoreHeights(l.pffHeight + 1)
			return c
		}},
		{name: "consensus endpoint fails", id: fbChain, cause: nodefake.ErrInjected, chain: func(*testing.T) *nodefake.FibreChain {
			c := l.chain()
			c.Fail = nodefake.ErrInjected
			return c
		}},
		{name: "bridge fails", id: fbChain, cause: nodefake.ErrInjected, chain: func(*testing.T) *nodefake.FibreChain {
			c := l.chain()
			c.FailBridge = nodefake.ErrInjected
			return c
		}},
		{name: "certificate evidence missing", id: fbChain, chain: func(*testing.T) *nodefake.FibreChain {
			c := nodefake.NewFibreChain()
			c.AddHeader(l.pffHeight, l.dataHash, fbHeaderTime)
			c.SetDAH(l.pffHeight, l.rowRoots, l.colRoots)
			c.SetNamespaceData(l.pffHeight, l.nd)
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := l.ref()
			if tc.ref != nil {
				tc.ref(&ref)
			}
			bt, err := fibreVerifier(t, tc.chain(t), tc.id).VerifyInclusion(context.Background(), ref)
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Zero(t, bt, "no block time on a refusal")
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
		})
	}
}

func TestFibreRefusesACanceledContext(t *testing.T) {
	l := loadFbLive(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := l.chain()
	_, err := fibreVerifier(t, c, fbChain).VerifyInclusion(ctx, l.ref())
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.Zero(t, c.HeaderReads())
}

func TestFibreConfigNeedsAnchors(t *testing.T) {
	_, err := inclusion.NewFibre(inclusion.FibreConfig{})
	require.ErrorIs(t, err, inclusion.ErrConfig)
}
