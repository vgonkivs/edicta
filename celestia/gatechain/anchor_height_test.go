package gatechain_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestFindAnchorBindsTheBlobToTheDataRootOfTheHeader(t *testing.T) {
	var got [2][]byte
	c := chain(t, nil)
	c.AddBlob(H, node.Blob{Namespace: ns, Data: bytes.Clone(data), ShareVersion: 1, Signer: signer, Commitment: comm(t, data)},
		rootProof{root: rootAt(H), got: &got})
	r := ref(t)
	a, err := gatechain.NewAnchors(c).FindAnchor(bg, r)
	require.NoError(t, err)
	assert.EqualValues(t, H, a.Height)
	assert.Equal(t, rootAt(H), got[0], "verified against DataHash of the header at the ref height")
	assert.Equal(t, r.Commitment, got[1])
}

func TestFindAnchorWithoutAValidBindingIsChainUnavailable(t *testing.T) {
	blob := func() node.Blob {
		return node.Blob{Namespace: ns, Data: bytes.Clone(data), ShareVersion: 1, Signer: signer, Commitment: comm(t, data)}
	}
	cases := []struct {
		name  string
		build func() *nodefake.Chain
	}{
		{"proof of another data root", func() *nodefake.Chain {
			c := nodefake.NewChain(signer)
			c.AddHeader(node.Header{ChainID: "devnet-1", Height: H, Time: t0, DataRoot: rootAt(H)})
			c.AddBlob(H, blob(), rootProof{root: rootAt(H + 1)})
			return c
		}},
		{"header without a data root", func() *nodefake.Chain {
			c := nodefake.NewChain(signer)
			c.AddHeader(node.Header{ChainID: "devnet-1", Height: H, Time: t0})
			c.AddBlob(H, blob(), rootProof{root: rootAt(H)})
			return c
		}},
		{"blob served without a proof", func() *nodefake.Chain {
			c := nodefake.NewChain(signer)
			c.AddHeader(node.Header{ChainID: "devnet-1", Height: H, Time: t0, DataRoot: rootAt(H)})
			c.AddBlob(H, blob(), nil)
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gatechain.NewAnchors(tc.build()).FindAnchor(bg, ref(t))
			require.ErrorIs(t, err, gate.ErrChainUnavailable)
			assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
		})
	}
}

// heightBlind serves, for any requested height, the blob and proof stored at
// serve: a bridge that ignores the height argument.
type heightBlind struct {
	*nodefake.Chain
	serve uint64
}

func (b heightBlind) Blob(ctx context.Context, _ uint64, ns, c []byte) (node.Blob, error) {
	return b.Chain.Blob(ctx, b.serve, ns, c)
}

func (b heightBlind) CommitmentProof(ctx context.Context, _ uint64, ns, c []byte) (node.CommitmentProof, error) {
	return b.Chain.CommitmentProof(ctx, b.serve, ns, c)
}

func gateOver(t *testing.T, r node.Reader) *gatefix.Env {
	t.Helper()
	return gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
		d.Headers = gatechain.NewHeaders(r)
		d.Anchors = gatechain.NewAnchors(r)
		d.DA = gatechain.NewBlobSource(r)
	}))
}

func attackChain(t *testing.T, blobHeight uint64, proofRoot []byte) (*nodefake.Chain, *gatefix.Env, []byte, func()) {
	t.Helper()
	c := gatefix.Template(t)
	pr := c.PayloadRef
	ch := nodefake.NewChain(pr.Signer)
	ch.AddHeader(node.Header{ChainID: "devnet-1", Height: pr.Height, Time: time.Unix(int64(gatefix.BlockTime(c)), 0).UTC(), DataRoot: rootAt(pr.Height)})
	ch.AddBlob(blobHeight, node.Blob{Namespace: pr.Namespace, Data: gatefix.Blob(t), ShareVersion: 1, Signer: pr.Signer,
		Commitment: pr.Commitment}, rootProof{root: proofRoot})
	var env *gatefix.Env
	var rdr node.Reader = ch
	if blobHeight != pr.Height {
		rdr = heightBlind{Chain: ch, serve: blobHeight}
	}
	env = gateOver(t, rdr)
	b, _ := gatefix.Sign(t, "agent1", c)
	return ch, env, b, func() { env.RequireUntouched(c) }
}

func TestGateAuthorizesAnHonestBlobAtItsHeight(t *testing.T) {
	_, env, b, _ := attackChain(t, gatefix.Template(t).PayloadRef.Height, rootAt(gatefix.Template(t).PayloadRef.Height))
	res, err := env.Authorize(b)
	require.NoError(t, err)
	require.NotEmpty(t, res.Authorization)
}

// A blob and proof from another height are valid on their own; only the
// binding to the header at the committed height exposes them.
func TestGateNeverAuthorizesABlobFromAnotherHeight(t *testing.T) {
	h := gatefix.Template(t).PayloadRef.Height
	_, env, b, untouched := attackChain(t, h+7, rootAt(h+7))
	res, err := env.Authorize(b)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
	assert.Nil(t, res.Authorization)
	untouched()
}

func TestGateNeverAuthorizesWithoutAProof(t *testing.T) {
	h := gatefix.Template(t).PayloadRef.Height
	c := gatefix.Template(t)
	pr := c.PayloadRef
	ch := nodefake.NewChain(pr.Signer)
	ch.AddHeader(node.Header{ChainID: "devnet-1", Height: h, Time: time.Unix(int64(gatefix.BlockTime(c)), 0).UTC(), DataRoot: rootAt(h)})
	ch.AddBlob(h, node.Blob{Namespace: pr.Namespace, Data: gatefix.Blob(t), ShareVersion: 1, Signer: pr.Signer, Commitment: pr.Commitment}, nil)
	env := gateOver(t, ch)
	b, _ := gatefix.Sign(t, "agent1", c)
	res, err := env.Authorize(b)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	assert.Nil(t, res.Authorization)
	env.RequireUntouched(c)
}

// ---- retention sources over node ----

type fixedClock struct{}

func (fixedClock) Now() time.Time { return t0 }

// scripted overrides the two at-height calls of the consensus fake.
type scripted struct {
	*nodefake.Consensus
	at       func(h uint64) (node.FibreParams, error)
	canary   func(call int32) heightcheck.Status
	atCalls  atomic.Int32
	canCalls atomic.Int32
}

func (s *scripted) FibreParamsAt(_ context.Context, h uint64) (node.FibreParams, error) {
	s.atCalls.Add(1)
	return s.at(h)
}

func (s *scripted) HeightCanary(context.Context) (heightcheck.Status, error) {
	st := s.canary(s.canCalls.Add(1))
	if st == heightcheck.Inconclusive {
		return st, errors.New("canary: timeout")
	}
	return st, nil
}

func newScripted(at uint64, canary func(int32) heightcheck.Status) *scripted {
	cs := nodefake.NewConsensus("devnet-1")
	cs.Fibre = &node.FibreParams{RetentionS: 14400}
	cs.SetHeight(1000)
	return &scripted{Consensus: cs, canary: canary,
		at: func(uint64) (node.FibreParams, error) { return node.FibreParams{RetentionS: at}, nil }}
}

func startParams(t *testing.T, s *scripted) *retention.Params {
	t.Helper()
	latest, direct := gatechain.NewRetentionSources(s)
	p, err := retention.NewParams(retention.Policy{}, latest, direct, memstore.New(), fixedClock{})
	require.NoError(t, err)
	require.NoError(t, p.Start(bg))
	return p
}

func always(st heightcheck.Status) func(int32) heightcheck.Status {
	return func(int32) heightcheck.Status { return st }
}

func TestRetentionSourcesDirectReadUsedWhenCanaryPairPasses(t *testing.T) {
	s := newScripted(100, always(heightcheck.Honoured))
	p := startParams(t, s)
	require.False(t, p.ObservationsOnly())
	got, err := p.FibreRetention(bg, 1000)
	require.NoError(t, err)
	assert.EqualValues(t, 100, got, "the lower direct value beats the sample")
}

func TestRetentionSourcesDirectReadDiscardedWhenPairedCanaryFailsOrIsInconclusive(t *testing.T) {
	for name, st := range map[string]heightcheck.Status{
		"fails":        heightcheck.Ignoring,
		"inconclusive": heightcheck.Inconclusive,
	} {
		t.Run(name, func(t *testing.T) {
			// The start canary passes; the canary right after the read does not.
			s := newScripted(100, func(call int32) heightcheck.Status {
				if call == 1 {
					return heightcheck.Honoured
				}
				return st
			})
			p := startParams(t, s)
			require.False(t, p.ObservationsOnly())
			got, err := p.FibreRetention(bg, 1000)
			require.NoError(t, err)
			assert.EqualValues(t, 14400, got, "the direct value is dropped, the recorded sample stands")
			assert.Positive(t, s.atCalls.Load(), "the read was made and then discarded")
		})
	}
}

func TestRetentionSourcesHeightIgnoringEndpointNeverUsesTheDirectSource(t *testing.T) {
	s := newScripted(100, always(heightcheck.Ignoring))
	p := startParams(t, s)
	assert.True(t, p.ObservationsOnly())
	got, err := p.FibreRetention(bg, 1000)
	require.NoError(t, err)
	assert.EqualValues(t, 14400, got)
	assert.Zero(t, s.atCalls.Load(), "no at-height read is issued")

	_, err = p.FibreRetention(bg, 5000)
	require.ErrorIs(t, err, retention.ErrNotCovered, "uncovered height, never the latest value")
	assert.Zero(t, s.atCalls.Load())
}

func TestRetentionSourcesDirectReadFailureIsNotAValue(t *testing.T) {
	s := newScripted(0, always(heightcheck.Honoured))
	s.at = func(uint64) (node.FibreParams, error) {
		return node.FibreParams{}, errors.Join(node.ErrUnavailable, heightcheck.ErrHeightIgnored)
	}
	_, direct := gatechain.NewRetentionSources(s)
	_, err := direct.RetentionAt(bg, 1000)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)

	ok, err := direct.HonoursHeight(bg)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRetentionSourcesCanaryMapping(t *testing.T) {
	cases := map[string]struct {
		st      heightcheck.Status
		honours bool
		err     bool
	}{
		"honoured":     {heightcheck.Honoured, true, false},
		"ignoring":     {heightcheck.Ignoring, false, false},
		"inconclusive": {heightcheck.Inconclusive, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, direct := gatechain.NewRetentionSources(newScripted(1, always(tc.st)))
			ok, err := direct.HonoursHeight(bg)
			assert.Equal(t, tc.honours, ok)
			assert.Equal(t, tc.err, err != nil)
		})
	}
}

func TestRetentionLatestSourceReadsHeadValueHead(t *testing.T) {
	s := newScripted(1, always(heightcheck.Honoured))
	latest, _ := gatechain.NewRetentionSources(s)
	id, err := latest.ChainID(bg)
	require.NoError(t, err)
	assert.Equal(t, "devnet-1", id)
	smp, err := latest.LatestSample(bg)
	require.NoError(t, err)
	assert.Equal(t, "devnet-1", smp.ChainID)
	assert.EqualValues(t, 14400, smp.RetentionS)
	assert.EqualValues(t, 1000, smp.FromHeight)
	assert.EqualValues(t, 1000, smp.ToHeight)
}
