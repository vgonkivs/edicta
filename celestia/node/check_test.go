package node_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// setup builds a healthy pair on an arbitrary chain id.
func setup(chainID string) (*nodefake.Chain, *nodefake.Consensus, node.Expect) {
	ch := nodefake.NewChain(make([]byte, 20))
	ch.AddHeader(node.Header{ChainID: chainID, Height: 10, Time: t0, AppVersion: 3, DataRoot: []byte{1}})
	return ch, nodefake.NewConsensus(chainID), node.Expect{Now: func() time.Time { return t0 }}
}

func TestCheckPasses(t *testing.T) {
	for _, id := range []string{"testchain-7", "x", "some_Other.chain/9"} {
		ch, co, e := setup(id)
		h, err := node.Check(context.Background(), ch, co, e)
		require.NoError(t, err, id)
		assert.Equal(t, id, h.ChainID)
		assert.EqualValues(t, 10, h.Height)

		e.ChainID = id
		_, err = node.Check(context.Background(), ch, co, e)
		require.NoError(t, err, id)
	}
}

func TestCheckRefusals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nodefake.Chain, *nodefake.Consensus, *node.Expect)
		want   string
	}{
		{"bridge head unreachable", func(ch *nodefake.Chain, _ *nodefake.Consensus, _ *node.Expect) { ch.Fail = nodefake.ErrInjected }, "bridge node head"},
		{"empty chain id in head", func(ch *nodefake.Chain, _ *nodefake.Consensus, _ *node.Expect) {
			ch.AddHeader(node.Header{Height: 11, Time: t0, AppVersion: 3})
		}, "no chain id"},
		{"config chain id differs", func(_ *nodefake.Chain, _ *nodefake.Consensus, e *node.Expect) { e.ChainID = "other-1" }, `expected "other-1"`},
		{"consensus on another chain", func(_ *nodefake.Chain, co *nodefake.Consensus, _ *node.Expect) { co.ChainID = "other-1" }, "consensus node on"},
		{"consensus info fails", func(_ *nodefake.Chain, co *nodefake.Consensus, _ *node.Expect) { co.Fail = nodefake.ErrInjected }, "consensus node info"},
		{"second provider differs", func(_ *nodefake.Chain, co *nodefake.Consensus, _ *node.Expect) {
			co.Providers = []string{"testchain-7", "other-1"}
		}, "consensus provider 1"},
		{"app version below default min", func(ch *nodefake.Chain, _ *nodefake.Consensus, _ *node.Expect) {
			ch.AddHeader(node.Header{ChainID: "testchain-7", Height: 11, Time: t0, AppVersion: 2})
		}, "app version 2 outside 3..10"},
		{"app version below configured min", func(_ *nodefake.Chain, _ *nodefake.Consensus, e *node.Expect) { e.MinAppVersion = 4 }, "app version 3 outside 4..10"},
		{"app version above max", func(ch *nodefake.Chain, _ *nodefake.Consensus, _ *node.Expect) {
			ch.AddHeader(node.Header{ChainID: "testchain-7", Height: 11, Time: t0, AppVersion: 11})
		}, "outside 3..10"},
		{"stale head", func(_ *nodefake.Chain, _ *nodefake.Consensus, e *node.Expect) {
			e.Now = func() time.Time { return t0.Add(121 * time.Second) }
		}, "off the local clock"},
		{"head from the future", func(_ *nodefake.Chain, _ *nodefake.Consensus, e *node.Expect) {
			e.Now = func() time.Time { return t0.Add(-121 * time.Second) }
		}, "off the local clock"},
		{"configured lag exceeded", func(_ *nodefake.Chain, _ *nodefake.Consensus, e *node.Expect) {
			e.MaxHeadLagS = 5
			e.Now = func() time.Time { return t0.Add(6 * time.Second) }
		}, "off the local clock"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, co, e := setup("testchain-7")
			tc.mutate(ch, co, &e)
			_, err := node.Check(context.Background(), ch, co, e)
			require.Error(t, err)
			assert.ErrorIs(t, err, node.ErrUnsupported)
			assert.ErrorContains(t, err, tc.want)
		})
	}
}

func TestCheckBoundaries(t *testing.T) {
	tests := []struct {
		name string
		app  uint64
		skew time.Duration
		e    node.Expect
	}{
		{"min app version exactly", 3, 0, node.Expect{}},
		{"max app version exactly", 10, 0, node.Expect{}},
		{"lag exactly at limit", 3, 120 * time.Second, node.Expect{}},
		{"negative skew exactly at limit", 3, -120 * time.Second, node.Expect{}},
		{"configured min lowers floor", 2, 0, node.Expect{MinAppVersion: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, co, _ := setup("testchain-7")
			ch.AddHeader(node.Header{ChainID: "testchain-7", Height: 11, Time: t0, AppVersion: tc.app})
			e := tc.e
			e.Now = func() time.Time { return t0.Add(tc.skew) }
			_, err := node.Check(context.Background(), ch, co, e)
			require.NoError(t, err)
		})
	}
}

func TestCheckNilDependencies(t *testing.T) {
	ch, co, e := setup("testchain-7")
	_, err := node.Check(context.Background(), nil, co, e)
	assert.ErrorIs(t, err, node.ErrUnsupported)
	_, err = node.Check(context.Background(), ch, nil, e)
	assert.ErrorIs(t, err, node.ErrUnsupported)
}

// probeReader answers the blob probes with a chosen error.
type probeReader struct {
	*nodefake.Chain
	blobErr, proofErr error
}

func (p probeReader) Blob(ctx context.Context, h uint64, ns, c []byte) (node.Blob, error) {
	return node.Blob{}, p.blobErr
}

func (p probeReader) CommitmentProof(ctx context.Context, h uint64, ns, c []byte) (node.CommitmentProof, error) {
	return nil, p.proofErr
}

func TestCheckProbeClassification(t *testing.T) {
	other := errors.New("rpc: blob: some new wording")
	tests := []struct {
		name              string
		blobErr, proofErr error
		want              string
	}{
		{"blob probe finds something", nil, node.ErrNotFound, "blob probe"},
		{"blob probe unknown error", other, node.ErrNotFound, "blob probe"},
		{"blob probe unavailable", node.ErrUnavailable, node.ErrNotFound, "blob probe"},
		{"proof probe finds something", node.ErrNotFound, nil, "commitment proof probe"},
		{"proof probe unknown error", node.ErrNotFound, other, "commitment proof probe"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, co, e := setup("testchain-7")
			_, err := node.Check(context.Background(), probeReader{ch, tc.blobErr, tc.proofErr}, co, e)
			require.Error(t, err)
			assert.ErrorIs(t, err, node.ErrUnsupported)
			assert.ErrorContains(t, err, tc.want)
		})
	}

	ch, co, e := setup("testchain-7")
	_, err := node.Check(context.Background(), probeReader{ch, node.ErrNotFound, node.ErrNotFound}, co, e)
	require.NoError(t, err)
}

func TestCheckProbeUsesConfiguredNamespace(t *testing.T) {
	ch, co, e := setup("testchain-7")
	e.Namespace = append(make([]byte, 19), []byte("customns01")...)
	_, err := node.Check(context.Background(), ch, co, e)
	require.NoError(t, err)
}

func TestCheckFibreAbsenceIsNotACheckFailure(t *testing.T) {
	ch, co, e := setup("testchain-7")
	co.Fibre = nil
	_, err := node.Check(context.Background(), ch, co, e)
	require.NoError(t, err)
	_, err = co.FibreParams(context.Background())
	assert.ErrorIs(t, err, node.ErrNotFound)
}
