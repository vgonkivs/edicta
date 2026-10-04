package nodefake_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

// Conformance to the seam, checked by the compiler.
var (
	_ node.Reader    = (*nodefake.Chain)(nil)
	_ node.Submitter = (*nodefake.Chain)(nil)
	_ node.Consensus = (*nodefake.Consensus)(nil)
)

func TestChainNotFoundMapsToSentinel(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewChain([]byte{1})
	_, err := c.Head(ctx)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.HeaderAt(ctx, 3)
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.Blob(ctx, 3, []byte{1}, []byte{2})
	assert.ErrorIs(t, err, node.ErrNotFound)
	_, err = c.CommitmentProof(ctx, 3, []byte{1}, []byte{2})
	assert.ErrorIs(t, err, node.ErrNotFound)
}

func TestChainFailAppliesToEveryMethod(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewChain([]byte{1})
	c.Fail = nodefake.ErrInjected
	_, e1 := c.Head(ctx)
	_, e2 := c.HeaderAt(ctx, 1)
	_, e3 := c.Blob(ctx, 1, nil, nil)
	_, e4 := c.CommitmentProof(ctx, 1, nil, nil)
	_, e5 := c.Address(ctx)
	_, e6 := c.SubmitBlob(ctx, nil, nil)
	for _, e := range []error{e1, e2, e3, e4, e5, e6} {
		assert.ErrorIs(t, e, nodefake.ErrInjected)
	}
}

func TestChainSubmitRoundTrip(t *testing.T) {
	ctx := context.Background()
	addr := []byte{9, 9}
	c := nodefake.NewChain(addr)
	c.AddHeader(node.Header{ChainID: "testchain-7", Height: 5})
	ns := []byte("ns")
	h, err := c.SubmitBlob(ctx, ns, []byte("data"))
	require.NoError(t, err)
	assert.EqualValues(t, 6, h)
	head, err := c.Head(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 6, head.Height)
	assert.Equal(t, "testchain-7", head.ChainID)
	assert.Equal(t, 1, c.Submitted)
}

func TestConsensusFibreAbsentIsNotFound(t *testing.T) {
	c := nodefake.NewConsensus("testchain-7")
	_, err := c.FibreParams(context.Background())
	assert.ErrorIs(t, err, node.ErrNotFound)
	c.Fibre = &node.FibreParams{RetentionS: 14400}
	p, err := c.FibreParams(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 14400, p.RetentionS)
}

func TestConsensusBroadcastAndTx(t *testing.T) {
	ctx := context.Background()
	c := nodefake.NewConsensus("testchain-7")
	hash, err := c.Broadcast(ctx, []byte("tx"))
	require.NoError(t, err)
	require.Len(t, c.Sent, 1)
	st, err := c.Tx(ctx, hash)
	require.NoError(t, err)
	assert.False(t, st.Found)
	c.SetTx(hash, node.TxStatus{Found: true, Height: 4})
	st, err = c.Tx(ctx, hash)
	require.NoError(t, err)
	assert.True(t, st.Found)
}
