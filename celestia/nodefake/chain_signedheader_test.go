package nodefake

import (
	"bytes"
	"context"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
)

func TestChainSignedHeaderIsCoherent(t *testing.T) {
	c := NewChain(nil)
	root := bytes.Repeat([]byte{7}, 32)
	c.AddHeader(node.Header{ChainID: "x-1", Height: 5, Time: time.Unix(1_700_000_000, 0), AppVersion: 8, DataRoot: root})

	raw, err := c.SignedHeader(context.Background(), 5)
	require.NoError(t, err)
	var sh cmtproto.SignedHeader
	require.NoError(t, sh.Unmarshal(raw))
	require.NotNil(t, sh.Header)
	require.NotNil(t, sh.Commit)
	assert.EqualValues(t, 5, sh.Header.Height)
	assert.Equal(t, root, sh.Header.DataHash)
	assert.EqualValues(t, 5, sh.Commit.Height)
	h, err := cmttypes.HeaderFromProto(sh.Header)
	require.NoError(t, err)
	assert.Equal(t, []byte(h.Hash()), sh.Commit.BlockID.Hash, "the commit names this header")

	_, err = c.SignedHeader(context.Background(), 6)
	require.ErrorIs(t, err, node.ErrNotFound)
	c.Fail = ErrInjected
	_, err = c.SignedHeader(context.Background(), 5)
	require.ErrorIs(t, err, ErrInjected)
}
