package headertrust_test

import (
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

func TestHeaderOfSigned(t *testing.T) {
	c := buildChain(firstHeight, firstHeight+3)
	bare := c.raw(t, firstHeight+1)
	var ph cmtproto.Header
	require.NoError(t, ph.Unmarshal(bare))

	t.Run("a bound signed header yields the bare header", func(t *testing.T) {
		got, err := headertrust.HeaderOfSigned(fibrefix.BoundSignedHeader(t, ph))
		require.NoError(t, err)
		assert.Equal(t, bare, got)
	})
	t.Run("a bare header is not a signed header", func(t *testing.T) {
		_, err := headertrust.HeaderOfSigned(bare)
		require.Error(t, err)
	})
	t.Run("the commit must be bound to the header", func(t *testing.T) {
		for name, sh := range map[string]cmtproto.SignedHeader{
			"no commit":    {Header: &ph},
			"no header":    {Commit: &cmtproto.Commit{Height: ph.Height}},
			"empty":        {Header: &ph, Commit: &cmtproto.Commit{}},
			"other block":  {Header: &ph, Commit: &cmtproto.Commit{Height: ph.Height, BlockID: cmtproto.BlockID{Hash: c.hash(firstHeight)}}},
			"other height": {Header: &ph, Commit: &cmtproto.Commit{Height: ph.Height + 1, BlockID: cmtproto.BlockID{Hash: c.hash(firstHeight + 1)}}},
		} {
			raw, err := sh.Marshal()
			require.NoError(t, err, name)
			_, err = headertrust.HeaderOfSigned(raw)
			assert.Error(t, err, name)
		}
	})
}
