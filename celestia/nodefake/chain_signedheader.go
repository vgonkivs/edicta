package nodefake

import (
	"bytes"
	"context"
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	cmttypes "github.com/cometbft/cometbft/types"
)

// SignedHeader returns a SignedHeader for the stored header at height: its
// data hash is the stored data root and the commit names the hash of that
// header. The commit carries no signatures; readers that check them need the
// real client.
func (c *Chain) SignedHeader(_ context.Context, height uint64) ([]byte, error) {
	hd, err := c.HeaderAt(context.Background(), height)
	if err != nil {
		return nil, err
	}
	ph := &cmtproto.Header{
		Version:         cmtversion.Consensus{Block: 11, App: hd.AppVersion},
		ChainID:         hd.ChainID,
		Height:          int64(hd.Height),
		Time:            hd.Time,
		DataHash:        bytes.Clone(hd.DataRoot),
		ValidatorsHash:  bytes.Repeat([]byte{1}, 32),
		ConsensusHash:   bytes.Repeat([]byte{2}, 32),
		LastBlockId:     cmtproto.BlockID{Hash: bytes.Repeat([]byte{3}, 32), PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{4}, 32)}},
		ProposerAddress: bytes.Repeat([]byte{5}, 20),
	}
	h, err := cmttypes.HeaderFromProto(ph)
	if err != nil {
		return nil, fmt.Errorf("nodefake: header: %w", err)
	}
	sh := cmtproto.SignedHeader{
		Header: ph,
		Commit: &cmtproto.Commit{Height: ph.Height, BlockID: cmtproto.BlockID{Hash: h.Hash(),
			PartSetHeader: cmtproto.PartSetHeader{Total: 1, Hash: bytes.Repeat([]byte{6}, 32)}}},
	}
	return sh.Marshal()
}
