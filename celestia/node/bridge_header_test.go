package node

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	libshare "github.com/celestiaorg/go-square/v4/share"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/header"
	headerapi "github.com/celestiaorg/celestia-node/nodebuilder/header"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

func headerBridge(get func(context.Context, uint64) (*header.ExtendedHeader, error)) bridge {
	var h headerapi.API
	h.Internal.GetByHeight = get
	return bridge{rc: &client.ReadClient{Header: &h}}
}

func signedExtHeader(h uint64) *header.ExtendedHeader {
	e := extHeader(h)
	e.Commit = &core.Commit{Height: int64(h), Round: 2}
	return e
}

func TestBridgeSignedHeader(t *testing.T) {
	b := headerBridge(func(_ context.Context, h uint64) (*header.ExtendedHeader, error) {
		return signedExtHeader(h), nil
	})
	raw, err := b.SignedHeader(tctx(t), 77)
	require.NoError(t, err)

	var got cmtproto.SignedHeader
	require.NoError(t, got.Unmarshal(raw))
	require.NotNil(t, got.Header)
	require.NotNil(t, got.Commit)
	assert.Equal(t, int64(77), got.Header.Height)
	assert.Equal(t, "mocha-4", got.Header.ChainID)
	assert.Equal(t, []byte{77}, got.Header.DataHash)
	assert.Equal(t, int64(77), got.Commit.Height)
	assert.Equal(t, int32(2), got.Commit.Round)
}

func TestBridgeSignedHeaderRefusals(t *testing.T) {
	tests := []struct {
		name string
		get  func(context.Context, uint64) (*header.ExtendedHeader, error)
		want error
	}{
		{"other height", func(context.Context, uint64) (*header.ExtendedHeader, error) { return extHeader(78), nil }, heightcheck.ErrHeightIgnored},
		{"nil header", func(context.Context, uint64) (*header.ExtendedHeader, error) { return nil, nil }, ErrUnavailable},
		{"no commit", func(_ context.Context, h uint64) (*header.ExtendedHeader, error) { return extHeader(h), nil }, ErrUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := headerBridge(tc.get).SignedHeader(tctx(t), 77)
			require.ErrorIs(t, err, tc.want)
			assert.Nil(t, raw)
		})
	}
}

func TestProofJSONRoundTripVerifies(t *testing.T) {
	ns, err := libshare.NewV0Namespace([]byte("edicta-tst"))
	require.NoError(t, err)
	bl, err := blob.NewBlobV0(ns, []byte("small payload"))
	require.NoError(t, err)
	shares, err := blob.BlobsToShares(bl)
	require.NoError(t, err)
	require.Len(t, shares, 1)

	raw := make([][]byte, len(shares))
	for i, s := range shares {
		raw[i] = s.ToBytes()
	}
	eds, err := da.ExtendShares(raw)
	require.NoError(t, err)
	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)
	root := dah.Hash()

	p, err := blob.ProveCommitment(eds, ns, shares)
	require.NoError(t, err)
	require.NoError(t, p.Verify(root, bl.Commitment))

	enc, err := json.Marshal(proof{p: p})
	require.NoError(t, err)
	var back blob.CommitmentProof
	require.NoError(t, json.Unmarshal(enc, &back))
	require.NoError(t, back.Verify(root, bl.Commitment))

	other := append([]byte(nil), root...)
	other[0] ^= 1
	assert.Error(t, back.Verify(other, bl.Commitment))
}
