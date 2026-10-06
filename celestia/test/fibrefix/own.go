package fibrefix

import (
	"encoding/json"
	"os"
	"testing"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

// BoundSignedHeader wraps h in a SignedHeader whose commit names the height
// and the block id hash of h, as a consensus node serves it. The commit has no
// signatures.
func BoundSignedHeader(t testing.TB, h cmtproto.Header) []byte {
	t.Helper()
	ch, err := cmttypes.HeaderFromProto(&h)
	require.NoError(t, err)
	raw, err := (&cmtproto.SignedHeader{
		Header: &h,
		Commit: &cmtproto.Commit{Height: h.Height, BlockID: cmtproto.BlockID{Hash: ch.Hash()}},
	}).Marshal()
	require.NoError(t, err)
	return raw
}

// PromiseHeaderProto is the bare header at the promise height.
func (l *Live) PromiseHeaderProto(t testing.TB) cmtproto.Header {
	t.Helper()
	var h cmtproto.Header
	require.NoError(t, h.Unmarshal(l.PromiseHeader))
	return h
}

// PromiseValsetNext is the CometBFT validator set at the promise height + 1,
// the set that the next_validators_hash of the promise header commits to.
func (l *Live) PromiseValsetNext(t testing.TB) []byte {
	t.Helper()
	raw, err := os.ReadFile(vectorPath("fibre_cert.json"))
	require.NoError(t, err)
	var f struct {
		Live struct {
			Raw struct {
				Valsets []struct {
					Height string `json:"height"`
					Hex    string `json:"hex"`
				} `json:"cometbft_valsets"`
			} `json:"raw"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	for _, v := range f.Live.Raw.Valsets {
		if uint64(Num(t, v.Height)) == l.PromiseHeight+1 {
			return Unhex(t, v.Hex)
		}
	}
	require.FailNow(t, "no validator set after the promise height")
	return nil
}
