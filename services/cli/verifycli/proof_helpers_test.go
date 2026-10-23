package verifycli

import (
	"encoding/json"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	"github.com/cometbft/cometbft/crypto/merkle"
	tmbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

// proofOf builds a real inclusion proof of txs[idx] in the square made of
// txs, in the form a node serves it, and the data root it verifies against.
func proofOf(t testing.TB, txs [][]byte, idx int) (json.RawMessage, []byte) {
	t.Helper()
	sp, err := proof.NewTxInclusionProof(txs, uint64(idx), 0)
	require.NoError(t, err)
	out := core.ShareProof{
		Data:             sp.Data,
		NamespaceID:      sp.NamespaceId,
		NamespaceVersion: sp.NamespaceVersion,
		RowProof:         core.RowProof{StartRow: sp.RowProof.StartRow, EndRow: sp.RowProof.EndRow},
	}
	for _, p := range sp.ShareProofs {
		out.ShareProofs = append(out.ShareProofs, &cmtproto.NMTProof{Start: p.Start, End: p.End, Nodes: p.Nodes})
	}
	for i, r := range sp.RowProof.RowRoots {
		out.RowProof.RowRoots = append(out.RowProof.RowRoots, tmbytes.HexBytes(r))
		p := sp.RowProof.Proofs[i]
		out.RowProof.Proofs = append(out.RowProof.Proofs, &merkle.Proof{Total: p.Total, Index: p.Index, LeafHash: p.LeafHash, Aunts: p.Aunts})
	}
	root := out.RowProof.Proofs[0].ComputeRootHash()
	b, err := cmtjson.Marshal(out)
	require.NoError(t, err)
	return b, root
}
