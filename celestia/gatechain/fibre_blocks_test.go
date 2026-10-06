package gatechain_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/eds"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/celestiaorg/nmt"

	"github.com/vgonkivs/edicta/celestia/nodefake"
)

const anchorVectorPath = "../../spec/vectors/da/fibre_anchor.json"

var headerTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

type vecQuery struct {
	Description string   `json:"description"`
	Namespace   string   `json:"namespace"`
	Commitment  string   `json:"commitment"`
	ChainID     string   `json:"chain_id"`
	Candidates  []string `json:"candidates"`
	Anchor      string   `json:"anchor"`
}

type vecTx struct {
	Position string `json:"position"`
	SHA256   string `json:"sha256"`
	Promise  struct {
		Commitment string `json:"commitment"`
		Namespace  string `json:"namespace"`
	} `json:"promise"`
}

type vecCase struct {
	ID  string `json:"id"`
	Raw struct {
		Height     string   `json:"height"`
		DataHash   string   `json:"data_hash"`
		RowRoots   []string `json:"row_roots"`
		ColRoots   []string `json:"column_roots"`
		NamespaceD string   `json:"namespace_data_hex"`
	} `json:"raw"`
	Expect struct {
		Txs          []vecTx    `json:"txs"`
		Queries      []vecQuery `json:"queries"`
		ArchiveProof struct {
			Hex    string `json:"hex"`
			SHA256 string `json:"sha256"`
		} `json:"archive_proof"`
	} `json:"expect"`
}

type vecOp struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Index  string `json:"index"`
	Offset string `json:"offset"`
	Xor    string `json:"xor"`
	Row    string `json:"row"`
	Share  string `json:"share"`
	Row2   string `json:"row2"`
	Value  string `json:"value"`
	Bytes  string `json:"bytes"`
	NS     string `json:"namespace"`
}

type vecMutation struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Case        string `json:"case"`
	Op          vecOp  `json:"op"`
	Expect      struct {
		Verdict string `json:"verdict"`
		Fails   string `json:"fails"`
	} `json:"expect"`
}

type vecReassembly struct {
	ID     string   `json:"id"`
	Shares []string `json:"shares_hex"`
	Expect struct {
		Verdict string   `json:"verdict"`
		Fails   string   `json:"fails"`
		TxsSHA  []string `json:"txs_sha256"`
	} `json:"expect"`
}

type anchorVector struct {
	Live struct {
		Cases []vecCase `json:"cases"`
	} `json:"live"`
	Mutations  []vecMutation   `json:"mutations"`
	Reassembly []vecReassembly `json:"reassembly"`
}

func loadAnchorVector(t testing.TB) anchorVector {
	t.Helper()
	raw, err := os.ReadFile(anchorVectorPath)
	require.NoError(t, err)
	var v anchorVector
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Live.Cases)
	require.NotEmpty(t, v.Mutations)
	require.NotEmpty(t, v.Reassembly)
	return v
}

func (v anchorVector) caseByID(t testing.TB, id string) vecCase {
	t.Helper()
	for _, c := range v.Live.Cases {
		if c.ID == id {
			return c
		}
	}
	require.FailNow(t, "no such case", id)
	return vecCase{}
}

func num(t testing.TB, s string) int {
	t.Helper()
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	require.NoError(t, err)
	return n
}

// block is what a bridge and a consensus node say about one height: the data
// hash of the header, the DAH and the PayForFibre namespace data.
type block struct {
	height   uint64
	dataHash []byte
	rows     [][]byte
	cols     [][]byte
	nd       shwap.NamespaceData
}

func vectorBlock(t testing.TB, c vecCase) block {
	t.Helper()
	b := block{height: uint64(num(t, c.Raw.Height)), dataHash: unhex(t, c.Raw.DataHash)}
	for _, r := range c.Raw.RowRoots {
		b.rows = append(b.rows, unhex(t, r))
	}
	for _, r := range c.Raw.ColRoots {
		b.cols = append(b.cols, unhex(t, r))
	}
	require.NoError(t, readStream(&b.nd, unhex(t, c.Raw.NamespaceD)))
	return b
}

func readStream(nd *shwap.NamespaceData, stream []byte) error {
	_, err := nd.ReadFrom(bytes.NewReader(stream))
	return err
}

func streamOf(t testing.TB, nd shwap.NamespaceData) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, err := nd.WriteTo(&buf)
	require.NoError(t, err)
	return buf.Bytes()
}

// splitTxs puts txs in compact shares of the PayForFibre namespace.
func splitTxs(t testing.TB, txs ...[]byte) []libshare.Share {
	t.Helper()
	css := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
	for _, tx := range txs {
		require.NoError(t, css.WriteTx(tx))
	}
	shares, err := css.Export()
	require.NoError(t, err)
	return shares
}

// buildBlockFromShares makes a block whose square holds the shares in the
// PayForFibre namespace, followed by tail padding, with real proofs.
func buildBlockFromShares(t testing.TB, height uint64, shares []libshare.Share) block {
	t.Helper()
	k := 2
	for k*k < len(shares) {
		k *= 2
	}
	ods := append(append([]libshare.Share(nil), shares...), libshare.TailPaddingShares(k*k-len(shares))...)
	sq, err := eds.Rsmt2DFromShares(ods, k)
	require.NoError(t, err)
	roots, err := sq.AxisRoots(context.Background())
	require.NoError(t, err)
	nd, err := eds.NamespaceData(context.Background(), sq, libshare.PayForFibreNamespace)
	require.NoError(t, err)
	return block{height: height, dataHash: roots.Hash(), rows: roots.RowRoots, cols: roots.ColumnRoots, nd: nd}
}

func buildBlock(t testing.TB, height uint64, txs ...[]byte) block {
	t.Helper()
	if len(txs) == 0 {
		return buildBlockFromShares(t, height, nil)
	}
	return buildBlockFromShares(t, height, splitTxs(t, txs...))
}

func (b block) clone() block {
	c := block{height: b.height, dataHash: bytes.Clone(b.dataHash)}
	for _, r := range b.rows {
		c.rows = append(c.rows, bytes.Clone(r))
	}
	for _, r := range b.cols {
		c.cols = append(c.cols, bytes.Clone(r))
	}
	c.nd = cloneND(b.nd)
	return c
}

func cloneND(nd shwap.NamespaceData) shwap.NamespaceData {
	out := make(shwap.NamespaceData, len(nd))
	for i, r := range nd {
		out[i].Shares = append([]libshare.Share(nil), r.Shares...)
		if r.Proof != nil {
			p := *r.Proof
			out[i].Proof = &p
		}
	}
	return out
}

func (b block) dah() *da.DataAvailabilityHeader {
	return &da.DataAvailabilityHeader{RowRoots: b.rows, ColumnRoots: b.cols}
}

// chain serves the block and the certificate evidence of the live promise.
func (b block) chain(t testing.TB, l live) *nodefake.FibreChain {
	t.Helper()
	c := nodefake.NewFibreChain()
	c.AddHeader(b.height, b.dataHash, headerTime)
	c.SetDAH(b.height, b.rows, b.cols)
	c.SetNamespaceData(b.height, b.nd)
	c.SetHistoricalInfo(l.promiseH, l.hist)
	c.SetSignedHeader(l.promiseH, l.promiseHdr)
	return c
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func flipByte(b []byte, off int, x byte) []byte {
	out := bytes.Clone(b)
	out[off] ^= x
	return out
}

// applyOp edits the block as the vector op says. truncate_stream and
// verify_namespace act on the encoded stream and the checked namespace, which
// the bridge reader cannot express; they report false.
func applyOp(t testing.TB, b block, op vecOp) (block, bool) {
	t.Helper()
	b = b.clone()
	x := byte(0)
	if op.Xor != "" {
		x = unhex(t, op.Xor)[0]
	}
	rowIdx := func(s string) int {
		if s == "last" {
			return len(b.nd) - 1
		}
		return num(t, s)
	}
	shareIdx := func(r int, s string) int {
		if s == "last" {
			return len(b.nd[r].Shares) - 1
		}
		return num(t, s)
	}
	switch op.Kind {
	case "flip":
		switch op.Target {
		case "data_hash":
			b.dataHash = flipByte(b.dataHash, num(t, op.Offset), x)
		case "row_root":
			i := num(t, op.Index)
			b.rows[i] = flipByte(b.rows[i], num(t, op.Offset), x)
		case "column_root":
			i := num(t, op.Index)
			b.cols[i] = flipByte(b.cols[i], num(t, op.Offset), x)
		case "share":
			r := rowIdx(op.Row)
			s := shareIdx(r, op.Share)
			sh, err := libshare.NewShare(flipByte(b.nd[r].Shares[s].ToBytes(), num(t, op.Offset), x))
			require.NoError(t, err)
			b.nd[r].Shares[s] = sh
		default:
			require.FailNow(t, "unknown flip target", op.Target)
		}
	case "move_column_root_to_rows":
		b.rows = append(b.rows, b.cols[0])
		b.cols = b.cols[1:]
	case "drop_share":
		r := rowIdx(op.Row)
		s := shareIdx(r, op.Share)
		b.nd[r].Shares = append(b.nd[r].Shares[:s:s], b.nd[r].Shares[s+1:]...)
	case "drop_row":
		r := rowIdx(op.Row)
		b.nd = append(b.nd[:r:r], b.nd[r+1:]...)
	case "dup_row":
		r := rowIdx(op.Row)
		b.nd = append(b.nd, b.nd[r])
	case "swap_rows":
		i, j := rowIdx(op.Row), rowIdx(op.Row2)
		b.nd[i], b.nd[j] = b.nd[j], b.nd[i]
	case "set_max_ns_ignored":
		r := rowIdx(op.Row)
		p := b.nd[r].Proof
		var np nmt.Proof
		if p.IsOfAbsence() {
			np = nmt.NewAbsenceProof(p.Start(), p.End(), p.Nodes(), p.LeafHash(), op.Value == "true")
		} else {
			np = nmt.NewInclusionProof(p.Start(), p.End(), p.Nodes(), op.Value == "true")
		}
		b.nd[r].Proof = &np
	case "truncate_stream", "verify_namespace":
		return b, false
	default:
		require.FailNow(t, "unknown op", op.Kind)
	}
	return b, true
}

func newInclusion(p *nmt.Proof, nodes [][]byte) nmt.Proof {
	return nmt.NewInclusionProof(p.Start(), p.End(), nodes, p.IsMaxNamespaceIDIgnored())
}

func newRange(p *nmt.Proof, start, end int) nmt.Proof {
	return nmt.NewInclusionProof(start, end, p.Nodes(), p.IsMaxNamespaceIDIgnored())
}
