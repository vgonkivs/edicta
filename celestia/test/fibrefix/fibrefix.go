// Package fibrefix builds da = 1 anchor evidence from the live Mocha vectors
// and from synthetic blocks with real proofs. It is for tests only.
package fibrefix

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share/eds"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/celestiaorg/nmt"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/commitment"
)

// vectorPath finds a file under spec/vectors/da from any package directory.
func vectorPath(name string) string {
	dir, err := os.Getwd()
	if err != nil {
		return name
	}
	for {
		p := filepath.Join(dir, "spec", "vectors", "da", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return name
		}
		dir = parent
	}
}

func Unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func Num(t testing.TB, s string) int {
	t.Helper()
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	require.NoError(t, err)
	return n
}

// Live is the PayForFibre at Mocha height 1,402,819 with the archive record
// fields the anchor verifier reads.
type Live struct {
	Ref           commitment.PayloadRef
	ChainID       string
	Height        uint64
	PromiseHeight uint64
	PFFTx         []byte
	Hist          []byte
	PromiseHeader []byte
	PromiseValset []byte
	Header        cmtproto.Header
	Headers       map[uint64][]byte
	HeaderHashes  map[uint64][]byte
	TrustedHeight uint64
	Created       time.Time
	Payload       []byte
	Case          VecCase
	Proof         []byte
}

type certFile struct {
	Live struct {
		Raw struct {
			ChainID    string `json:"chain_id"`
			PFFHeight  string `json:"pff_height"`
			PFFTxHex   string `json:"pff_tx_hex"`
			Historical struct {
				Hex string `json:"hex"`
			} `json:"historical_info"`
			Headers []struct {
				Height string `json:"height"`
				Hex    string `json:"header_hex"`
			} `json:"headers"`
			Valsets []struct {
				Height string `json:"height"`
				Hex    string `json:"hex"`
			} `json:"cometbft_valsets"`
		} `json:"raw"`
		Derived struct {
			Binding struct {
				NamespaceHex  string `json:"namespace_hex"`
				CommitmentHex string `json:"commitment_hex"`
			} `json:"binding"`
			Promise struct {
				Height  string `json:"height"`
				Created string `json:"creation_timestamp"`
			} `json:"promise"`
			HeaderHashes []struct {
				Height string `json:"height"`
				Hash   string `json:"hash_hex"`
			} `json:"header_hashes"`
		} `json:"derived"`
	} `json:"live"`
}

// LoadLive reads the live case from both vector files.
func LoadLive(t testing.TB) *Live {
	t.Helper()
	raw, err := os.ReadFile(vectorPath("fibre_cert.json"))
	require.NoError(t, err)
	var f certFile
	require.NoError(t, json.Unmarshal(raw, &f))
	r := f.Live.Raw
	l := &Live{
		ChainID:       r.ChainID,
		Height:        uint64(Num(t, r.PFFHeight)),
		PromiseHeight: uint64(Num(t, f.Live.Derived.Promise.Height)),
		PFFTx:         Unhex(t, r.PFFTxHex),
		Hist:          Unhex(t, r.Historical.Hex),
		Headers:       map[uint64][]byte{},
		HeaderHashes:  map[uint64][]byte{},
		Payload:       []byte{0x65},
	}
	l.Ref = commitment.PayloadRef{
		DA:         commitment.DAFibre,
		Namespace:  Unhex(t, f.Live.Derived.Binding.NamespaceHex),
		Commitment: Unhex(t, f.Live.Derived.Binding.CommitmentHex),
		Height:     l.Height,
	}
	ts, err := time.Parse(time.RFC3339Nano, f.Live.Derived.Promise.Created)
	require.NoError(t, err)
	l.Created = ts
	for _, h := range r.Headers {
		l.Headers[uint64(Num(t, h.Height))] = Unhex(t, h.Hex)
	}
	for _, h := range f.Live.Derived.HeaderHashes {
		l.HeaderHashes[uint64(Num(t, h.Height))] = Unhex(t, h.Hash)
	}
	l.PromiseHeader = l.Headers[l.PromiseHeight]
	for _, v := range r.Valsets {
		if uint64(Num(t, v.Height)) == l.PromiseHeight {
			l.PromiseValset = Unhex(t, v.Hex)
		}
	}
	require.NotEmpty(t, l.PromiseValset)
	l.TrustedHeight = l.Height
	require.NoError(t, l.Header.Unmarshal(l.Headers[l.Height]))

	v := LoadAnchorVector(t)
	l.Case = v.CaseByID(t, "h1402819")
	l.Proof = Unhex(t, l.Case.Expect.ArchiveProof.Hex)
	return l
}

// Evidence is a fresh record of the live case.
func (l *Live) Evidence(t testing.TB) *archive.EvidenceRecord {
	t.Helper()
	return &archive.EvidenceRecord{
		DA:              commitment.DAFibre,
		Commitment:      bytes.Clone(l.Ref.Commitment),
		Namespace:       bytes.Clone(l.Ref.Namespace),
		Height:          l.Height,
		Header:          SignedHeader(t, l.Header),
		AnchorTx:        bytes.Clone(l.PFFTx),
		AnchorTxIndex:   1,
		TxCode:          0,
		SystemBlob:      SystemBlobOf(t, l.PFFTx),
		SystemBlobProof: bytes.Clone(l.Proof),
		PromiseHeight:   l.PromiseHeight,
		PromiseHeader:   l.promiseSigned(t),
		HistoricalInfo:  bytes.Clone(l.Hist),
	}
}

// promiseSigned is the promise header as the archive stores it, a
// SignedHeader around the bare header.
func (l *Live) promiseSigned(t testing.TB) []byte {
	t.Helper()
	var h cmtproto.Header
	require.NoError(t, h.Unmarshal(l.PromiseHeader))
	return SignedHeader(t, h)
}

// EvidenceFor is the live evidence with the anchor tx and proof of a
// synthetic block; the header keeps everything but the data hash.
func (l *Live) EvidenceFor(t testing.TB, b Block, anchor []byte) *archive.EvidenceRecord {
	t.Helper()
	ev := l.Evidence(t)
	h := l.Header
	h.DataHash = bytes.Clone(b.DataHash)
	ev.Header = SignedHeader(t, h)
	ev.AnchorTx = bytes.Clone(anchor)
	ev.SystemBlob = SystemBlobOf(t, anchor)
	ev.SystemBlobProof = b.Proof(t)
	return ev
}

func SignedHeader(t testing.TB, h cmtproto.Header) []byte {
	t.Helper()
	return BoundSignedHeader(t, h)
}

// SystemBlobOf is the system blob the tx stands for in the square.
func SystemBlobOf(t testing.TB, tx []byte) []byte {
	t.Helper()
	ftx, ok, err := fibretypes.TryParseFibreTx(tx)
	require.NoError(t, err)
	require.True(t, ok)
	b, err := ftx.SystemBlob.Marshal()
	require.NoError(t, err)
	return b
}

// MutateTx rewrites the PayForFibre message of a tx. The owner signature
// covers the promise only, so edits outside it keep it valid.
func MutateTx(t testing.TB, raw []byte, f func(*fibretypes.MsgPayForFibre)) []byte {
	t.Helper()
	var tr cosmostx.TxRaw
	require.NoError(t, tr.Unmarshal(raw))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(tr.BodyBytes))
	require.Len(t, body.Messages, 1)
	var msg fibretypes.MsgPayForFibre
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	f(&msg)
	v, err := msg.Marshal()
	require.NoError(t, err)
	body.Messages[0].Value = v
	tr.BodyBytes, err = body.Marshal()
	require.NoError(t, err)
	out, err := tr.Marshal()
	require.NoError(t, err)
	return out
}

// Block is what a bridge and a consensus node say about one height: the data
// hash of the header, the DAH and the PayForFibre namespace data.
type Block struct {
	DataHash []byte
	Rows     [][]byte
	Cols     [][]byte
	ND       shwap.NamespaceData
}

func (b Block) DAHProto(t testing.TB) []byte {
	t.Helper()
	out, err := (&daproto.DataAvailabilityHeader{RowRoots: b.Rows, ColumnRoots: b.Cols}).Marshal()
	require.NoError(t, err)
	return out
}

func (b Block) Stream(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, err := b.ND.WriteTo(&buf)
	require.NoError(t, err)
	return buf.Bytes()
}

// Proof is the form-1 archive proof of the block.
func (b Block) Proof(t testing.TB) []byte {
	t.Helper()
	return fibreproof.EncodeProof(b.DAHProto(t), b.Stream(t))
}

func (b Block) DAH() *da.DataAvailabilityHeader {
	return &da.DataAvailabilityHeader{RowRoots: b.Rows, ColumnRoots: b.Cols}
}

func (b Block) Clone() Block {
	c := Block{DataHash: bytes.Clone(b.DataHash)}
	for _, r := range b.Rows {
		c.Rows = append(c.Rows, bytes.Clone(r))
	}
	for _, r := range b.Cols {
		c.Cols = append(c.Cols, bytes.Clone(r))
	}
	c.ND = make(shwap.NamespaceData, len(b.ND))
	for i, r := range b.ND {
		c.ND[i].Shares = append([]libshare.Share(nil), r.Shares...)
		if r.Proof != nil {
			p := *r.Proof
			c.ND[i].Proof = &p
		}
	}
	return c
}

// VectorBlock is the block of a live vector case.
func VectorBlock(t testing.TB, c VecCase) Block {
	t.Helper()
	b := Block{DataHash: Unhex(t, c.Raw.DataHash)}
	for _, r := range c.Raw.RowRoots {
		b.Rows = append(b.Rows, Unhex(t, r))
	}
	for _, r := range c.Raw.ColRoots {
		b.Cols = append(b.Cols, Unhex(t, r))
	}
	_, err := b.ND.ReadFrom(bytes.NewReader(Unhex(t, c.Raw.NamespaceD)))
	require.NoError(t, err)
	return b
}

// SplitTxs puts txs in compact shares of the PayForFibre namespace.
func SplitTxs(t testing.TB, txs ...[]byte) []libshare.Share {
	t.Helper()
	css := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
	for _, tx := range txs {
		require.NoError(t, css.WriteTx(tx))
	}
	shares, err := css.Export()
	require.NoError(t, err)
	return shares
}

// BuildBlockFromShares makes a block whose square holds the shares in the
// PayForFibre namespace, followed by tail padding, with real proofs.
func BuildBlockFromShares(t testing.TB, shares []libshare.Share) Block {
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
	return Block{DataHash: roots.Hash(), Rows: roots.RowRoots, Cols: roots.ColumnRoots, ND: nd}
}

func BuildBlock(t testing.TB, txs ...[]byte) Block {
	t.Helper()
	if len(txs) == 0 {
		return BuildBlockFromShares(t, nil)
	}
	return BuildBlockFromShares(t, SplitTxs(t, txs...))
}

type VecQuery struct {
	Description string   `json:"description"`
	Namespace   string   `json:"namespace"`
	Commitment  string   `json:"commitment"`
	ChainID     string   `json:"chain_id"`
	Candidates  []string `json:"candidates"`
	Anchor      string   `json:"anchor"`
}

type VecTx struct {
	Position string `json:"position"`
	SHA256   string `json:"sha256"`
}

type VecCase struct {
	ID  string `json:"id"`
	Raw struct {
		Height     string   `json:"height"`
		DataHash   string   `json:"data_hash"`
		RowRoots   []string `json:"row_roots"`
		ColRoots   []string `json:"column_roots"`
		NamespaceD string   `json:"namespace_data_hex"`
	} `json:"raw"`
	Expect struct {
		Txs          []VecTx    `json:"txs"`
		Queries      []VecQuery `json:"queries"`
		ArchiveProof struct {
			Hex    string `json:"hex"`
			SHA256 string `json:"sha256"`
		} `json:"archive_proof"`
		Sizes struct {
			DAHProto string `json:"dah_proto"`
		} `json:"sizes"`
	} `json:"expect"`
}

type VecOp struct {
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

type VecMutation struct {
	ID     string `json:"id"`
	Case   string `json:"case"`
	Op     VecOp  `json:"op"`
	Expect struct {
		Verdict string `json:"verdict"`
		Fails   string `json:"fails"`
	} `json:"expect"`
}

type VecReassembly struct {
	ID     string   `json:"id"`
	Shares []string `json:"shares_hex"`
	Expect struct {
		Verdict string   `json:"verdict"`
		Fails   string   `json:"fails"`
		TxsSHA  []string `json:"txs_sha256"`
	} `json:"expect"`
}

type AnchorVector struct {
	Live struct {
		Cases []VecCase `json:"cases"`
	} `json:"live"`
	Mutations  []VecMutation   `json:"mutations"`
	Reassembly []VecReassembly `json:"reassembly"`
}

func LoadAnchorVector(t testing.TB) AnchorVector {
	t.Helper()
	raw, err := os.ReadFile(vectorPath("fibre_anchor.json"))
	require.NoError(t, err)
	var v AnchorVector
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Live.Cases)
	require.NotEmpty(t, v.Mutations)
	require.NotEmpty(t, v.Reassembly)
	return v
}

func (v AnchorVector) CaseByID(t testing.TB, id string) VecCase {
	t.Helper()
	for _, c := range v.Live.Cases {
		if c.ID == id {
			return c
		}
	}
	require.FailNow(t, "no such case", id)
	return VecCase{}
}

func flip(b []byte, off int, x byte) []byte {
	out := bytes.Clone(b)
	out[off] ^= x
	return out
}

// ApplyOp edits the block as the vector op says. truncate_stream and
// verify_namespace act on the encoded stream and the checked namespace, so
// they report false.
func ApplyOp(t testing.TB, b Block, op VecOp) (Block, bool) {
	t.Helper()
	b = b.Clone()
	x := byte(0)
	if op.Xor != "" {
		x = Unhex(t, op.Xor)[0]
	}
	rowIdx := func(s string) int {
		if s == "last" {
			return len(b.ND) - 1
		}
		return Num(t, s)
	}
	shareIdx := func(r int, s string) int {
		if s == "last" {
			return len(b.ND[r].Shares) - 1
		}
		return Num(t, s)
	}
	switch op.Kind {
	case "flip":
		switch op.Target {
		case "data_hash":
			b.DataHash = flip(b.DataHash, Num(t, op.Offset), x)
		case "row_root":
			i := Num(t, op.Index)
			b.Rows[i] = flip(b.Rows[i], Num(t, op.Offset), x)
		case "column_root":
			i := Num(t, op.Index)
			b.Cols[i] = flip(b.Cols[i], Num(t, op.Offset), x)
		case "share":
			r := rowIdx(op.Row)
			s := shareIdx(r, op.Share)
			sh, err := libshare.NewShare(flip(b.ND[r].Shares[s].ToBytes(), Num(t, op.Offset), x))
			require.NoError(t, err)
			b.ND[r].Shares[s] = sh
		default:
			require.FailNow(t, "unknown flip target", op.Target)
		}
	case "move_column_root_to_rows":
		b.Rows = append(b.Rows, b.Cols[0])
		b.Cols = b.Cols[1:]
	case "drop_share":
		r := rowIdx(op.Row)
		s := shareIdx(r, op.Share)
		b.ND[r].Shares = append(b.ND[r].Shares[:s:s], b.ND[r].Shares[s+1:]...)
	case "drop_row":
		r := rowIdx(op.Row)
		b.ND = append(b.ND[:r:r], b.ND[r+1:]...)
	case "dup_row":
		r := rowIdx(op.Row)
		b.ND = append(b.ND, b.ND[r])
	case "swap_rows":
		i, j := rowIdx(op.Row), rowIdx(op.Row2)
		b.ND[i], b.ND[j] = b.ND[j], b.ND[i]
	case "set_max_ns_ignored":
		r := rowIdx(op.Row)
		p := b.ND[r].Proof
		var np nmt.Proof
		if p.IsOfAbsence() {
			np = nmt.NewAbsenceProof(p.Start(), p.End(), p.Nodes(), p.LeafHash(), op.Value == "true")
		} else {
			np = nmt.NewInclusionProof(p.Start(), p.End(), p.Nodes(), op.Value == "true")
		}
		b.ND[r].Proof = &np
	case "truncate_stream", "verify_namespace":
		return b, false
	default:
		require.FailNow(t, "unknown op", op.Kind)
	}
	return b, true
}
