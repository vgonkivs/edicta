package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share/shwap"
	square "github.com/celestiaorg/go-square/v4"
	libshare "github.com/celestiaorg/go-square/v4/share"
	blobtx "github.com/celestiaorg/go-square/v4/tx"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
)

const chainID = "mocha-5"

type inputs struct {
	liveTx     []byte
	liveResult abci.ExecTxResult
	pffTx      []byte
}

// section is the part of the vector file this tool owns; the Python
// generator embeds it as "upstream".
type section struct {
	Pins   map[string]string `json:"pins"`
	Inputs map[string]string `json:"inputs"`
	Blocks []blockDoc        `json:"blocks"`
}

type txDoc struct {
	Hex   string `json:"hex"`
	Class string `json:"class"`
}

type resultDoc struct {
	Code      string `json:"code"`
	DataHex   string `json:"data_hex"`
	GasWanted string `json:"gas_wanted"`
	GasUsed   string `json:"gas_used"`
	LeafHex   string `json:"leaf_hex"`
}

type proofDoc struct {
	Key          string `json:"key"`
	NamespaceHex string `json:"namespace_hex"`
	Start        string `json:"start"`
	End          string `json:"end"`
	ProofHex     string `json:"proof_hex"`
}

// variantDoc is a share proof of the block that is not part of its record:
// a sub-range of a namespace or a range across two shares, so the XR cases
// can swap it in and exercise a branch that a record built from a whole
// block never reaches.
type variantDoc struct {
	ID           string `json:"id"`
	NamespaceHex string `json:"namespace_hex"`
	Start        string `json:"start"`
	End          string `json:"end"`
	ProofHex     string `json:"proof_hex"`
}

type captureDoc struct {
	TxIndex       string `json:"tx_index"`
	RailRef       string `json:"rail_ref"`
	ResultsTotal  string `json:"results_total"`
	ResultPathHex string `json:"result_path_hex"`
}

type blockDoc struct {
	ID                string       `json:"id"`
	Description       string       `json:"description"`
	ChainID           string       `json:"chain_id"`
	Height            string       `json:"height"`
	SquareSize        string       `json:"square_size"`
	Txs               []txDoc      `json:"txs"`
	Results           []resultDoc  `json:"results"`
	ResultsRootHex    string       `json:"results_root_hex"`
	DataHashHex       string       `json:"data_hash_hex"`
	HeaderHex         string       `json:"header_hex"`
	HeaderHashHex     string       `json:"header_hash_hex"`
	NextHeaderHex     string       `json:"next_header_hex"`
	NextHeaderHashHex string       `json:"next_header_hash_hex"`
	Proofs            []proofDoc   `json:"proofs"`
	Variants          []variantDoc `json:"variants,omitempty"`
	Captures          []captureDoc `json:"captures"`
	Negative          bool         `json:"negative,omitempty"`
}

type variantSpec struct {
	id         string
	ns         libshare.Namespace
	start, end int
}

type blockSpec struct {
	id, description string
	height          int64
	txs             [][]byte
	results         []abci.ExecTxResult
	captures        []int
	variants        []variantSpec
	// negative blocks feed failing XR cases and the migration conflict only;
	// their captures are not records of the vector file.
	negative bool
	// mutate changes the square after Construct, before it is extended, to
	// build a layout go-square never produces.
	mutate func([]libshare.Share) error
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// fixed gives n deterministic bytes for a label, so the synthetic txs and
// header fields never change between runs.
func fixed(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		s := sha256.Sum256([]byte("edicta/v1.1 execresult vectors|" + label + "|" + strconv.Itoa(i)))
		out = append(out, s[:]...)
	}
	return out[:n]
}

func loadInputs(vectors string) (inputs, error) {
	var eo struct {
		Live struct {
			TxHex string `json:"tx_hex"`
		} `json:"live"`
		ResultProof struct {
			Results []struct {
				Code      string `json:"code"`
				Data      string `json:"data"`
				GasWanted string `json:"gas_wanted"`
				GasUsed   string `json:"gas_used"`
			} `json:"results"`
		} `json:"result_proof"`
	}
	if err := readJSON(filepath.Join(vectors, "verifier", "execution_outcomes.json"), &eo); err != nil {
		return inputs{}, err
	}
	tx, err := hex.DecodeString(eo.Live.TxHex)
	if err != nil || len(eo.ResultProof.Results) == 0 {
		return inputs{}, fmt.Errorf("execution_outcomes.json: live tx or results")
	}
	r0 := eo.ResultProof.Results[0]
	data, err := base64.StdEncoding.DecodeString(r0.Data)
	if err != nil {
		return inputs{}, err
	}
	code, err1 := strconv.ParseUint(r0.Code, 10, 32)
	gw, err2 := strconv.ParseInt(r0.GasWanted, 10, 64)
	gu, err3 := strconv.ParseInt(r0.GasUsed, 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return inputs{}, fmt.Errorf("execution_outcomes.json: result 0")
	}

	var fa struct {
		Live struct {
			Cases []struct {
				Raw struct {
					NamespaceDataHex string `json:"namespace_data_hex"`
				} `json:"raw"`
			} `json:"cases"`
		} `json:"live"`
	}
	if err := readJSON(filepath.Join(vectors, "da", "fibre_anchor.json"), &fa); err != nil {
		return inputs{}, err
	}
	if len(fa.Live.Cases) == 0 {
		return inputs{}, fmt.Errorf("fibre_anchor.json: no live case")
	}
	nsd, err := hex.DecodeString(fa.Live.Cases[0].Raw.NamespaceDataHex)
	if err != nil {
		return inputs{}, err
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(nsd)); err != nil {
		return inputs{}, fmt.Errorf("fibre_anchor.json namespace data: %w", err)
	}
	units, err := libshare.ParseTxs(nd.Flatten())
	if err != nil || len(units) == 0 {
		return inputs{}, fmt.Errorf("fibre_anchor.json: no PFF unit")
	}
	return inputs{
		liveTx:     tx,
		liveResult: abci.ExecTxResult{Code: uint32(code), Data: data, GasWanted: gw, GasUsed: gu},
		pffTx:      units[0],
	}, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func blobTx(label string, size int) ([]byte, error) {
	b, err := libshare.NewV0Blob(libshare.MustNewV0Namespace([]byte("edicta-x19")), fixed(label+" blob", size))
	if err != nil {
		return nil, err
	}
	return blobtx.MarshalBlobTx(fixed(label+" inner tx", 120), b)
}

func specs(in inputs) ([]blockSpec, error) {
	b1, err := blobTx("three_namespaces", 700)
	if err != nil {
		return nil, err
	}
	b3, err := blobTx("tx_then_blob", 900)
	if err != nil {
		return nil, err
	}
	return []blockSpec{
		{
			id: "three_namespaces",
			description: "Two ordinary txs (the live bank-send tx first), a blob tx and the live PayForFibre tx: " +
				"proofs of TX_NS, PFB_NS and PFF_NS plus the closing share.",
			height:   4300000,
			txs:      [][]byte{in.liveTx, fixed("ordinary B", 300), b1, in.pffTx},
			results:  []abci.ExecTxResult{in.liveResult, {Code: 5, GasWanted: 100000, GasUsed: 52000}, {GasWanted: 80000, GasUsed: 65000}, {GasWanted: 90000, GasUsed: 70000}},
			captures: []int{0, 1},
			variants: []variantSpec{
				{"tx_from_share_1", libshare.TxNamespace, 1, 2},
				{"tx_first_share_only", libshare.TxNamespace, 0, 1},
			},
		},
		{
			id:          "single_share_square",
			description: "One small ordinary tx in a 1 x 1 square: the transaction namespace ends the square, so there is no closing share.",
			height:      4300010,
			txs:         [][]byte{fixed("ordinary C", 100)},
			results:     []abci.ExecTxResult{{Data: []byte{0x0a, 0x01, 0xff}, GasWanted: 50000, GasUsed: 41000}},
			captures:    []int{0},
		},
		{
			id:          "tx_then_blob",
			description: "One ordinary tx and one blob tx, no Fibre tx: proofs of TX_NS and PFB_NS plus the closing share; key 11 absent.",
			height:      4300020,
			txs:         [][]byte{fixed("ordinary D", 260), b3},
			results:     []abci.ExecTxResult{{GasWanted: 70000, GasUsed: 60000}, {Code: 11, GasWanted: 90000, GasUsed: 90001}},
			captures:    []int{0},
			variants:    []variantSpec{{"closing_two_shares", libshare.Namespace{}, 2, 4}},
		},
		{
			id: "duplicate_ordinary",
			description: "The same ordinary tx twice: two units of TX_NS hash to its rail_ref, so the record cannot bind " +
				"the index (negative block).",
			height:   4300030,
			txs:      [][]byte{fixed("ordinary E", 200), fixed("ordinary E", 200)},
			results:  []abci.ExecTxResult{{GasWanted: 60000, GasUsed: 50000}, {Code: 32, GasWanted: 60000, GasUsed: 30000}},
			captures: []int{0},
			negative: true,
		},
		{
			id: "second_sequence_start",
			description: "Two ordinary txs in two TX_NS shares, with the sequence-start bit set on the second share " +
				"after Construct: the namespace holds a second sequence start (negative block, a layout go-square " +
				"never builds).",
			height:   4300040,
			txs:      [][]byte{fixed("ordinary F", 300), fixed("ordinary G", 300)},
			results:  []abci.ExecTxResult{{GasWanted: 70000, GasUsed: 61000}, {GasWanted: 70000, GasUsed: 62000}},
			captures: []int{0},
			negative: true,
			mutate: func(sq []libshare.Share) error {
				if len(sq) < 2 || !sq[1].Namespace().Equals(libshare.TxNamespace) {
					return fmt.Errorf("second_sequence_start: share 1 is not in TX_NS")
				}
				b := append([]byte(nil), sq[1].ToBytes()...)
				b[libshare.NamespaceSize] |= 1
				sh, err := libshare.NewShare(b)
				if err != nil {
					return err
				}
				sq[1] = sh
				return nil
			},
		},
		{
			id: "squat_three_namespaces",
			description: "A forgery of block three_namespaces: same chain id and height, the live bank-send tx alone " +
				"with result code 13, fabricated headers that link to each other. Self-consistent, so it passes the " +
				"gate's self-check without a trust root (MG3), but not the trusted chain (negative block; the " +
				"migration's squatted key).",
			height:   4300000,
			txs:      [][]byte{in.liveTx},
			results:  []abci.ExecTxResult{{Code: 13, GasWanted: 100000, GasUsed: 40000}},
			captures: []int{0},
			negative: true,
		},
	}, nil
}

func header(height int64, dataHash, lastResults, lastBlock []byte) core.Header {
	label := "h" + itoa(height)
	return core.Header{
		Version: cmtversion.Consensus{Block: 11, App: appconsts.Version},
		ChainID: chainID,
		Height:  height,
		Time:    time.Unix(1792000000+height*6, 123456789).UTC(),
		LastBlockID: core.BlockID{
			Hash:          lastBlock,
			PartSetHeader: core.PartSetHeader{Total: 1, Hash: fixed(label+" parts", 32)},
		},
		LastCommitHash:     fixed(label+" last commit", 32),
		DataHash:           dataHash,
		ValidatorsHash:     fixed("validators", 32),
		NextValidatorsHash: fixed("validators", 32),
		ConsensusHash:      fixed("consensus", 32),
		AppHash:            fixed(label+" app", 32),
		LastResultsHash:    lastResults,
		EvidenceHash:       fixed("evidence", 32),
		ProposerAddress:    fixed("proposer", 20),
	}
}

func headerProto(h core.Header) ([]byte, error) {
	p := h.ToProto()
	return p.Marshal()
}

var txNamespaces = []struct {
	key string
	ns  libshare.Namespace
}{{"9", libshare.TxNamespace}, {"10", libshare.PayForBlobNamespace}, {"11", libshare.PayForFibreNamespace}}

func buildBlock(s blockSpec) (blockDoc, error) {
	classified, err := fibretypes.ClassifyTxs(s.txs)
	if err != nil {
		return blockDoc{}, err
	}
	sq, err := square.Construct(classified, appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold)
	if err != nil {
		return blockDoc{}, err
	}
	if s.mutate != nil {
		if err := s.mutate(sq); err != nil {
			return blockDoc{}, err
		}
	}
	eds, err := da.ExtendShares(libshare.ToBytes(sq))
	if err != nil {
		return blockDoc{}, err
	}
	dah, err := da.NewDataAvailabilityHeader(eds)
	if err != nil {
		return blockDoc{}, err
	}
	k, err := square.Size(len(sq))
	if err != nil {
		return blockDoc{}, err
	}

	d := blockDoc{ID: s.id, Description: s.description, ChainID: chainID, Height: itoa(s.height), SquareSize: itoa(int64(k)), DataHashHex: hx(dah.Hash()), Negative: s.negative}
	for i, c := range classified {
		class := "ordinary"
		if c.FibreTx != nil {
			class = "fibre"
		} else if _, isBlob, _ := blobtx.UnmarshalBlobTx(c.Bytes); isBlob {
			class = "blob"
		}
		d.Txs = append(d.Txs, txDoc{Hex: hx(s.txs[i]), Class: class})
	}

	ptrs := make([]*abci.ExecTxResult, len(s.results))
	for i := range s.results {
		ptrs[i] = &s.results[i]
	}
	results := core.NewResults(ptrs)
	for i, r := range s.results {
		leaf, err := results[i].Marshal()
		if err != nil {
			return blockDoc{}, err
		}
		d.Results = append(d.Results, resultDoc{Code: itoa(int64(r.Code)), DataHex: hx(r.Data), GasWanted: itoa(r.GasWanted), GasUsed: itoa(r.GasUsed), LeafHex: hx(leaf)})
	}
	d.ResultsRootHex = hx(results.Hash())

	h := header(s.height, dah.Hash(), fixed("h"+itoa(s.height)+" last results", 32), fixed("h"+itoa(s.height)+" last block", 32))
	next := header(s.height+1, fixed("h"+itoa(s.height+1)+" data", 32), results.Hash(), h.Hash())
	hb, err := headerProto(h)
	if err != nil {
		return blockDoc{}, err
	}
	nb, err := headerProto(next)
	if err != nil {
		return blockDoc{}, err
	}
	d.HeaderHex, d.HeaderHashHex, d.NextHeaderHex, d.NextHeaderHashHex = hx(hb), hx(h.Hash()), hx(nb), hx(next.Hash())

	end := 0
	add := func(key string, ns libshare.Namespace, r libshare.Range) error {
		sp, err := proof.NewShareInclusionProofFromEDS(eds, ns, r)
		if err != nil {
			return err
		}
		if err := sp.Validate(dah.Hash()); err != nil {
			return fmt.Errorf("%s: proof of key %s: %w", s.id, key, err)
		}
		raw, err := sp.Marshal()
		if err != nil {
			return err
		}
		d.Proofs = append(d.Proofs, proofDoc{Key: key, NamespaceHex: hx(ns.Bytes()), Start: itoa(int64(r.Start)), End: itoa(int64(r.End)), ProofHex: hx(raw)})
		return nil
	}
	for _, t := range txNamespaces {
		r := libshare.GetShareRangeForNamespace(sq, t.ns)
		if r.IsEmpty() {
			continue
		}
		if r.Start != end {
			return blockDoc{}, fmt.Errorf("%s: namespace %x starts at %d, not %d", s.id, t.ns.Bytes(), r.Start, end)
		}
		if err := add(t.key, t.ns, r); err != nil {
			return blockDoc{}, err
		}
		end = r.End
	}
	if end < len(sq) {
		if err := add("12", sq[end].Namespace(), libshare.NewRange(end, end+1)); err != nil {
			return blockDoc{}, err
		}
	}

	for _, v := range s.variants {
		ns := v.ns
		if ns.Equals(libshare.Namespace{}) {
			ns = sq[v.start].Namespace()
		}
		r := libshare.NewRange(v.start, v.end)
		for i := v.start; i < v.end; i++ {
			if i >= len(sq) || !sq[i].Namespace().Equals(ns) {
				return blockDoc{}, fmt.Errorf("%s: variant %s: share %d is not in namespace %x", s.id, v.id, i, ns.Bytes())
			}
		}
		sp, err := proof.NewShareInclusionProofFromEDS(eds, ns, r)
		if err != nil {
			return blockDoc{}, fmt.Errorf("%s: variant %s: %w", s.id, v.id, err)
		}
		if err := sp.Validate(dah.Hash()); err != nil {
			return blockDoc{}, fmt.Errorf("%s: variant %s: %w", s.id, v.id, err)
		}
		raw, err := sp.Marshal()
		if err != nil {
			return blockDoc{}, err
		}
		d.Variants = append(d.Variants, variantDoc{ID: v.id, NamespaceHex: hx(ns.Bytes()), Start: itoa(int64(v.start)), End: itoa(int64(v.end)), ProofHex: hx(raw)})
	}

	for _, i := range s.captures {
		if d.Txs[i].Class != "ordinary" {
			return blockDoc{}, fmt.Errorf("%s: capture of a %s tx", s.id, d.Txs[i].Class)
		}
		p := results.ProveResult(i)
		if err := p.Verify(results.Hash(), mustHex(d.Results[i].LeafHex)); err != nil {
			return blockDoc{}, err
		}
		var path []byte
		for _, a := range p.Aunts {
			path = append(path, a...)
		}
		ref := sha256.Sum256(s.txs[i])
		d.Captures = append(d.Captures, captureDoc{TxIndex: itoa(int64(i)), RailRef: hx(ref[:]), ResultsTotal: itoa(p.Total), ResultPathHex: hx(path)})
	}
	return d, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func build(in inputs) (section, error) {
	ss, err := specs(in)
	if err != nil {
		return section{}, err
	}
	sec := section{
		Pins: map[string]string{
			"celestia-app":  "github.com/celestiaorg/celestia-app/v10 v10.4.0-mocha (x/fibre/types ClassifyTxs, pkg/da ExtendShares and NewDataAvailabilityHeader, pkg/proof NewShareInclusionProofFromEDS and ShareProof, pkg/appconsts Version, SquareSizeUpperBound, SubtreeRootThreshold)",
			"celestia-core": "github.com/celestiaorg/celestia-core v0.42.0 as github.com/cometbft/cometbft (types.Header ToProto and Hash, types.NewResults Hash and ProveResult, crypto/merkle Proof.Verify)",
			"go-square":     "github.com/celestiaorg/go-square/v4 v4.0.1 (Construct, GetShareRangeForNamespace, ParseTxs, tx.MarshalBlobTx)",
			"celestia-node": "github.com/celestiaorg/celestia-node v0.34.2-mocha (shwap.NamespaceData, to read the live PFF)",
		},
		Inputs: map[string]string{
			"live_tx":     "verifier/execution_outcomes.json live.tx_hex, its result result_proof.results[0]",
			"pff_tx":      "the first PayForFibre unit of da/fibre_anchor.json live.cases[0].raw.namespace_data_hex",
			"synthetic":   "every other tx, header field and result is fixed bytes (SHA-256 of a label), so a rebuild gives the same section",
			"app_version": strconv.FormatUint(appconsts.Version, 10),
		},
	}
	for _, s := range ss {
		d, err := buildBlock(s)
		if err != nil {
			return section{}, err
		}
		sec.Blocks = append(sec.Blocks, d)
	}
	return sec, nil
}
