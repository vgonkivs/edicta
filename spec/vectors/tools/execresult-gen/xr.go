package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	libshare "github.com/celestiaorg/go-square/v4/share"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
)

type vectorFile struct {
	Upstream section    `json:"upstream"`
	Cases    []caseDoc  `json:"cases"`
	Records  []recordIn `json:"records"`
}

type recordIn struct {
	ID            string `json:"id"`
	RecordCBORHex string `json:"record_cbor_hex"`
}

type caseDoc struct {
	ID            string            `json:"id"`
	RecordCBORHex string            `json:"record_cbor_hex"`
	Trusted       map[string]string `json:"trusted"`
	Query         struct {
		ChainID string `json:"chain_id"`
		RailRef string `json:"rail_ref"`
	} `json:"query"`
	Expect outcome `json:"expect"`
}

type outcome struct {
	Result string            `json:"result"`
	Rule   string            `json:"rule"`
	Reason string            `json:"reason"`
	Facts  map[string]string `json:"facts,omitempty"`
}

// record holds the fields of a kind 19 record. The Python checker owns
// strict decoding; this reader only takes the map apart.
type record struct {
	u map[uint64]uint64
	b map[uint64][]byte
	s map[uint64]string
}

func decodeRecord(raw []byte) (record, error) {
	r := record{u: map[uint64]uint64{}, b: map[uint64][]byte{}, s: map[uint64]string{}}
	i := 0
	head := func() (byte, uint64, error) {
		if i >= len(raw) {
			return 0, 0, errors.New("truncated")
		}
		ib := raw[i]
		i++
		major, ai := ib>>5, uint64(ib&0x1f)
		if ai < 24 {
			return major, ai, nil
		}
		if ai > 27 {
			return 0, 0, errors.New("unsupported head")
		}
		n := 1 << (ai - 24)
		if i+n > len(raw) {
			return 0, 0, errors.New("truncated")
		}
		var v uint64
		for _, c := range raw[i : i+n] {
			v = v<<8 | uint64(c)
		}
		i += n
		return major, v, nil
	}
	major, n, err := head()
	if err != nil || major != 5 {
		return r, errors.New("not a map")
	}
	for range n {
		km, k, err := head()
		if err != nil || km != 0 {
			return r, errors.New("key")
		}
		vm, v, err := head()
		if err != nil {
			return r, err
		}
		switch vm {
		case 0:
			r.u[k] = v
		case 2, 3:
			if uint64(len(raw)-i) < v {
				return r, errors.New("truncated string")
			}
			if vm == 2 {
				r.b[k] = raw[i : i+int(v)]
			} else {
				r.s[k] = string(raw[i : i+int(v)])
			}
			i += int(v)
		default:
			return r, errors.New("value type")
		}
	}
	if i != len(raw) {
		return r, errors.New("trailing data")
	}
	return r, nil
}

type xrFail struct{ rule, reason, why string }

func (f xrFail) Error() string { return f.rule + " (" + f.reason + "): " + f.why }

func fail(rule, reason, format string, a ...any) error {
	return xrFail{rule, reason, fmt.Sprintf(format, a...)}
}

func parseHeader(b []byte) (core.Header, error) {
	var p cmtproto.Header
	if err := p.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	h, err := core.HeaderFromProto(&p)
	if err != nil {
		return core.Header{}, err
	}
	return h, h.ValidateBasic()
}

// squareWidth is k from a row proof total of 4k (row and column roots of
// the extended square).
func squareWidth(sp proof.ShareProof) int {
	if sp.RowProof == nil || len(sp.RowProof.Proofs) == 0 || sp.RowProof.Proofs[0] == nil {
		return 0
	}
	t := sp.RowProof.Proofs[0].Total
	if t < 4 || t%4 != 0 {
		return 0
	}
	k := t / 4
	if k&(k-1) != 0 {
		return 0
	}
	return int(k)
}

// span returns the shares [start, end) of the original square the proof
// covers, row by row, or false if its rows are not consecutive rows of the
// original square.
func span(sp proof.ShareProof, k int) (int, int, bool) {
	rp := sp.RowProof
	rows := len(rp.RowRoots)
	if k == 0 || rows == 0 || len(rp.Proofs) != rows || len(sp.ShareProofs) != rows || int(rp.EndRow)-int(rp.StartRow)+1 != rows {
		return 0, 0, false
	}
	for i, p := range rp.Proofs {
		if p == nil || p.Total != int64(4*k) || p.Index != int64(rp.StartRow)+int64(i) || p.Index >= int64(k) {
			return 0, 0, false
		}
	}
	for i, p := range sp.ShareProofs {
		if p == nil || p.Start < 0 || p.End <= p.Start || int(p.End) > k {
			return 0, 0, false
		}
		if i > 0 && p.Start != 0 || i < rows-1 && int(p.End) != k {
			return 0, 0, false
		}
	}
	start := int(rp.StartRow)*k + int(sp.ShareProofs[0].Start)
	end := int(rp.EndRow)*k + int(sp.ShareProofs[rows-1].End)
	return start, end, true
}

func compactShares(seqLen int) int {
	if seqLen <= libshare.FirstCompactShareContentSize {
		return 1
	}
	rest := seqLen - libshare.FirstCompactShareContentSize
	return 1 + (rest+libshare.ContinuationCompactShareContentSize-1)/libshare.ContinuationCompactShareContentSize
}

var keyNamespace = map[uint64]libshare.Namespace{9: libshare.TxNamespace, 10: libshare.PayForBlobNamespace, 11: libshare.PayForFibreNamespace}

// xr runs the XR rules of core 20.2.2 on one record.
func xr(c caseDoc) (map[string]string, error) {
	raw, err := hex.DecodeString(c.RecordCBORHex)
	if err != nil {
		return nil, err
	}
	r, err := decodeRecord(raw)
	if err != nil {
		return nil, fail("XR1", "tx_proof_invalid", "record: %v", err)
	}
	railRef, err := hex.DecodeString(c.Query.RailRef)
	if err != nil {
		return nil, err
	}
	if r.s[3] != c.Query.ChainID || !bytes.Equal(r.b[4], railRef) {
		return nil, fail("XR1", "tx_proof_invalid", "the record carries another key")
	}
	height, txIndex, total := r.u[5], r.u[6], r.u[14]

	// XR2
	h, err := parseHeader(r.b[7])
	if err != nil || uint64(h.Height) != height || h.ChainID != r.s[3] {
		return nil, fail("XR2", "tx_proof_invalid", "header does not decode as the header at height")
	}
	next, err := parseHeader(r.b[8])
	if err != nil || uint64(next.Height) != height+1 || next.ChainID != r.s[3] {
		return nil, fail("XR2", "tx_proof_invalid", "next_header does not decode as the header at height + 1")
	}
	for _, x := range []core.Header{h, next} {
		want, ok := c.Trusted[strconv.FormatInt(x.Height, 10)]
		if !ok {
			return nil, fail("XR2", "result_header_unreachable", "no trusted hash at %d", x.Height)
		}
		if hex.EncodeToString(x.Hash()) != want {
			return nil, fail("XR2", "header_not_linking", "header at %d is not on the trusted chain", x.Height)
		}
	}

	// XR3
	if h.Version.App != appconsts.Version {
		return nil, fail("XR3", "result_index_unbound", "app version %d", h.Version.App)
	}

	// XR4 and XR5
	keys := []uint64{9, 10, 11, 12}
	end, counts := 0, map[uint64]int{}
	var txUnits [][]byte
	var k int
	closed := false
	for _, key := range keys {
		pb, ok := r.b[key]
		if !ok {
			continue
		}
		var sp proof.ShareProof
		if err := sp.Unmarshal(pb); err != nil {
			return nil, fail("XR4", "tx_proof_invalid", "key %d: %v", key, err)
		}
		ns, err := libshare.NewNamespace(uint8(sp.NamespaceVersion), sp.NamespaceId)
		if err != nil {
			return nil, fail("XR4", "tx_proof_invalid", "key %d namespace", key)
		}
		if want, isTx := keyNamespace[key]; isTx && !ns.Equals(want) || !isTx && !libshare.PayForFibreNamespace.IsLessThan(ns) {
			return nil, fail("XR4", "tx_proof_invalid", "key %d: namespace %x", key, ns.Bytes())
		}
		kw := squareWidth(sp)
		s, e, ok := span(sp, kw)
		if !ok || len(sp.Data) != e-s {
			return nil, fail("XR4", "tx_proof_invalid", "key %d does not prove consecutive shares of the original square", key)
		}
		if err := sp.Validate(h.DataHash); err != nil {
			return nil, fail("XR4", "tx_proof_invalid", "key %d: %v", key, err)
		}
		shares, err := libshare.FromBytes(sp.Data)
		if err != nil {
			return nil, fail("XR4", "tx_proof_invalid", "key %d shares: %v", key, err)
		}
		for _, sh := range shares {
			if !sh.Namespace().Equals(ns) {
				return nil, fail("XR4", "tx_proof_invalid", "key %d holds a share of another namespace", key)
			}
		}
		if k != 0 && kw != k {
			return nil, fail("XR4", "tx_proof_invalid", "key %d: another square width", key)
		}
		k = kw
		if s != end {
			return nil, fail("XR5", "tx_proof_invalid", "key %d starts at share %d, the previous range ends at %d", key, s, end)
		}
		end = e
		if key == 12 {
			if e-s != 1 {
				return nil, fail("XR5", "tx_proof_invalid", "the closing proof covers %d shares", e-s)
			}
			closed = true
			continue
		}
		if !shares[0].IsSequenceStart() || compactShares(int(shares[0].SequenceLen())) != len(shares) {
			return nil, fail("XR5", "tx_proof_invalid", "key %d is not one whole compact sequence", key)
		}
		for _, sh := range shares[1:] {
			if sh.IsSequenceStart() {
				return nil, fail("XR5", "tx_proof_invalid", "key %d: a second sequence", key)
			}
		}
		units, err := libshare.ParseTxs(shares)
		if err != nil {
			return nil, fail("XR5", "tx_proof_invalid", "key %d units: %v", key, err)
		}
		counts[key] = len(units)
		if key == 9 {
			txUnits = units
		}
	}
	if _, ok := r.b[9]; !ok {
		return nil, fail("XR5", "tx_proof_invalid", "no transaction namespace proof")
	}
	if !closed && end != k*k {
		return nil, fail("XR5", "tx_proof_invalid", "the transaction namespaces end at share %d, neither a closing share nor the square's end %d", end, k*k)
	}

	// XR6
	sum := 0
	for _, n := range counts {
		sum += n
	}
	if uint64(sum) != total {
		return nil, fail("XR6", "result_index_unbound", "%d txs in the transaction namespaces, results_total %d", sum, total)
	}

	// XR7
	at, found := -1, 0
	for j, u := range txUnits {
		if s := sha256.Sum256(u); bytes.Equal(s[:], railRef) {
			at, found = j, found+1
		}
	}
	if found != 1 {
		return nil, fail("XR7", "tx_hash_mismatch", "%d ordinary txs hash to rail_ref", found)
	}
	if uint64(at) != txIndex || txIndex >= total {
		return nil, fail("XR7", "result_index_unbound", "the tx is unit %d, tx_index %d", at, txIndex)
	}

	// XR8
	leaf := r.b[13]
	var res abci.ExecTxResult
	if err := res.Unmarshal(leaf); err != nil {
		return nil, fail("XR8", "results_root_mismatch", "result: %v", err)
	}
	det := abci.ExecTxResult{Code: res.Code, Data: res.Data, GasWanted: res.GasWanted, GasUsed: res.GasUsed}
	again, err := det.Marshal()
	if err != nil || !bytes.Equal(again, leaf) {
		return nil, fail("XR8", "results_root_mismatch", "result is not the deterministic leaf")
	}
	path := r.b[15]
	if len(path)%32 != 0 {
		return nil, fail("XR8", "results_root_mismatch", "result_path length")
	}
	var aunts [][]byte
	for i := 0; i < len(path); i += 32 {
		aunts = append(aunts, path[i:i+32])
	}
	lh := sha256.Sum256(append([]byte{0}, leaf...))
	mp := merkle.Proof{Total: int64(total), Index: int64(txIndex), LeafHash: lh[:], Aunts: aunts}
	if err := mp.Verify(next.LastResultsHash, leaf); err != nil {
		return nil, fail("XR8", "results_root_mismatch", "%v", err)
	}
	outcome := "success"
	if res.Code != 0 {
		outcome = "failure"
	}
	return map[string]string{
		"height":      strconv.FormatUint(height, 10),
		"header_hash": hex.EncodeToString(h.Hash()),
		"tx_index":    strconv.FormatUint(txIndex, 10),
		"tx_hex":      hex.EncodeToString(txUnits[at]),
		"inclusion":   "proven",
		"result":      "proven",
		"code":        strconv.FormatUint(uint64(res.Code), 10),
		"outcome":     outcome,
	}, nil
}

func checkCases(f vectorFile) (int, error) {
	if len(f.Cases) == 0 {
		return 0, errors.New("no cases")
	}
	rules := map[string]bool{}
	for _, c := range f.Cases {
		facts, err := xr(c)
		got := outcome{Result: "pass", Rule: "none", Reason: "none", Facts: facts}
		var xf xrFail
		switch {
		case errors.As(err, &xf):
			got = outcome{Result: "set_aside", Rule: xf.rule, Reason: xf.reason}
		case err != nil:
			return 0, fmt.Errorf("%s: %w", c.ID, err)
		}
		if !reflect.DeepEqual(got, c.Expect) {
			return 0, fmt.Errorf("%s: upstream gives %+v (%v), the file expects %+v", c.ID, got, err, c.Expect)
		}
		rules[got.Rule] = true
	}
	var seen []string
	for r := range rules {
		seen = append(seen, r)
	}
	sort.Strings(seen)
	want := []string{"XR1", "XR2", "XR3", "XR4", "XR5", "XR6", "XR7", "XR8", "none"}
	if !reflect.DeepEqual(seen, want) {
		return 0, fmt.Errorf("cases cover the rules %v, want %v", seen, want)
	}
	return len(f.Cases), nil
}
