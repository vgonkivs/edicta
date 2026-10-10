package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/celestia-node/share/shwap"
	"github.com/celestiaorg/go-square/v4/inclusion"
	libshare "github.com/celestiaorg/go-square/v4/share"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
)

// The tail rule binds a candidate's result index only on blocks of this app
// version; the protocol pins it, so it is not imported.
const pinnedAppVersion = 10

// The share commitment threshold the app passes to CreateCommitment.
const subtreeRootThreshold = 64

const kindAbsence = 14

// The archive record format of the kind 14 record.
const recordFormat = 1

var pffNS = libshare.PayForFibreNamespace

type liveDoc struct {
	Live     []liveCase `json:"live"`
	Source   liveSource `json:"live_source"`
	TailRule tailRule   `json:"live_tail_rule"`
}

type liveSource struct {
	FetchedAt string            `json:"fetched_at"`
	ChainID   string            `json:"chain_id"`
	Generator string            `json:"generator"`
	Upstream  map[string]string `json:"upstream"`
	Endpoints map[string]string `json:"endpoints"`
	Note      string            `json:"note"`
	Reads     []sourceRead      `json:"reads"`
}

type sourceRead struct {
	What     string `json:"what"`
	Endpoint string `json:"endpoint"`
	Heights  string `json:"heights"`
}

type queryDoc struct {
	DA             string `json:"da"`
	Namespace      string `json:"namespace"`
	Commitment     string `json:"commitment"`
	Signer         string `json:"signer,omitempty"`
	ChainID        string `json:"chain_id"`
	H0             string `json:"h0"`
	AnchorDeadline string `json:"anchor_deadline"`
}

type liveCase struct {
	ID             string            `json:"id"`
	Description    string            `json:"description"`
	Query          queryDoc          `json:"query"`
	TrustedHeaders map[string]string `json:"trusted_headers"`
	Records        []recordDoc       `json:"records"`
	Expect         expectDoc         `json:"expect"`
}

type recordDoc struct {
	Height    string `json:"height"`
	RecordHex string `json:"record_hex"`
	SHA256    string `json:"sha256"`
	Size      string `json:"size"`
}

type expectDoc struct {
	Heights []heightDoc `json:"heights"`
	Window  windowDoc   `json:"window"`
}

type heightDoc struct {
	Height     string    `json:"height"`
	Result     string    `json:"result"`
	Rule       string    `json:"rule"`
	Why        string    `json:"why"`
	Rows       []string  `json:"rows,omitempty"`
	PFFTxs     string    `json:"pff_txs,omitempty"`
	Candidates []candDoc `json:"candidates,omitempty"`
	Blobs      []blobDoc `json:"blobs,omitempty"`
}

type candDoc struct {
	Position    string `json:"position"`
	ResultIndex string `json:"result_index,omitempty"`
	Code        string `json:"code"`
}

type blobDoc struct {
	ShareVersion string `json:"share_version"`
	Signer       string `json:"signer,omitempty"`
	Commitment   string `json:"commitment,omitempty"`
}

type windowDoc struct {
	Result        string `json:"result"`
	AnchorHeight  string `json:"anchor_height,omitempty"`
	FirstUnproven string `json:"first_unproven,omitempty"`
}

type tailRule struct {
	Description string      `json:"description"`
	Blocks      []tailBlock `json:"blocks"`
}

type tailBlock struct {
	Height    string   `json:"height"`
	Case      string   `json:"case"`
	AppVer    string   `json:"app_version"`
	Txs       []tailTx `json:"txs"`
	FibreFrom string   `json:"fibre_from"`
	Construct string   `json:"construct_check"`
}

type tailTx struct {
	Index  string `json:"index"`
	Class  string `json:"class"`
	Size   string `json:"size"`
	SHA256 string `json:"sha256"`
}

// parts are the fields of one kind 14 record.
type parts struct {
	da         uint64
	commitment []byte
	namespace  []byte
	height     uint64
	header     []byte
	dah        []byte
	nsData     []byte
	results    []byte
	nextHeader []byte
}

type caseInput struct {
	id, description string
	q               queryDoc
	trusted         map[string]string
	recs            []parts
}

type input struct {
	source liveSource
	cases  []caseInput
	tail   tailRule
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hx(s[:])
}

func utoa(n uint64) string { return strconv.FormatUint(n, 10) }

func cborHead(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.Write([]byte{m | 24, byte(n)})
	case n <= 0xffff:
		buf.Write([]byte{m | 25, byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		buf.Write([]byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		buf.WriteByte(m | 27)
		for i := 7; i >= 0; i-- {
			buf.WriteByte(byte(n >> (8 * i)))
		}
	}
}

// encodeRecord writes the kind 14 record as deterministic CBOR: a map with
// unsigned keys in ascending order, shortest heads, no indefinite lengths.
func encodeRecord(p parts) []byte {
	type field struct {
		key  uint64
		u    uint64
		b    []byte
		isBs bool
	}
	fs := []field{{key: 1, u: recordFormat}, {key: 2, u: kindAbsence}, {key: 3, u: p.da},
		{key: 4, b: p.commitment, isBs: true}, {key: 5, b: p.namespace, isBs: true}, {key: 6, u: p.height},
		{key: 7, b: p.header, isBs: true}, {key: 8, b: p.dah, isBs: true}, {key: 9, b: p.nsData, isBs: true}}
	if p.results != nil {
		fs = append(fs, field{key: 10, b: p.results, isBs: true}, field{key: 11, b: p.nextHeader, isBs: true})
	}
	var b bytes.Buffer
	cborHead(&b, 5, uint64(len(fs)))
	for _, f := range fs {
		cborHead(&b, 0, f.key)
		if f.isBs {
			cborHead(&b, 2, uint64(len(f.b)))
			b.Write(f.b)
		} else {
			cborHead(&b, 0, f.u)
		}
	}
	return b.Bytes()
}

// decodeRecord reads back what encodeRecord writes and refuses anything else.
func decodeRecord(rec []byte) (parts, error) {
	r := bytes.NewReader(rec)
	head := func() (byte, uint64, error) {
		ib, err := r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		major, ai := ib>>5, ib&0x1f
		var n uint64
		switch {
		case ai < 24:
			n = uint64(ai)
		case ai >= 24 && ai <= 27:
			k := 1 << (ai - 24)
			for i := 0; i < k; i++ {
				c, err := r.ReadByte()
				if err != nil {
					return 0, 0, err
				}
				n = n<<8 | uint64(c)
			}
		default:
			return 0, 0, errors.New("unsupported CBOR head")
		}
		return major, n, nil
	}
	major, count, err := head()
	if err != nil || major != 5 {
		return parts{}, fmt.Errorf("record is not a map: %v", err)
	}
	var p parts
	vals := map[uint64]any{}
	for i := uint64(0); i < count; i++ {
		mk, k, err := head()
		if err != nil || mk != 0 {
			return parts{}, fmt.Errorf("map key: %v", err)
		}
		mv, v, err := head()
		if err != nil {
			return parts{}, err
		}
		switch mv {
		case 0:
			vals[k] = v
		case 2:
			if v > uint64(r.Len()) {
				return parts{}, fmt.Errorf("key %d: byte string beyond the record", k)
			}
			bs := make([]byte, v)
			if _, err := io.ReadFull(r, bs); err != nil {
				return parts{}, err
			}
			vals[k] = bs
		default:
			return parts{}, fmt.Errorf("key %d: major type %d", k, mv)
		}
	}
	if r.Len() != 0 {
		return parts{}, errors.New("trailing bytes")
	}
	u := func(k uint64) uint64 { v, _ := vals[k].(uint64); return v }
	bs := func(k uint64) []byte { v, _ := vals[k].([]byte); return v }
	if u(1) != recordFormat || u(2) != kindAbsence {
		return parts{}, errors.New("not a format 1 kind 14 record")
	}
	p = parts{da: u(3), commitment: bs(4), namespace: bs(5), height: u(6), header: bs(7), dah: bs(8),
		nsData: bs(9), results: bs(10), nextHeader: bs(11)}
	if !bytes.Equal(encodeRecord(p), rec) {
		return parts{}, errors.New("record does not re-encode to the same bytes")
	}
	return p, nil
}

type unproven struct{ rule, why string }

func (u unproven) Error() string { return u.rule + ": " + u.why }

func signedHeader(b []byte, h uint64, trusted map[string]string, rule string) (*core.SignedHeader, error) {
	var pb cmtproto.SignedHeader
	if err := pb.Unmarshal(b); err != nil {
		return nil, unproven{rule, "signed header protobuf: " + err.Error()}
	}
	sh, err := core.SignedHeaderFromProto(&pb)
	if err != nil {
		return nil, unproven{rule, "signed header: " + err.Error()}
	}
	if sh.Height != int64(h) {
		return nil, unproven{rule, fmt.Sprintf("header height %d, want %d", sh.Height, h)}
	}
	want, ok := trusted[utoa(h)]
	if !ok {
		return nil, unproven{rule, "header trust does not reach " + utoa(h)}
	}
	hash := sh.Header.Hash()
	if hx(hash) != want {
		return nil, unproven{rule, "header hash differs from the trusted hash"}
	}
	if sh.Commit.Height != int64(h) || !bytes.Equal(sh.Commit.BlockID.Hash, hash) {
		return nil, unproven{rule, "commit is not for this header"}
	}
	return sh, nil
}

// reassemble parses the PayForFibre compact shares and accepts them only if
// splitting the parsed txs again gives the same shares.
func reassemble(shares []libshare.Share) ([][]byte, error) {
	if len(shares) == 0 {
		return nil, nil
	}
	txs, err := libshare.ParseTxs(shares)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	css := libshare.NewCompactShareSplitter(pffNS, libshare.ShareVersionZero)
	for _, tx := range txs {
		if err := css.WriteTx(tx); err != nil {
			return nil, err
		}
	}
	again, err := css.Export()
	if err != nil {
		return nil, err
	}
	if len(again) != len(shares) {
		return nil, fmt.Errorf("re-split gives %d shares, input has %d", len(again), len(shares))
	}
	for i := range again {
		if !bytes.Equal(again[i].ToBytes(), shares[i].ToBytes()) {
			return nil, fmt.Errorf("re-split differs at share %d", i)
		}
	}
	return txs, nil
}

// promiseOf decodes a PFF_NS unit the way CV1 reads a PayForFibre tx. It
// does not ask TryParseFibreTx: a unit that fails here makes the height not
// proven whatever the upstream classifier says.
func promiseOf(tx []byte) (*fibretypes.MsgPayForFibre, error) {
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return nil, err
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return nil, err
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil {
		return nil, fmt.Errorf("%d messages", len(body.Messages))
	}
	if body.Messages[0].TypeUrl != pffTypeURL {
		return nil, fmt.Errorf("type URL %q", body.Messages[0].TypeUrl)
	}
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return nil, err
	}
	if len(msg.PaymentPromise.Namespace) != 29 || len(msg.PaymentPromise.Commitment) != 32 {
		return nil, errors.New("promise namespace or commitment size")
	}
	return &msg, nil
}

const pffTypeURL = "/celestia.fibre.v1.MsgPayForFibre"

type servedResults struct {
	Height     string `json:"height"`
	TxsResults []struct {
		Code      uint32 `json:"code"`
		Data      []byte `json:"data,omitempty"`
		GasWanted string `json:"gas_wanted"`
		GasUsed   string `json:"gas_used"`
	} `json:"txs_results"`
}

func resultCodes(results, nextHeader []byte, h uint64, trusted map[string]string) ([]uint32, error) {
	nh, err := signedHeader(nextHeader, h+1, trusted, "AB5")
	if err != nil {
		return nil, err
	}
	var sr servedResults
	if err := json.Unmarshal(results, &sr); err != nil {
		return nil, unproven{"AB5", "results: " + err.Error()}
	}
	rs := make([]*abci.ExecTxResult, len(sr.TxsResults))
	codes := make([]uint32, len(sr.TxsResults))
	for i, x := range sr.TxsResults {
		gw, err1 := strconv.ParseInt(x.GasWanted, 10, 64)
		gu, err2 := strconv.ParseInt(x.GasUsed, 10, 64)
		if err1 != nil || err2 != nil {
			return nil, unproven{"AB5", "results: gas is not an int64"}
		}
		rs[i] = &abci.ExecTxResult{Code: x.Code, Data: x.Data, GasWanted: gw, GasUsed: gu}
		codes[i] = x.Code
	}
	if !bytes.Equal(core.NewResults(rs).Hash(), nh.LastResultsHash) {
		return nil, unproven{"AB5", "results do not hash to last_results_hash of header(h + 1)"}
	}
	return codes, nil
}

// classify runs AB1 to AB6 on one record with upstream code.
func classify(p parts, q queryDoc, qns, qcom, qsigner []byte, h uint64, trusted map[string]string) (heightDoc, error) {
	da1 := q.DA == "1"
	if utoa(p.da) != q.DA || !bytes.Equal(p.commitment, qcom) || !bytes.Equal(p.namespace, qns) || p.height != h {
		return heightDoc{}, unproven{"record", "the record is not about this query and height"}
	}
	sh, err := signedHeader(p.header, h, trusted, "AB1")
	if err != nil {
		return heightDoc{}, err
	}
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(p.dah); err != nil {
		return heightDoc{}, unproven{"AB2", "DAH protobuf: " + err.Error()}
	}
	dah := &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}
	if err := dah.ValidateBasic(); err != nil {
		return heightDoc{}, unproven{"AB2", err.Error()}
	}
	if !bytes.Equal(dah.Hash(), sh.DataHash) {
		return heightDoc{}, unproven{"AB2", "DAH hash differs from data_hash"}
	}
	ns := pffNS
	if !da1 {
		if ns, err = libshare.NewNamespaceFromBytes(qns); err != nil {
			return heightDoc{}, unproven{"AB3", err.Error()}
		}
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(p.nsData)); err != nil {
		return heightDoc{}, unproven{"AB3", err.Error()}
	}
	if err := nd.Verify(dah, ns); err != nil {
		return heightDoc{}, unproven{"AB3", err.Error()}
	}
	rowIdx, err := share.RowsWithNamespace(dah, ns)
	if err != nil {
		return heightDoc{}, unproven{"AB3", err.Error()}
	}
	out := heightDoc{Height: utoa(h), Rows: []string{}}
	for _, r := range rowIdx {
		out.Rows = append(out.Rows, strconv.Itoa(r))
	}
	shares := nd.Flatten()
	where := "no row holds the namespace"
	if len(rowIdx) > 0 {
		where = fmt.Sprintf("%d row(s) hold the namespace in their range", len(rowIdx))
	}

	if !da1 {
		if len(shares) == 0 {
			out.Result, out.Rule, out.Why = "absent", "AB6", where+"; every entry is an NMT absence proof, S is empty"
			if len(rowIdx) == 0 {
				out.Why = where + ": S is empty"
			}
			return out, nil
		}
		blobs, err := libshare.ParseBlobs(shares)
		if err != nil {
			return heightDoc{}, unproven{"AB6", "shares do not parse: " + err.Error()}
		}
		present := false
		for _, b := range blobs {
			bd := blobDoc{ShareVersion: strconv.Itoa(int(b.ShareVersion()))}
			if b.ShareVersion() == libshare.ShareVersionOne {
				com, err := inclusion.CreateCommitment(b, merkle.HashFromByteSlices, subtreeRootThreshold)
				if err != nil {
					return heightDoc{}, unproven{"AB6", err.Error()}
				}
				bd.Signer, bd.Commitment = hx(b.Signer()), hx(com)
				if bytes.Equal(com, qcom) && bytes.Equal(b.Signer(), qsigner) {
					present = true
				}
			}
			out.Blobs = append(out.Blobs, bd)
		}
		out.Rule = "AB6"
		if present {
			out.Result, out.Why = "present", fmt.Sprintf("%d blob(s) in the namespace; a share version 1 blob has the queried commitment and signer", len(blobs))
		} else {
			out.Result, out.Why = "absent", fmt.Sprintf("%d blob(s) in the namespace, none of share version 1 with the queried commitment and signer", len(blobs))
		}
		return out, nil
	}

	out.PFFTxs = "0"
	// AB3 selects rows by the pinned layout, so at another app version
	// neither an empty S nor units without a candidate prove anything.
	pinned := sh.Version.App == pinnedAppVersion
	if len(shares) == 0 && !pinned {
		return heightDoc{}, unproven{"AB4", "another app version: S empty proves nothing"}
	}
	if len(shares) == 0 {
		out.Result, out.Rule = "absent", "AB4"
		out.Why = where + "; its entry is an NMT absence proof, S is empty"
		if len(rowIdx) == 0 {
			out.Why = where + ": S is empty"
		}
		return out, nil
	}
	units, err := reassemble(shares)
	if err != nil {
		return heightDoc{}, unproven{"AB4", err.Error()}
	}
	out.PFFTxs = strconv.Itoa(len(units))
	var cands []int
	for j, tx := range units {
		msg, err := promiseOf(tx)
		if err != nil {
			return heightDoc{}, unproven{"AB4", "a unit of PFF_NS does not decode as a MsgPayForFibre tx"}
		}
		pp := msg.PaymentPromise
		if bytes.Equal(pp.Namespace, qns) && bytes.Equal(pp.Commitment, qcom) && pp.BlobVersion == 0 &&
			pp.ChainId == q.ChainID && pp.Height <= int64(h) {
			cands = append(cands, j)
		}
	}
	if len(cands) == 0 && !pinned {
		return heightDoc{}, unproven{"AB4", "another app version with units in PFF_NS: not proven"}
	}
	if len(cands) == 0 {
		out.Result, out.Rule = "absent", "AB4"
		out.Why = fmt.Sprintf("%d PFF(s) in PFF_NS, none a candidate for the query", len(units))
		return out, nil
	}
	if p.results == nil || p.nextHeader == nil {
		return heightDoc{}, unproven{"AB5", "a candidate whose code is not proven"}
	}
	codes, err := resultCodes(p.results, p.nextHeader, h, trusted)
	if err != nil {
		return heightDoc{}, err
	}
	n, pc := len(codes), len(units)
	if n < pc || pc < 1 {
		return heightDoc{}, unproven{"AB5", "n >= p >= 1 does not hold"}
	}
	uniform := true
	for _, c := range codes {
		if c != codes[0] {
			uniform = false
		}
	}
	out.Rule = "AB5"
	// A block of another app version may follow other square rules, so its
	// results never bind an index: only every code 0 counts, and only as
	// presence, which holds whatever the index.
	if sh.Version.App != pinnedAppVersion {
		if !uniform || codes[0] != 0 {
			return heightDoc{}, unproven{"AB5", "another app version without every code 0: not proven"}
		}
		for _, j := range cands {
			out.Candidates = append(out.Candidates, candDoc{Position: strconv.Itoa(j), Code: "0"})
		}
		out.Result, out.Why = "present", "another app version, every result code 0"
		return out, nil
	}
	present := false
	var why []string
	for _, j := range cands {
		i := n - pc + j
		out.Candidates = append(out.Candidates, candDoc{Position: strconv.Itoa(j), ResultIndex: strconv.Itoa(i), Code: strconv.Itoa(int(codes[i]))})
		why = append(why, fmt.Sprintf("position %d: result index n - p + j = %d - %d + %d = %d, code %d", j, n, pc, j, i, codes[i]))
		present = present || codes[i] == 0
	}
	if present {
		out.Result = "present"
	} else {
		out.Result = "absent"
	}
	out.Why = fmt.Sprintf("%d candidate(s) among %d PFF(s); %s", len(cands), pc, strings.Join(why, "; "))
	if !uniform {
		out.Why += "; the codes are not uniform, so only the tail rule binds the index"
	}
	return out, nil
}

func window(hs []heightDoc) windowDoc {
	for _, x := range hs {
		if x.Result == "present" {
			return windowDoc{Result: "present", AnchorHeight: x.Height}
		}
	}
	for _, x := range hs {
		if x.Result != "absent" {
			return windowDoc{Result: "unproven", FirstUnproven: x.Height}
		}
	}
	return windowDoc{Result: "absent"}
}

func decodeQuery(q queryDoc) (ns, com, signer []byte, h0, d uint64, err error) {
	if ns, err = hex.DecodeString(q.Namespace); err != nil {
		return
	}
	if com, err = hex.DecodeString(q.Commitment); err != nil {
		return
	}
	if signer, err = hex.DecodeString(q.Signer); err != nil {
		return
	}
	if h0, err = strconv.ParseUint(q.H0, 10, 64); err != nil {
		return
	}
	d, err = strconv.ParseUint(q.AnchorDeadline, 10, 64)
	return
}

func build(in input) (liveDoc, error) {
	doc := liveDoc{Source: in.source, TailRule: in.tail}
	recByHeight := map[string]map[string]parts{}
	for _, c := range in.cases {
		ns, com, signer, h0, d, err := decodeQuery(c.q)
		if err != nil {
			return liveDoc{}, fmt.Errorf("%s: query: %w", c.id, err)
		}
		lc := liveCase{ID: c.id, Description: c.description, Query: c.q, TrustedHeaders: c.trusted}
		byH := map[uint64]parts{}
		recByHeight[c.id] = map[string]parts{}
		for _, p := range c.recs {
			rec := encodeRecord(p)
			lc.Records = append(lc.Records, recordDoc{Height: utoa(p.height), RecordHex: hx(rec), SHA256: sha(rec), Size: strconv.Itoa(len(rec))})
			byH[p.height] = p
			recByHeight[c.id][utoa(p.height)] = p
		}
		for h := h0; h <= d; h++ {
			p, ok := byH[h]
			if !ok {
				lc.Expect.Heights = append(lc.Expect.Heights, heightDoc{Height: utoa(h), Result: "unproven", Rule: "none", Why: "no absence proof for this height"})
				continue
			}
			hd, err := classify(p, c.q, ns, com, signer, h, c.trusted)
			var u unproven
			if errors.As(err, &u) {
				hd = heightDoc{Height: utoa(h), Result: "unproven", Rule: u.rule, Why: u.why}
			} else if err != nil {
				return liveDoc{}, fmt.Errorf("%s at %d: %w", c.id, h, err)
			}
			lc.Expect.Heights = append(lc.Expect.Heights, hd)
		}
		lc.Expect.Window = window(lc.Expect.Heights)
		doc.Live = append(doc.Live, lc)
	}
	for _, b := range in.tail.Blocks {
		if err := checkTail(b, recByHeight[b.Case][b.Height]); err != nil {
			return liveDoc{}, fmt.Errorf("tail rule at %s: %w", b.Height, err)
		}
	}
	return doc, nil
}

// checkTail confirms, on the bytes the vector file holds, what the fetch saw
// on the full block: the Fibre txs are the last p elements of data.txs, and
// they are the PFF_NS units in the same order.
func checkTail(b tailBlock, p parts) error {
	if p.nsData == nil {
		return errors.New("no record of the named case at this height")
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(p.nsData)); err != nil {
		return err
	}
	units, err := reassemble(nd.Flatten())
	if err != nil {
		return err
	}
	n, pc := len(b.Txs), len(units)
	if pc < 2 || n <= pc {
		return fmt.Errorf("want at least two PFFs and another tx: n %d, p %d", n, pc)
	}
	if b.FibreFrom != strconv.Itoa(n-pc) {
		return fmt.Errorf("fibre_from %s, want %d", b.FibreFrom, n-pc)
	}
	for i, tx := range b.Txs {
		if tx.Index != strconv.Itoa(i) {
			return fmt.Errorf("tx %d: index %s", i, tx.Index)
		}
		fibre := i >= n-pc
		if fibre != (tx.Class == "fibre") {
			return fmt.Errorf("tx %d: class %s", i, tx.Class)
		}
		if fibre {
			u := units[i-(n-pc)]
			if tx.SHA256 != sha(u) || tx.Size != strconv.Itoa(len(u)) {
				return fmt.Errorf("tx %d is not PFF_NS unit %d", i, i-(n-pc))
			}
		}
	}
	return nil
}

func inputsFromDoc(f liveDoc) (input, error) {
	in := input{source: f.Source, tail: f.TailRule}
	for _, c := range f.Live {
		ci := caseInput{id: c.ID, description: c.Description, q: c.Query, trusted: c.TrustedHeaders}
		for _, r := range c.Records {
			b, err := hex.DecodeString(r.RecordHex)
			if err != nil {
				return input{}, err
			}
			p, err := decodeRecord(b)
			if err != nil {
				return input{}, fmt.Errorf("%s at %s: %w", c.ID, r.Height, err)
			}
			ci.recs = append(ci.recs, p)
		}
		in.cases = append(in.cases, ci)
	}
	return in, nil
}
