package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/celestiaorg/nmt"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
)

const revision = "v0-draft.23"

type file struct {
	Format     string            `json:"format"`
	Revision   string            `json:"revision"`
	Generator  string            `json:"generator"`
	Upstream   map[string]string `json:"upstream"`
	Rules      map[string]string `json:"rules"`
	Namespace  string            `json:"pff_namespace"`
	Live       liveDoc           `json:"live"`
	Mutations  []mutation        `json:"mutations"`
	Reassembly []reassemblyCase  `json:"reassembly"`
}

type liveDoc struct {
	Description string     `json:"description"`
	Source      liveSource `json:"source"`
	Cases       []liveCase `json:"cases"`
}

type liveCase struct {
	ID     string     `json:"id"`
	Raw    liveRaw    `json:"raw"`
	Expect liveExpect `json:"expect"`
}

type liveExpect struct {
	SquareSize string            `json:"square_size"`
	Rows       []string          `json:"rows"`
	ShareCount string            `json:"share_count"`
	Txs        []txDoc           `json:"txs"`
	Queries    []query           `json:"queries"`
	Evidence   evidenceDoc       `json:"archive_proof"`
	Sizes      map[string]string `json:"sizes"`
}

type txDoc struct {
	Position   string      `json:"position"`
	Length     string      `json:"length"`
	SHA256     string      `json:"sha256"`
	Fibre      bool        `json:"fibre"`
	Promise    *promiseDoc `json:"promise,omitempty"`
	SystemBlob string      `json:"system_blob_hex,omitempty"`
}

type promiseDoc struct {
	ChainID           string `json:"chain_id"`
	Height            string `json:"height"`
	Namespace         string `json:"namespace"`
	BlobSize          string `json:"blob_size"`
	BlobVersion       string `json:"blob_version"`
	Commitment        string `json:"commitment"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationUnixNanos string `json:"creation_unix_nanos"`
}

type query struct {
	Description string   `json:"description"`
	Namespace   string   `json:"namespace"`
	Commitment  string   `json:"commitment"`
	BlobVersion string   `json:"blob_version"`
	ChainID     string   `json:"chain_id"`
	Candidates  []string `json:"candidates"`
	Anchor      string   `json:"anchor"`
}

type evidenceDoc struct {
	Description string `json:"description"`
	Hex         string `json:"hex"`
	SHA256      string `json:"sha256"`
	Size        string `json:"size"`
}

type op struct {
	Kind      string `json:"kind"`
	Target    string `json:"target,omitempty"`
	Index     string `json:"index,omitempty"`
	Row       string `json:"row,omitempty"`
	Row2      string `json:"row2,omitempty"`
	Share     string `json:"share,omitempty"`
	Offset    string `json:"offset,omitempty"`
	Xor       string `json:"xor,omitempty"`
	Bytes     string `json:"bytes,omitempty"`
	Value     string `json:"value,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type mutationExpect struct {
	Verdict  string `json:"verdict"`
	Fails    string `json:"fails,omitempty"`
	SameTxs  *bool  `json:"same_txs,omitempty"`
	Upstream string `json:"upstream_error,omitempty"`
}

type mutation struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Case        string         `json:"case"`
	Op          op             `json:"op"`
	Expect      mutationExpect `json:"expect"`
}

type reassemblyCase struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Shares      []string         `json:"shares_hex"`
	Expect      reassemblyExpect `json:"expect"`
	Upstream    string           `json:"upstream_parse_txs"`
}

type reassemblyExpect struct {
	Verdict string    `json:"verdict"`
	Fails   string    `json:"fails,omitempty"`
	Txs     *[]string `json:"txs_sha256,omitempty"`
}

var pffNS = libshare.PayForFibreNamespace

func hx(b []byte) string { return hex.EncodeToString(b) }

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hx(s[:])
}

func itoa(n int) string { return strconv.Itoa(n) }

type inputs struct {
	dataHash []byte
	rows     [][]byte
	cols     [][]byte
	stream   []byte
	ns       libshare.Namespace
	// edit, when set, changes the decoded namespace data before it is verified.
	edit func(shwap.NamespaceData) (shwap.NamespaceData, error)
}

type outcome struct {
	stage string // "" when accepted
	err   string
	dah   *da.DataAvailabilityHeader
	nd    shwap.NamespaceData
	txs   [][]byte
}

// evaluate runs the lookup's proof steps on one input: the DAH against the
// header's data_hash, the namespace data against the DAH, then reassembly.
func evaluate(in inputs) outcome {
	dah := &da.DataAvailabilityHeader{RowRoots: in.rows, ColumnRoots: in.cols}
	if err := dah.ValidateBasic(); err != nil {
		return outcome{stage: "NA2", err: err.Error()}
	}
	if !bytes.Equal(dah.Hash(), in.dataHash) {
		return outcome{stage: "NA2", err: "DAH hash differs from data_hash"}
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(in.stream)); err != nil {
		return outcome{stage: "NA3", err: err.Error()}
	}
	if in.edit != nil {
		var err error
		if nd, err = in.edit(nd); err != nil {
			return outcome{stage: "NA3", err: err.Error()}
		}
	}
	if err := nd.Verify(dah, in.ns); err != nil {
		return outcome{stage: "NA3", err: err.Error()}
	}
	txs, err := reassemble(nd.Flatten())
	if err != nil {
		return outcome{stage: "NA4", err: err.Error()}
	}
	return outcome{dah: dah, nd: nd, txs: txs}
}

// reassemble parses the compact shares of the PayForFibre namespace and
// accepts them only if splitting the parsed txs again gives the same shares:
// that rules out a truncated last unit, a missing or extra share, a second
// sequence and non-canonical reserved bytes or padding, all of which
// ParseTxs alone tolerates or drops silently.
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

func decodeHexList(xs []string) ([][]byte, error) {
	out := make([][]byte, len(xs))
	for i, x := range xs {
		b, err := hex.DecodeString(x)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

func baseInputs(r liveRaw) (inputs, error) {
	dh, err := hex.DecodeString(r.DataHash)
	if err != nil {
		return inputs{}, err
	}
	rows, err := decodeHexList(r.RowRoots)
	if err != nil {
		return inputs{}, err
	}
	cols, err := decodeHexList(r.ColumnRoots)
	if err != nil {
		return inputs{}, err
	}
	st, err := hex.DecodeString(r.NamespaceDataHex)
	if err != nil {
		return inputs{}, err
	}
	return inputs{dataHash: dh, rows: rows, cols: cols, stream: st, ns: pffNS}, nil
}

type parsedPromise struct {
	doc   promiseDoc
	ns    []byte
	com   []byte
	nanos int64
}

func parsePFF(tx []byte) (*parsedPromise, []byte, bool, error) {
	ftx, ok, err := fibretypes.TryParseFibreTx(tx)
	if err != nil || !ok {
		return nil, nil, false, err
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return nil, nil, false, err
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return nil, nil, false, err
	}
	if len(body.Messages) != 1 {
		return nil, nil, false, fmt.Errorf("fibre tx with %d messages", len(body.Messages))
	}
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return nil, nil, false, err
	}
	var pp fibre.PaymentPromise
	if err := pp.FromProto(&msg.PaymentPromise); err != nil {
		return nil, nil, false, err
	}
	sb, err := ftx.SystemBlob.Marshal()
	if err != nil {
		return nil, nil, false, err
	}
	p := msg.PaymentPromise
	ts := pp.CreationTimestamp.UTC()
	return &parsedPromise{
		doc: promiseDoc{
			ChainID:           p.ChainId,
			Height:            strconv.FormatInt(p.Height, 10),
			Namespace:         hx(p.Namespace),
			BlobSize:          strconv.FormatUint(uint64(p.BlobSize), 10),
			BlobVersion:       strconv.FormatUint(uint64(p.BlobVersion), 10),
			Commitment:        hx(p.Commitment),
			CreationTimestamp: ts.Format(time.RFC3339Nano),
			CreationUnixNanos: strconv.FormatInt(ts.UnixNano(), 10),
		},
		ns: p.Namespace, com: p.Commitment, nanos: ts.UnixNano(),
	}, sb, true, nil
}

// cborHead writes a CBOR head with the shortest argument encoding.
func cborHead(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.WriteByte(m | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		buf.Write([]byte{byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		buf.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		buf.WriteByte(m | 27)
		for i := 7; i >= 0; i-- {
			buf.WriteByte(byte(n >> (8 * i)))
		}
	}
}

// archiveProof is the archive form of the anchor proof: a deterministic CBOR
// map {1: form, 2: DAH protobuf, 3: namespace data stream}.
func archiveProof(dahProto, stream []byte) []byte {
	var b bytes.Buffer
	cborHead(&b, 5, 3)
	cborHead(&b, 0, 1)
	cborHead(&b, 0, 1)
	cborHead(&b, 0, 2)
	cborHead(&b, 2, uint64(len(dahProto)))
	b.Write(dahProto)
	cborHead(&b, 0, 3)
	cborHead(&b, 2, uint64(len(stream)))
	b.Write(stream)
	return b.Bytes()
}

// selectAnchor applies the selection with every candidate at code 0: the
// earliest creation timestamp, then the earliest position.
func selectAnchor(cands []int, ps map[int]*parsedPromise) string {
	if len(cands) == 0 {
		return "none"
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if ps[c].nanos < ps[best].nanos {
			best = c
		}
	}
	return itoa(best)
}

func liveCaseFor(r liveRaw) (liveCase, error) {
	in, err := baseInputs(r)
	if err != nil {
		return liveCase{}, err
	}
	o := evaluate(in)
	if o.stage != "" {
		return liveCase{}, fmt.Errorf("live %s rejected at %s: %s", r.Height, o.stage, o.err)
	}
	rows, err := share.RowsWithNamespace(o.dah, pffNS)
	if err != nil {
		return liveCase{}, err
	}
	e := liveExpect{SquareSize: itoa(o.dah.SquareSize()), ShareCount: itoa(o.nd.Length())}
	for _, x := range rows {
		e.Rows = append(e.Rows, itoa(x))
	}
	ps := map[int]*parsedPromise{}
	for i, tx := range o.txs {
		d := txDoc{Position: itoa(i), Length: itoa(len(tx)), SHA256: sha(tx)}
		p, sb, ok, err := parsePFF(tx)
		if err != nil {
			return liveCase{}, fmt.Errorf("tx %d: %w", i, err)
		}
		if ok {
			d.Fibre = true
			d.Promise = &p.doc
			d.SystemBlob = hx(sb)
			ps[i] = p
		}
		e.Txs = append(e.Txs, d)
	}
	if len(ps) == 0 {
		return liveCase{}, fmt.Errorf("live %s: no PayForFibre in the namespace data", r.Height)
	}

	type key struct{ ns, com, chain string }
	seen := map[key]bool{}
	var order []int
	for i := range o.txs {
		if _, ok := ps[i]; ok {
			order = append(order, i)
		}
	}
	for _, i := range order {
		p := ps[i]
		k := key{hx(p.ns), hx(p.com), p.doc.ChainID}
		if seen[k] {
			continue
		}
		seen[k] = true
		var cands []int
		for _, j := range order {
			q := ps[j]
			if bytes.Equal(q.ns, p.ns) && bytes.Equal(q.com, p.com) && q.doc.BlobVersion == "0" && q.doc.ChainID == p.doc.ChainID {
				cands = append(cands, j)
			}
		}
		qd := query{
			Description: "Promise of the tx at position " + itoa(i) + ".",
			Namespace:   k.ns, Commitment: k.com, BlobVersion: "0", ChainID: k.chain, Anchor: selectAnchor(cands, ps),
		}
		for _, c := range cands {
			qd.Candidates = append(qd.Candidates, itoa(c))
		}
		e.Queries = append(e.Queries, qd)
	}
	first := ps[order[0]]
	other := bytes.Clone(first.com)
	other[0] ^= 0x01
	e.Queries = append(e.Queries,
		query{
			Description: "Commitment of the first promise with its first byte XOR 0x01: no candidate in complete namespace data, so the absence is proven (ErrAnchorNotFound).",
			Namespace:   hx(first.ns), Commitment: hx(other), BlobVersion: "0", ChainID: first.doc.ChainID, Candidates: []string{}, Anchor: "none",
		},
		query{
			Description: "The first promise under another chain id: no candidate.",
			Namespace:   hx(first.ns), Commitment: hx(first.com), BlobVersion: "0", ChainID: "mocha-4", Candidates: []string{}, Anchor: "none",
		},
	)

	dp, err := (&daproto.DataAvailabilityHeader{RowRoots: in.rows, ColumnRoots: in.cols}).Marshal()
	if err != nil {
		return liveCase{}, err
	}
	ap := archiveProof(dp, in.stream)
	e.Evidence = evidenceDoc{
		Description: "system_blob_proof of an archive evidence record (da = 1) in anchor-proof form 1: CBOR map {1: 1, 2: dah_proto, 3: namespace data stream}.",
		Hex:         hx(ap), SHA256: sha(ap), Size: itoa(len(ap)),
	}
	e.Sizes = map[string]string{
		"dah_proto":      itoa(len(dp)),
		"namespace_data": itoa(len(in.stream)),
		"archive_proof":  itoa(len(ap)),
	}
	return liveCase{ID: "h" + r.Height, Raw: r, Expect: e}, nil
}

func flip(b []byte, off int, x byte) ([]byte, error) {
	if off < 0 || off >= len(b) {
		return nil, fmt.Errorf("offset %d outside %d bytes", off, len(b))
	}
	c := bytes.Clone(b)
	c[off] ^= x
	return c, nil
}

func cloneND(nd shwap.NamespaceData) shwap.NamespaceData {
	out := make(shwap.NamespaceData, len(nd))
	for i, r := range nd {
		out[i] = shwap.RowNamespaceData{Shares: append([]libshare.Share(nil), r.Shares...), Proof: r.Proof}
	}
	return out
}

func mutations(lc []liveCase) ([]mutation, error) {
	var ms []mutation
	add := func(c liveCase, id, desc string, o op, apply func(inputs) (inputs, error)) error {
		base, err := baseInputs(c.Raw)
		if err != nil {
			return err
		}
		ref := evaluate(base)
		in, err := apply(base)
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		got := evaluate(in)
		m := mutation{ID: id, Description: desc, Case: c.ID, Op: o}
		if got.stage == "" {
			same := len(got.txs) == len(ref.txs)
			for i := 0; same && i < len(got.txs); i++ {
				same = bytes.Equal(got.txs[i], ref.txs[i])
			}
			m.Expect = mutationExpect{Verdict: "accept", SameTxs: &same}
		} else {
			m.Expect = mutationExpect{Verdict: "reject", Fails: got.stage, Upstream: got.err}
		}
		ms = append(ms, m)
		return nil
	}

	c := lc[0]
	multi := c
	for _, x := range lc {
		if len(x.Expect.Rows) > len(multi.Expect.Rows) {
			multi = x
		}
	}
	firstRow, _ := strconv.Atoi(c.Expect.Rows[0])

	steps := []struct {
		c     liveCase
		id    string
		desc  string
		o     op
		apply func(inputs) (inputs, error)
	}{
		{c, "data_hash", "data_hash of the header with one byte flipped: the DAH no longer hashes to it.",
			op{Kind: "flip", Target: "data_hash", Offset: "0", Xor: "01"},
			func(in inputs) (inputs, error) {
				var err error
				in.dataHash, err = flip(in.dataHash, 0, 1)
				return in, err
			}},
		{c, "row_root", "The row root that holds the PayForFibre namespace, one byte of its hash part flipped.",
			op{Kind: "flip", Target: "row_root", Index: itoa(firstRow), Offset: "70", Xor: "01"},
			func(in inputs) (inputs, error) {
				in.rows = append([][]byte(nil), in.rows...)
				var err error
				in.rows[firstRow], err = flip(in.rows[firstRow], 70, 1)
				return in, err
			}},
		{c, "column_root", "Column root 0, one byte flipped: it is not used by the namespace proof but is covered by the DAH hash.",
			op{Kind: "flip", Target: "column_root", Index: "0", Offset: "70", Xor: "01"},
			func(in inputs) (inputs, error) {
				in.cols = append([][]byte(nil), in.cols...)
				var err error
				in.cols[0], err = flip(in.cols[0], 70, 1)
				return in, err
			}},
		{c, "dah_split_shifted", "Column root 0 moved to the end of the row roots: the concatenation row_roots || column_roots is unchanged, so a verifier that hashes it without the equal-count check (ValidateBasic) would accept the shifted split and look up the wrong row roots.",
			op{Kind: "move_column_root_to_rows"},
			func(in inputs) (inputs, error) {
				in.rows = append(append([][]byte(nil), in.rows...), in.cols[0])
				in.cols = append([][]byte(nil), in.cols[1:]...)
				return in, nil
			}},
		{c, "share_flip", "Row 0 of the namespace data, share 0, byte 100 flipped.",
			op{Kind: "flip", Target: "share", Row: "0", Share: "0", Offset: "100", Xor: "01"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) {
					nd = cloneND(nd)
					raw, err := flip(nd[0].Shares[0].ToBytes(), 100, 1)
					if err != nil {
						return nil, err
					}
					s, err := libshare.NewShare(raw)
					if err != nil {
						return nil, err
					}
					nd[0].Shares[0] = s
					return nd, nil
				}
				return in, nil
			}},
		{c, "drop_last_share", "The last share of the last row removed, its proof unchanged.",
			op{Kind: "drop_share", Row: "last", Share: "last"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) {
					nd = cloneND(nd)
					r := len(nd) - 1
					nd[r].Shares = nd[r].Shares[:len(nd[r].Shares)-1]
					return nd, nil
				}
				return in, nil
			}},
		{c, "drop_row", "The last row of the namespace data removed: fewer rows than the DAH says hold the namespace.",
			op{Kind: "drop_row", Row: "last"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) { return cloneND(nd)[:len(nd)-1], nil }
				return in, nil
			}},
		{c, "dup_row", "The last row repeated: more rows than the DAH says hold the namespace.",
			op{Kind: "dup_row", Row: "last"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) {
					nd = cloneND(nd)
					return append(nd, nd[len(nd)-1]), nil
				}
				return in, nil
			}},
		{c, "max_ns_flag", "is_max_namespace_ignored of row 0's proof set to false (Celestia trees ignore the max namespace).",
			op{Kind: "set_max_ns_ignored", Row: "0", Value: "false"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) {
					nd = cloneND(nd)
					p := nd[0].Proof
					if p.IsOfAbsence() {
						return nil, errors.New("row 0 holds an absence proof")
					}
					q := nmtInclusion(p.Start(), p.End(), p.Nodes(), false)
					nd[0].Proof = &q
					return nd, nil
				}
				return in, nil
			}},
		{c, "truncate_stream", "The namespace data stream without its last byte.",
			op{Kind: "truncate_stream", Bytes: "1"},
			func(in inputs) (inputs, error) { in.stream = in.stream[:len(in.stream)-1]; return in, nil }},
		{c, "other_namespace", "The same namespace data checked as the data of the PayForBlob namespace (0x00 || 0^27 || 0x04).",
			op{Kind: "verify_namespace", Namespace: hx(libshare.PayForBlobNamespace.Bytes())},
			func(in inputs) (inputs, error) { in.ns = libshare.PayForBlobNamespace; return in, nil }},
	}
	if len(multi.Expect.Rows) >= 2 {
		steps = append(steps, struct {
			c     liveCase
			id    string
			desc  string
			o     op
			apply func(inputs) (inputs, error)
		}{multi, "swap_rows", "Rows 0 and 1 of the namespace data swapped: each row is checked against the row root at its own index.",
			op{Kind: "swap_rows", Row: "0", Row2: "1"},
			func(in inputs) (inputs, error) {
				in.edit = func(nd shwap.NamespaceData) (shwap.NamespaceData, error) {
					nd = cloneND(nd)
					nd[0], nd[1] = nd[1], nd[0]
					return nd, nil
				}
				return in, nil
			}})
	}
	for _, s := range steps {
		if err := add(s.c, s.id, s.desc, s.o, s.apply); err != nil {
			return nil, err
		}
	}
	return ms, nil
}

func synthTx(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(7*i)
	}
	return b
}

func split(txs ...[]byte) ([]libshare.Share, error) {
	css := libshare.NewCompactShareSplitter(pffNS, libshare.ShareVersionZero)
	for _, tx := range txs {
		if err := css.WriteTx(tx); err != nil {
			return nil, err
		}
	}
	return css.Export()
}

func rawShares(ss []libshare.Share) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = bytes.Clone(s.ToBytes())
	}
	return out
}

func toShares(raw [][]byte) ([]libshare.Share, error) {
	out := make([]libshare.Share, len(raw))
	for i, r := range raw {
		s, err := libshare.NewShare(r)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

const (
	nsEnd       = libshare.NamespaceSize
	seqLenAt    = nsEnd + libshare.ShareInfoBytes
	firstResAt  = seqLenAt + libshare.SequenceLenBytes
	contResAt   = nsEnd + libshare.ShareInfoBytes
	firstDataAt = firstResAt + libshare.ShareReservedBytes
)

func putU32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func getU32(b []byte, at int) uint32 {
	return uint32(b[at])<<24 | uint32(b[at+1])<<16 | uint32(b[at+2])<<8 | uint32(b[at+3])
}

func reassemblyCases() ([]reassemblyCase, error) {
	tA := synthTx(100, 0x11)
	tB := synthTx(600, 0x22)
	tC := synthTx(900, 0x33)
	// One delimited unit of exactly the first share's content: a 2-byte
	// varint and 472 bytes.
	tFill := synthTx(libshare.FirstCompactShareContentSize-2, 0x44)
	tD := synthTx(50, 0x55)

	type mk struct {
		id, desc string
		build    func() ([][]byte, error)
	}
	from := func(txs ...[]byte) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			s, err := split(txs...)
			if err != nil {
				return nil, err
			}
			return rawShares(s), nil
		}
	}
	edit := func(txs [][]byte, f func([][]byte) ([][]byte, error)) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			s, err := split(txs...)
			if err != nil {
				return nil, err
			}
			return f(rawShares(s))
		}
	}
	cases := []mk{
		{"empty", "No shares: the block has no PayForFibre namespace (only valid when the DAH proves no row holds it).", func() ([][]byte, error) { return [][]byte{}, nil }},
		{"one_tx", "One 100-byte tx in one share.", from(tA)},
		{"two_txs", "Txs of 600 and 900 bytes across four shares.", from(tB, tC)},
		{"unit_fills_first_share", "A unit that ends exactly at the end of the first share, then a 50-byte tx: the second share's reserved bytes point at its first data byte.", from(tFill, tD)},
		{"missing_last_share", "two_txs without its last share: the last tx is cut.", edit([][]byte{tB, tC}, func(s [][]byte) ([][]byte, error) { return s[:len(s)-1], nil })},
		{"missing_first_share", "two_txs without its first share: no sequence start.", edit([][]byte{tB, tC}, func(s [][]byte) ([][]byte, error) { return s[1:], nil })},
		{"extra_zero_share", "one_tx followed by a continuation share of zeros (reserved bytes 0) in the same namespace.", edit([][]byte{tA}, func(s [][]byte) ([][]byte, error) {
			z := make([]byte, libshare.ShareSize)
			copy(z, s[0][:nsEnd])
			return append(s, z), nil
		})},
		{"sequence_len_cuts_last_unit", "two_txs with the sequence length lowered by 10: the share count still matches, the last unit no longer fits, and ParseTxs drops it without an error.", edit([][]byte{tB, tC}, func(s [][]byte) ([][]byte, error) {
			putU32(s[0], seqLenAt, getU32(s[0], seqLenAt)-10)
			return s, nil
		})},
		{"sequence_len_beyond_units", "one_tx with the sequence length raised by 5: the extra bytes are zero padding inside the sequence, which ParseTxs reads as the end.", edit([][]byte{tA}, func(s [][]byte) ([][]byte, error) {
			putU32(s[0], seqLenAt, getU32(s[0], seqLenAt)+5)
			return s, nil
		})},
		{"reserved_bytes_shifted", "two_txs with the reserved bytes of the second share pointing one byte later.", edit([][]byte{tB, tC}, func(s [][]byte) ([][]byte, error) {
			v := getU32(s[1], contResAt)
			if v == 0 {
				return nil, errors.New("second share starts no unit")
			}
			putU32(s[1], contResAt, v+1)
			return s, nil
		})},
		{"two_sequences", "The shares of one_tx followed by the shares of a second, separately split 50-byte tx: two sequence starts.", func() ([][]byte, error) {
			a, err := split(tA)
			if err != nil {
				return nil, err
			}
			b, err := split(tD)
			if err != nil {
				return nil, err
			}
			return append(rawShares(a), rawShares(b)...), nil
		}},
		{"nonzero_padding", "one_tx with its last padding byte set to 0x01.", edit([][]byte{tA}, func(s [][]byte) ([][]byte, error) {
			s[len(s)-1][libshare.ShareSize-1] = 0x01
			return s, nil
		})},
		{"share_version_1", "one_tx with the info byte of its share set to version 1 (still a sequence start).", edit([][]byte{tA}, func(s [][]byte) ([][]byte, error) {
			s[0][nsEnd] = 1<<1 | 1
			return s, nil
		})},
		{"other_namespace", "one_tx split in the PayForBlob namespace.", func() ([][]byte, error) {
			css := libshare.NewCompactShareSplitter(libshare.PayForBlobNamespace, libshare.ShareVersionZero)
			if err := css.WriteTx(tA); err != nil {
				return nil, err
			}
			s, err := css.Export()
			if err != nil {
				return nil, err
			}
			return rawShares(s), nil
		}},
	}

	var out []reassemblyCase
	for _, c := range cases {
		raw, err := c.build()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.id, err)
		}
		rc := reassemblyCase{ID: c.id, Description: c.desc, Shares: []string{}}
		for _, r := range raw {
			rc.Shares = append(rc.Shares, hx(r))
		}
		shares, err := toShares(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.id, err)
		}
		if len(shares) == 0 {
			rc.Upstream = "0 txs"
		} else if up, err := libshare.ParseTxs(shares); err != nil {
			rc.Upstream = "error"
		} else {
			rc.Upstream = itoa(len(up)) + " txs"
		}
		txs, err := reassemble(shares)
		if err != nil {
			rc.Expect = reassemblyExpect{Verdict: "reject", Fails: "NA4"}
		} else {
			hs := []string{}
			for _, tx := range txs {
				hs = append(hs, sha(tx))
			}
			rc.Expect = reassemblyExpect{Verdict: "accept", Txs: &hs}
		}
		out = append(out, rc)
	}
	return out, nil
}

func build(in liveInput) (file, error) {
	f := file{
		Format:    "edicta-vectors/v0",
		Revision:  revision,
		Generator: "spec/vectors/tools/fibreanchor-gen",
		Upstream: map[string]string{
			"celestia-app":  "github.com/celestiaorg/celestia-app/v10 v10.4.0-mocha (pkg/da.DataAvailabilityHeader ValidateBasic and Hash, proto celestia.core.v1.da.DataAvailabilityHeader, x/fibre/types.TryParseFibreTx)",
			"celestia-node": "github.com/celestiaorg/celestia-node v0.34.2-mocha (share/shwap.NamespaceData ReadFrom, WriteTo and Verify, share.RowsWithNamespace)",
			"go-square":     "github.com/celestiaorg/go-square/v4 v4.0.1 (share.ParseTxs, share.NewCompactShareSplitter)",
			"nmt":           "github.com/celestiaorg/nmt v0.24.5 (Proof.VerifyNamespace, with the completeness fix for truncated proofs)",
			"replace_set":   "identical to github.com/celestiaorg/celestia-node v0.34.2-mocha go.mod",
		},
		Rules: map[string]string{
			"NA2":        "The DAH passes ValidateBasic (row and column root counts equal, each between 2 and 1024) and its Hash (RFC 6962 root over row_roots || column_roots) equals data_hash of the header at the height.",
			"NA3":        "The namespace data decodes (a sequence of uvarint-length-prefixed shwap.RowNamespaceData protobufs, nothing after the last) and NamespaceData.Verify(dah, PayForFibreNamespace) passes: exactly one entry per row whose row root's namespace range covers the namespace, in ascending row order, each a complete NMT namespace proof (inclusion with shares, or absence without) against the row root at that index.",
			"NA4":        "S = the shares of all rows in order. Empty S: no txs. Otherwise T = ParseTxs(S), and splitting T again with NewCompactShareSplitter(PayForFibreNamespace, 0) MUST give exactly S (same count, byte-equal shares).",
			"selection":  "Candidates: Fibre txs (TryParseFibreTx) of T whose promise has the queried namespace, commitment, blob_version 0 and chain id. queries[].anchor assumes every candidate executed with code 0: the earliest creation timestamp, then the lowest position in T. With other codes the gate skips non-zero candidates (section 10.4).",
			"mutation":   "op.kind: flip (target data_hash, row_root or column_root at index, or share at row/share: byte at offset XOR xor), move_column_root_to_rows, drop_share, drop_row, dup_row, swap_rows, set_max_ns_ignored, truncate_stream (drop the last bytes of namespace_data_hex), verify_namespace (verify for another namespace). Row and share 'last' mean the last one. Edits to rows and shares apply to the decoded namespace data, before NA3. fails is the first rule that rejects; upstream_error is informational.",
			"archive":    "archive_proof is the system_blob_proof field of an archive evidence record for da = 1, anchor-proof form 1 (section 19.2): deterministic CBOR map {1: 1, 2: bstr dah_proto, 3: bstr namespace data stream}.",
			"reassembly": "Synthetic shares in the PayForFibre namespace, NA4 only (no NMT proof). upstream_parse_txs is what go-square ParseTxs alone returns, to show what NA4 adds.",
		},
		Namespace: hx(pffNS.Bytes()),
	}
	f.Live = liveDoc{
		Description: "PayForFibre namespace data at Mocha heights 1402819 (the PFF of fibre_cert.json) and 1439696, with the DAH of each header.",
		Source:      in.Source,
	}
	for _, r := range in.Raw {
		c, err := liveCaseFor(r)
		if err != nil {
			return f, err
		}
		f.Live.Cases = append(f.Live.Cases, c)
	}
	sort.SliceStable(f.Live.Cases, func(i, j int) bool { return f.Live.Cases[i].ID < f.Live.Cases[j].ID })
	var err error
	if f.Mutations, err = mutations(f.Live.Cases); err != nil {
		return f, err
	}
	if f.Reassembly, err = reassemblyCases(); err != nil {
		return f, err
	}
	return f, nil
}

func nmtInclusion(start, end int, nodes [][]byte, ignoreMax bool) nmt.Proof {
	return nmt.NewInclusionProof(start, end, nodes, ignoreMax)
}
