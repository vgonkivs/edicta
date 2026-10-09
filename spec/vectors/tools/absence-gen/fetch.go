package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/header"
	"github.com/celestiaorg/celestia-node/share/shwap"
	"github.com/celestiaorg/go-square/v4/inclusion"
	libshare "github.com/celestiaorg/go-square/v4/share"
	blobtx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cometbft/cometbft/crypto/merkle"
	core "github.com/cometbft/cometbft/types"
)

const chainID = "mocha-5"

// Heights picked by hand from Mocha (task 031 P3 notes): a block with one
// normal tx and no PFF; a block with two share-version-1 blob txs and eight
// PFFs; a block with a failed normal tx (code 4), two blob txs and three
// PFFs, whose codes are not uniform; and three heights of the namespace an
// Edicta live run posted a share-version-1 blob to.
const (
	hNoPFF        = 1403118
	hOtherPFFs    = 1439495
	hPresentPFF   = 1197863
	presentPos    = 0
	hBlobPresent  = 1403104
	hBlobEmpty    = 1403105
	hBlobOther    = 1385832
	blobNSHex     = "00000000000000000000000000000000000000455c5c41bdb7aa55390b"
	blobSignerHex = "d6771a055f293733ad19b935f7d37e0db84899a2"
	// The payload_ref of v1/valid.json v1_pending_fibre, as in the synthetic cases.
	pendingNSHex  = "000000000000000000000000000000000000006564696374612f643031"
	pendingComHex = "13247a87a27789c3d23a82f82a0c107424c4a47a8a7867a2b61b0ee7cd02dc20"
)

const maxResponse = 64 << 20

type endpoints struct{ bridge, rpc, rpc2 string }

type fetcher struct {
	c     *http.Client
	ep    endpoints
	reads map[string][]string
	order []string
}

func (f *fetcher) note(what, endpoint string, h uint64) {
	k := what + "\x00" + endpoint
	if _, ok := f.reads[k]; !ok {
		f.order = append(f.order, k)
	}
	f.reads[k] = append(f.reads[k], utoa(h))
}

func body(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, fmt.Errorf("response above %d bytes", maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, b)
	}
	return b, nil
}

func (f *fetcher) bridgeCall(method, params string, h uint64) (json.RawMessage, error) {
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params)
	resp, err := f.c.Post(f.ep.bridge, "application/json", strings.NewReader(req))
	if err != nil {
		return nil, err
	}
	b, err := body(resp)
	if err != nil {
		return nil, err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, env.Error)
	}
	f.note("bridge "+method, f.ep.bridge, h)
	return env.Result, nil
}

func (f *fetcher) rpcGet(base, path string, h uint64, out any) error {
	resp, err := f.c.Get(fmt.Sprintf("%s/%s?height=%d", base, path, h))
	if err != nil {
		return err
	}
	b, err := body(resp)
	if err != nil {
		return err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	f.note("CometBFT /"+path, base, h)
	return json.Unmarshal(env.Result, out)
}

// header returns the bridge's signed header (protobuf) and DAH at h, after
// checking that the DAH hashes to data_hash.
func (f *fetcher) header(h uint64) ([]byte, *da.DataAvailabilityHeader, []byte, error) {
	res, err := f.bridgeCall("header.GetByHeight", fmt.Sprintf("[%d]", h), h)
	if err != nil {
		return nil, nil, nil, err
	}
	var eh header.ExtendedHeader
	if err := json.Unmarshal(res, &eh); err != nil {
		return nil, nil, nil, fmt.Errorf("header %d: %w", h, err)
	}
	if eh.Height() != h || eh.DAH == nil || !bytes.Equal(eh.DAH.Hash(), eh.DataHash) {
		return nil, nil, nil, fmt.Errorf("bridge header %d: wrong height or DAH", h)
	}
	sh := core.SignedHeader{Header: &eh.RawHeader, Commit: eh.Commit}
	b, err := sh.ToProto().Marshal()
	if err != nil {
		return nil, nil, nil, err
	}
	return b, eh.DAH, eh.Hash(), nil
}

func (f *fetcher) nsData(h uint64, ns libshare.Namespace) ([]byte, shwap.NamespaceData, error) {
	res, err := f.bridgeCall("share.GetNamespaceData", fmt.Sprintf(`[%d,%q]`, h, base64.StdEncoding.EncodeToString(ns.Bytes())), h)
	if err != nil {
		return nil, nil, err
	}
	var nd shwap.NamespaceData
	if err := json.Unmarshal(res, &nd); err != nil {
		return nil, nil, fmt.Errorf("namespace data %d: %w", h, err)
	}
	var stream bytes.Buffer
	if _, err := nd.WriteTo(&stream); err != nil {
		return nil, nil, err
	}
	return stream.Bytes(), nd, nil
}

// trusted reads the block hash at h from both consensus RPCs; they and the
// bridge must agree.
func (f *fetcher) trusted(h uint64, bridgeHash []byte) (string, error) {
	var hashes []string
	for _, base := range []string{f.ep.rpc, f.ep.rpc2} {
		var r struct {
			SignedHeader struct {
				Header struct {
					Height string `json:"height"`
				} `json:"header"`
				Commit struct {
					BlockID struct {
						Hash string `json:"hash"`
					} `json:"block_id"`
				} `json:"commit"`
			} `json:"signed_header"`
		}
		if err := f.rpcGet(base, "commit", h, &r); err != nil {
			return "", fmt.Errorf("%s /commit %d: %w", base, h, err)
		}
		if r.SignedHeader.Header.Height != utoa(h) {
			return "", fmt.Errorf("%s /commit: asked %d, got %s", base, h, r.SignedHeader.Header.Height)
		}
		hashes = append(hashes, strings.ToLower(r.SignedHeader.Commit.BlockID.Hash))
	}
	if hashes[0] != hashes[1] || hashes[0] != hx(bridgeHash) {
		return "", fmt.Errorf("block hash at %d: %v, bridge %x", h, hashes, bridgeHash)
	}
	return hashes[0], nil
}

// results returns the /block_results JSON reduced to the fields the results
// proof reads.
func (f *fetcher) results(h uint64) ([]byte, error) {
	var r struct {
		Height     string `json:"height"`
		TxsResults []struct {
			Code      uint32 `json:"code"`
			Data      []byte `json:"data"`
			GasWanted string `json:"gas_wanted"`
			GasUsed   string `json:"gas_used"`
		} `json:"txs_results"`
	}
	if err := f.rpcGet(f.ep.rpc, "block_results", h, &r); err != nil {
		return nil, err
	}
	var sr servedResults
	sr.Height = r.Height
	for _, x := range r.TxsResults {
		sr.TxsResults = append(sr.TxsResults, struct {
			Code      uint32 `json:"code"`
			Data      []byte `json:"data,omitempty"`
			GasWanted string `json:"gas_wanted"`
			GasUsed   string `json:"gas_used"`
		}{x.Code, x.Data, x.GasWanted, x.GasUsed})
	}
	return json.Marshal(sr)
}

type caseSpec struct {
	id, description string
	q               queryDoc
	heights         []uint64
	ns              libshare.Namespace
	withResults     bool
}

func (f *fetcher) record(cs caseSpec, h uint64, trusted map[string]string) (parts, error) {
	hdr, dah, hash, err := f.header(h)
	if err != nil {
		return parts{}, err
	}
	if trusted[utoa(h)], err = f.trusted(h, hash); err != nil {
		return parts{}, err
	}
	dp, err := (&daproto.DataAvailabilityHeader{RowRoots: dah.RowRoots, ColumnRoots: dah.ColumnRoots}).Marshal()
	if err != nil {
		return parts{}, err
	}
	stream, nd, err := f.nsData(h, cs.ns)
	if err != nil {
		return parts{}, err
	}
	if err := nd.Verify(dah, cs.ns); err != nil {
		return parts{}, fmt.Errorf("namespace data %d: %w", h, err)
	}
	ns, _ := hex.DecodeString(cs.q.Namespace)
	com, _ := hex.DecodeString(cs.q.Commitment)
	da, _ := strconv.ParseUint(cs.q.DA, 10, 64)
	p := parts{da: da, commitment: com, namespace: ns, height: h, header: hdr, dah: dp, nsData: stream}
	if cs.withResults {
		if p.results, err = f.results(h); err != nil {
			return parts{}, err
		}
		var nhash []byte
		if p.nextHeader, _, nhash, err = f.header(h + 1); err != nil {
			return parts{}, err
		}
		if trusted[utoa(h+1)], err = f.trusted(h+1, nhash); err != nil {
			return parts{}, err
		}
	}
	return p, nil
}

// tail reads data.txs at h, classifies them with celestia-app, rebuilds the
// square with ConstructEDS and compares its data root with data_hash.
func (f *fetcher) tail(h uint64, caseID string) (tailBlock, error) {
	var r struct {
		Block struct {
			Header struct {
				Version struct {
					App string `json:"app"`
				} `json:"version"`
				DataHash string `json:"data_hash"`
			} `json:"header"`
			Data struct {
				Txs [][]byte `json:"txs"`
			} `json:"data"`
		} `json:"block"`
	}
	if err := f.rpcGet(f.ep.rpc, "block", h, &r); err != nil {
		return tailBlock{}, err
	}
	txs := r.Block.Data.Txs
	classified, err := fibretypes.ClassifyTxs(txs)
	if err != nil {
		return tailBlock{}, err
	}
	eds, err := da.ConstructEDS(txs, pinnedAppVersion, -1)
	if err != nil {
		return tailBlock{}, err
	}
	dah, err := da.NewDataAvailabilityHeader(eds)
	if err != nil {
		return tailBlock{}, err
	}
	if !strings.EqualFold(hx(dah.Hash()), r.Block.Header.DataHash) {
		return tailBlock{}, fmt.Errorf("rebuilt data root %x, data_hash %s", dah.Hash(), r.Block.Header.DataHash)
	}
	b := tailBlock{Height: utoa(h), Case: caseID, AppVer: r.Block.Header.Version.App,
		Construct: "At fetch time: celestia-app pkg/da.ConstructEDS(data.txs, 10, -1) (ClassifyTxs, then go-square Construct) " +
			"rebuilt the square of these txs and its DAH hash equals data_hash of the header at this height."}
	first := -1
	for i, tx := range txs {
		class := "normal"
		if classified[i].FibreTx != nil {
			class = "fibre"
			if first < 0 {
				first = i
			}
		} else if _, ok, _ := blobtx.UnmarshalBlobTx(tx); ok {
			class = "blob"
		}
		b.Txs = append(b.Txs, tailTx{Index: strconv.Itoa(i), Class: class, Size: strconv.Itoa(len(tx)), SHA256: sha(tx)})
	}
	b.FibreFrom = strconv.Itoa(first)
	return b, nil
}

func fetch(ep endpoints) (input, error) {
	f := &fetcher{c: &http.Client{Timeout: 90 * time.Second}, ep: ep, reads: map[string][]string{}}
	nsb, err := hex.DecodeString(blobNSHex)
	if err != nil {
		return input{}, err
	}
	blobNS, err := libshare.NewNamespaceFromBytes(nsb)
	if err != nil {
		return input{}, err
	}
	signer, err := hex.DecodeString(blobSignerHex)
	if err != nil {
		return input{}, err
	}

	// The blob query: the share-version-1 blob of the Edicta signer at hBlobPresent.
	_, nd, err := f.nsData(hBlobPresent, blobNS)
	if err != nil {
		return input{}, err
	}
	blobs, err := libshare.ParseBlobs(nd.Flatten())
	if err != nil {
		return input{}, err
	}
	var blobCom []byte
	for _, b := range blobs {
		if b.ShareVersion() == libshare.ShareVersionOne && bytes.Equal(b.Signer(), signer) {
			if blobCom, err = inclusion.CreateCommitment(b, merkle.HashFromByteSlices, subtreeRootThreshold); err != nil {
				return input{}, err
			}
		}
	}
	if blobCom == nil {
		return input{}, fmt.Errorf("no share version 1 blob of the signer at %d", hBlobPresent)
	}

	// The Fibre query of the present case: the promise of the PFF at presentPos.
	_, nd, err = f.nsData(hPresentPFF, pffNS)
	if err != nil {
		return input{}, err
	}
	units, err := reassemble(nd.Flatten())
	if err != nil || len(units) <= presentPos {
		return input{}, fmt.Errorf("PFF units at %d: %v", hPresentPFF, err)
	}
	msg, err := promiseOf(units[presentPos])
	if err != nil {
		return input{}, err
	}
	pp := msg.PaymentPromise

	q := func(da string, ns, com, signer string, h0, d uint64) queryDoc {
		return queryDoc{DA: da, Namespace: ns, Commitment: com, Signer: signer, ChainID: chainID, H0: utoa(h0), AnchorDeadline: utoa(d)}
	}
	pendingFibre := func(h uint64) queryDoc { return q("1", pendingNSHex, pendingComHex, "", h, h) }
	blobQ := func(h uint64) queryDoc { return q("2", blobNSHex, hx(blobCom), blobSignerHex, h, h) }
	specs := []caseSpec{
		{id: "fibre_no_pff_row", q: pendingFibre(hNoPFF), heights: []uint64{hNoPFF}, ns: pffNS,
			description: "Mocha block with one normal tx and no PayForFibre tx. Query: the payload_ref of v1/valid.json v1_pending_fibre with chain_id mocha-5. Row 0 holds PFF_NS in its namespace range; its entry is an NMT absence proof, so S is empty: absent by AB4."},
		{id: "fibre_other_pffs_only", q: pendingFibre(hOtherPFFs), heights: []uint64{hOtherPFFs}, ns: pffNS,
			description: "Mocha block with two share-version-1 blob txs and eight PayForFibre txs (also a block of live_tail_rule). Same query: the eight promises are for other commitments and namespaces, so no candidate: absent by AB4."},
		{id: "fibre_present_live", q: q("1", hx(pp.Namespace), hx(pp.Commitment), "", hPresentPFF, hPresentPFF), heights: []uint64{hPresentPFF}, ns: pffNS, withResults: true,
			description: "Mocha block with a failed normal tx (code 4), two blob txs and three PayForFibre txs (also a block of live_tail_rule). Query: the promise of the first PFF. The candidate is at position 0; the tail rule binds it to result 3 (code 0), so the anchor is present by AB5. The codes are not uniform, and binding by position alone would read result 0 (code 4) and report a false absence."},
		{id: "blob_empty_namespace", q: blobQ(hBlobEmpty), heights: []uint64{hBlobEmpty}, ns: blobNS,
			description: "celestia_blob query: the share-version-1 blob an Edicta live run posted at 1403104 (namespace, share commitment, signer). At the next height the namespace holds no share: absent by AB6."},
		{id: "blob_other_blobs", q: blobQ(hBlobOther), heights: []uint64{hBlobOther}, ns: blobNS,
			description: "Same query at 1385832, where the namespace holds another share-version-1 blob of the same signer (an earlier live run) with another commitment: absent by AB6."},
		{id: "blob_present", q: blobQ(hBlobPresent), heights: []uint64{hBlobPresent}, ns: blobNS,
			description: "Same query at 1403104, the height of the blob: present by AB6 (the commitment recomputed from the shares and the signer of the first share match)."},
	}

	in := input{}
	for _, cs := range specs {
		ci := caseInput{id: cs.id, description: cs.description, q: cs.q, trusted: map[string]string{}}
		for _, h := range cs.heights {
			p, err := f.record(cs, h, ci.trusted)
			if err != nil {
				return input{}, fmt.Errorf("%s at %d: %w", cs.id, h, err)
			}
			ci.recs = append(ci.recs, p)
		}
		in.cases = append(in.cases, ci)
	}
	in.tail.Description = "The AB5 tail rule on live Mocha blocks of app version 10. txs lists /block data.txs at the height (class from " +
		"celestia-app ClassifyTxs and go-square UnmarshalBlobTx, size and SHA-256 of the raw tx). A checker confirms that " +
		"the last p entries are fibre and are the PFF_NS units of the named case's record, in order, with p >= 2 and n > p; " +
		"at a height where the case's record has results, n equals the number of results, which the chain fixes."
	for _, t := range []struct {
		h  uint64
		id string
	}{{hPresentPFF, "fibre_present_live"}, {hOtherPFFs, "fibre_other_pffs_only"}} {
		b, err := f.tail(t.h, t.id)
		if err != nil {
			return input{}, fmt.Errorf("tail at %d: %w", t.h, err)
		}
		in.tail.Blocks = append(in.tail.Blocks, b)
	}

	in.source = liveSource{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		ChainID:   chainID,
		Generator: "spec/vectors/tools/absence-gen",
		Upstream: map[string]string{
			"celestia-app":  "github.com/celestiaorg/celestia-app/v10 v10.4.0-mocha (pkg/da DataAvailabilityHeader and ConstructEDS, x/fibre/types ClassifyTxs and TryParseFibreTx)",
			"celestia-core": "github.com/celestiaorg/celestia-core v0.42.0 as github.com/cometbft/cometbft (SignedHeaderFromProto, Header.Hash, NewResults(...).Hash, merkle.HashFromByteSlices)",
			"celestia-node": "github.com/celestiaorg/celestia-node v0.34.2-mocha (shwap.NamespaceData ReadFrom, WriteTo, Verify; share.RowsWithNamespace)",
			"go-square":     "github.com/celestiaorg/go-square/v4 v4.0.1 (share.ParseTxs, share.ParseBlobs, inclusion.CreateCommitment, tx.UnmarshalBlobTx)",
		},
		Endpoints: map[string]string{"bridge": ep.bridge, "rpc": ep.rpc, "rpc2": ep.rpc2},
		Note: "Read-only. Signed headers and DAHs from the bridge (header.GetByHeight), namespace data from the bridge " +
			"(share.GetNamespaceData), block results and data.txs from rpc. trusted_headers stands in for header trust: the " +
			"block hash at each height as both rpc and rpc2 (two operators) report it in /commit, equal to the hash of the " +
			"bridge's header. results keeps only the fields the results proof reads.",
	}
	for _, k := range f.order {
		w := strings.SplitN(k, "\x00", 2)
		in.source.Reads = append(in.source.Reads, sourceRead{What: w[0], Endpoint: w[1], Heights: strings.Join(f.reads[k], ",")})
	}
	return in, nil
}
