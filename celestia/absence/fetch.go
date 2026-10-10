package absence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
)

// MaxHeightBytes bounds what one height's proof may take: the archive's cap
// of a kind 14 record.
const MaxHeightBytes = 16 << 20

// ErrTooLarge: the proof of a height is above MaxHeightBytes.
var ErrTooLarge = errors.New("absence: proof of the height is too large")

// ProofSource serves the parts of an absence proof at a height, as a bridge
// node does. Nothing it serves is trusted.
type ProofSource interface {
	// SignedHeader is the protobuf SignedHeader at height.
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
	DAH(ctx context.Context, height uint64) (*da.DataAvailabilityHeader, error)
	NamespaceData(ctx context.Context, height uint64, ns libshare.Namespace) (shwap.NamespaceData, error)
}

// ResultsSource serves the transaction results of a block, as a CometBFT
// RPC does.
type ResultsSource interface {
	BlockResults(ctx context.Context, height uint64) ([]railverify.TxResult, error)
}

// Fetcher builds kind 14 records from online sources.
type Fetcher struct {
	proofs  ProofSource
	results ResultsSource
	name    string
}

// NewFetcher reads proofs from proofs and, for heights with a candidate,
// results from results; without a results source such a height stays
// unproven. name says where the proofs came from in the report.
func NewFetcher(proofs ProofSource, results ResultsSource, name string) (*Fetcher, error) {
	if proofs == nil {
		return nil, errors.New("absence: no proof source")
	}
	return &Fetcher{proofs: proofs, results: results, name: name}, nil
}

// Name is the source the proofs come from.
func (f *Fetcher) Name() string { return f.name }

// Fetch builds the record of q at h. It does not tie the record to the
// chain: the caller verifies it against trusted hashes before relying on it
// or storing it. q.ChainID may be empty; the header's chain id then decides
// whether a height has a candidate that needs its results.
func (f *Fetcher) Fetch(ctx context.Context, q Query, h uint64) (*archive.AbsenceProofRecord, error) {
	if err := q.validateTarget(); err != nil {
		return nil, err
	}
	sh, hash, chainID, err := f.signedHeader(ctx, h)
	if err != nil {
		return nil, err
	}
	dah, err := f.proofs.DAH(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("absence: DAH at %d: %w", h, err)
	}
	if dah == nil {
		return nil, fmt.Errorf("absence: no DAH at %d", h)
	}
	dahRaw, err := (&daproto.DataAvailabilityHeader{RowRoots: dah.RowRoots, ColumnRoots: dah.ColumnRoots}).Marshal()
	if err != nil {
		return nil, fmt.Errorf("absence: DAH at %d: %w", h, err)
	}
	ns := libshare.PayForFibreNamespace
	if q.DA == commitment.DACelestiaBlob {
		if ns, err = libshare.NewNamespaceFromBytes(q.Namespace); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrQuery, err)
		}
	}
	nd, err := f.proofs.NamespaceData(ctx, h, ns)
	if err != nil {
		return nil, fmt.Errorf("absence: namespace data at %d: %w", h, err)
	}
	var stream bytes.Buffer
	if _, err := nd.WriteTo(&stream); err != nil {
		return nil, fmt.Errorf("absence: namespace data at %d: %w", h, err)
	}
	rec := &archive.AbsenceProofRecord{
		DA: q.DA, Commitment: bytes.Clone(q.Commitment), Namespace: bytes.Clone(q.Namespace), Height: h,
		Header: sh, DAH: dahRaw, NamespaceData: stream.Bytes(),
	}
	if err := bounded(rec); err != nil {
		return nil, err
	}
	if q.DA != commitment.DAFibre || f.results == nil {
		return rec, nil
	}
	// Only a height with a candidate needs its results. Whether it has one
	// is read here against the header's own hash; the caller's check
	// against the chain decides what the record proves.
	q.ChainID = chainID
	o := VerifyHeight(rec, q, h, TrustedHashes{h: hash})
	if !errors.Is(o.Err, ErrResultsMissing) {
		return rec, nil
	}
	if rec.Results, err = f.blockResults(ctx, h); err != nil {
		return nil, err
	}
	if rec.NextHeader, _, _, err = f.signedHeader(ctx, h+1); err != nil {
		return nil, err
	}
	if err := bounded(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func bounded(rec *archive.AbsenceProofRecord) error {
	if n := Size(rec); n > MaxHeightBytes {
		return fmt.Errorf("%w: %d bytes at height %d", ErrTooLarge, n, rec.Height)
	}
	return nil
}

// Size is the number of proof bytes a record holds.
func Size(rec *archive.AbsenceProofRecord) int {
	return len(rec.Header) + len(rec.DAH) + len(rec.NamespaceData) + len(rec.Results) + len(rec.NextHeader)
}

func (f *Fetcher) signedHeader(ctx context.Context, h uint64) ([]byte, []byte, string, error) {
	raw, err := f.proofs.SignedHeader(ctx, h)
	if err != nil {
		return nil, nil, "", fmt.Errorf("absence: signed header at %d: %w", h, err)
	}
	var pb cmtproto.SignedHeader
	if err := pb.Unmarshal(raw); err != nil {
		return nil, nil, "", fmt.Errorf("absence: signed header at %d: %w", h, err)
	}
	sh, err := core.SignedHeaderFromProto(&pb)
	if err != nil {
		return nil, nil, "", fmt.Errorf("absence: signed header at %d: %w", h, err)
	}
	if sh.Height < 0 || uint64(sh.Height) != h {
		return nil, nil, "", fmt.Errorf("absence: asked for the header at %d, got %d", h, sh.Height)
	}
	return raw, sh.Header.Hash(), sh.ChainID, nil
}

// resultsJSON is the result object the results proof reads: per result the
// code, the data in base64 and the gas values as decimal strings.
type resultsJSON struct {
	Height     string       `json:"height"`
	TxsResults []resultJSON `json:"txs_results"`
}

type resultJSON struct {
	Code      uint32 `json:"code"`
	Data      string `json:"data,omitempty"`
	GasWanted string `json:"gas_wanted"`
	GasUsed   string `json:"gas_used"`
}

func (f *Fetcher) blockResults(ctx context.Context, h uint64) ([]byte, error) {
	rs, err := f.results.BlockResults(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("absence: results at %d: %w", h, err)
	}
	out := resultsJSON{Height: strconv.FormatUint(h, 10), TxsResults: make([]resultJSON, len(rs))}
	for i, r := range rs {
		out.TxsResults[i] = resultJSON{Code: r.Code, GasWanted: strconv.FormatInt(r.GasWanted, 10), GasUsed: strconv.FormatInt(r.GasUsed, 10)}
		if len(r.Data) > 0 {
			out.TxsResults[i].Data = base64.StdEncoding.EncodeToString(r.Data)
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("absence: results at %d: %w", h, err)
	}
	return b, nil
}
