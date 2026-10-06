package gatechain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
)

// ErrInvalidConfig means an options struct failed its stateless checks.
var ErrInvalidConfig = errors.New("gatechain: invalid config")

// DefaultFibreMaxReadBytes is the answer size limit WithDefaults sets.
const DefaultFibreMaxReadBytes = 16 << 20

// Upper bounds of the options: the archive holds an anchor proof of at most
// 2^22 bytes, and a cache of whole proofs must stay a bounded amount of memory.
const (
	maxFibreMaxReadBytes = 1 << 30
	maxFibreCacheEntries = 1024
)

// FibreAnchorOptions configures FibreAnchors.
type FibreAnchorOptions struct {
	// MaxReadBytes bounds the encoded namespace data of one lookup; a larger
	// answer is unavailable, never an absent anchor.
	MaxReadBytes uint64
	// SkipCertificate turns the validator certificate check off. The zero value
	// checks it.
	SkipCertificate bool
	// CacheEntries bounds the anchors kept per reference; zero keeps none.
	CacheEntries int
	// Log receives the certificate warnings; nil is slog.Default.
	Log *slog.Logger
}

// WithDefaults fills the zero fields that have defaults.
func (o FibreAnchorOptions) WithDefaults() FibreAnchorOptions {
	if o.MaxReadBytes == 0 {
		o.MaxReadBytes = DefaultFibreMaxReadBytes
	}
	return o
}

// ValidateBasic checks the stateless fields.
func (o FibreAnchorOptions) ValidateBasic() error {
	if o.MaxReadBytes == 0 {
		return fmt.Errorf("%w: max read bytes is zero", ErrInvalidConfig)
	}
	if o.MaxReadBytes > maxFibreMaxReadBytes {
		return fmt.Errorf("%w: max read bytes %d above %d", ErrInvalidConfig, o.MaxReadBytes, uint64(maxFibreMaxReadBytes))
	}
	if o.CacheEntries < 0 {
		return fmt.Errorf("%w: negative cache entries", ErrInvalidConfig)
	}
	if o.CacheEntries > maxFibreCacheEntries {
		return fmt.Errorf("%w: cache entries %d above %d", ErrInvalidConfig, o.CacheEntries, maxFibreCacheEntries)
	}
	return nil
}

// FibreAnchor is the PayForFibre tx that anchors a reference.
type FibreAnchor struct {
	Height uint64
	// BlockTime is the time of the verified header at Height, Unix seconds.
	BlockTime uint64
	TxHash    [32]byte
	Promise   fibrecert.Promise
	// Proof is the anchor proof as the archive stores it: the verified DAH and
	// namespace data of the block.
	Proof []byte
}

type anchorKey struct {
	height uint64
	ns     string
	commit string
}

// FibreAnchors finds the PayForFibre anchor of a da = 1 reference from the
// PayForFibre namespace data of the block at the reference height.
type FibreAnchors struct {
	r       node.FibreAnchorReader
	chainID string
	o       FibreAnchorOptions
	cfgErr  error
	log     *slog.Logger

	mu    sync.Mutex
	cache map[anchorKey]FibreAnchor
	order []anchorKey
}

var _ gate.AnchorSource = (*FibreAnchors)(nil)

// NewFibreAnchors reads from r and accepts only promises for chainID. A bad
// config or a missing dependency makes every lookup fail closed.
func NewFibreAnchors(r node.FibreAnchorReader, chainID string, o FibreAnchorOptions) *FibreAnchors {
	o = o.WithDefaults()
	a := &FibreAnchors{r: r, chainID: chainID, o: o, log: o.Log, cache: map[anchorKey]FibreAnchor{}}
	if a.log == nil {
		a.log = slog.Default()
	}
	switch {
	case o.ValidateBasic() != nil:
		a.cfgErr = o.ValidateBasic()
	case r == nil:
		a.cfgErr = fmt.Errorf("%w: no reader", ErrInvalidConfig)
	case chainID == "":
		a.cfgErr = fmt.Errorf("%w: no chain id", ErrInvalidConfig)
	}
	return a
}

type candidate struct {
	raw  []byte
	hash [32]byte
	pff  fibrecert.PFF
}

// FindAnchor returns the anchor height and the start of retention, the
// creation time of the promise.
func (a *FibreAnchors) FindAnchor(ctx context.Context, ref commitment.PayloadRef) (gate.Anchor, error) {
	fa, err := a.Lookup(ctx, ref)
	if err != nil {
		return gate.Anchor{}, err
	}
	var start uint64
	if s := fa.Promise.CreationTime.Unix(); s > 0 {
		start = uint64(s)
	}
	return gate.Anchor{Height: fa.Height, RetentionStart: start}, nil
}

// Lookup is the anchor lookup. The DAH and the namespace data from the bridge
// are checked against the data hash of the consensus header at ref.Height; the
// Fibre txs they hold are candidates when they carry the reference's namespace
// and commitment, blob version 0 and this chain. The earliest creation time
// with result code 0 and a valid certificate wins; ties go to the position in
// the namespace.
func (a *FibreAnchors) Lookup(ctx context.Context, ref commitment.PayloadRef) (FibreAnchor, error) {
	if a.cfgErr != nil {
		return FibreAnchor{}, unavailable(a.cfgErr)
	}
	if err := checkRef(ref); err != nil {
		return FibreAnchor{}, err
	}
	if err := ctx.Err(); err != nil {
		return FibreAnchor{}, unavailable(err)
	}
	key := anchorKey{ref.Height, string(ref.Namespace), string(ref.Commitment)}
	if fa, ok := a.cached(key); ok {
		return fa, nil
	}
	fa, err := a.find(ctx, ref)
	if err != nil {
		return FibreAnchor{}, err
	}
	a.store(key, fa)
	return fa, nil
}

// checkRef refuses a reference that cannot name a da = 1 blob before any chain
// read: that is a bad argument, not a statement about the chain.
func checkRef(ref commitment.PayloadRef) error {
	switch {
	case ref.DA != commitment.DAFibre:
		return fmt.Errorf("%w: da %d", commitment.ErrInvalidEnum, ref.DA)
	case ref.Height == 0:
		return fmt.Errorf("%w: height", commitment.ErrZeroValue)
	case len(ref.Namespace) != libshare.NamespaceSize:
		return fmt.Errorf("%w: namespace is %d bytes", commitment.ErrInvalidNamespace, len(ref.Namespace))
	case len(ref.Commitment) != len([32]byte{}):
		return fmt.Errorf("%w: commitment is %d bytes", commitment.ErrFieldSize, len(ref.Commitment))
	}
	return nil
}

func (a *FibreAnchors) cached(k anchorKey) (FibreAnchor, bool) {
	if a.o.CacheEntries == 0 {
		return FibreAnchor{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fa, ok := a.cache[k]
	return cloneAnchor(fa), ok
}

// cloneAnchor copies every slice of fa so a caller cannot reach the cache.
func cloneAnchor(fa FibreAnchor) FibreAnchor {
	fa.Proof = bytes.Clone(fa.Proof)
	fa.Promise.Namespace = bytes.Clone(fa.Promise.Namespace)
	fa.Promise.SignerKey = bytes.Clone(fa.Promise.SignerKey)
	return fa
}

func (a *FibreAnchors) store(k anchorKey, fa FibreAnchor) {
	if a.o.CacheEntries == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.cache[k]; !ok {
		for len(a.order) >= a.o.CacheEntries {
			delete(a.cache, a.order[0])
			a.order = a.order[1:]
		}
		a.order = append(a.order, k)
	}
	a.cache[k] = cloneAnchor(fa)
}

// verifiedBlock is what the proof steps established about the PayForFibre
// namespace of one block.
type verifiedBlock struct {
	txs       [][]byte
	proof     []byte
	blockTime time.Time
}

func (a *FibreAnchors) find(ctx context.Context, ref commitment.PayloadRef) (FibreAnchor, error) {
	vb, err := a.verifyNamespace(ctx, ref.Height)
	if err != nil {
		return FibreAnchor{}, err
	}
	want := [32]byte(ref.Commitment)
	var cands []candidate
	for _, raw := range vb.txs {
		pff, ok, err := fibrecert.ParsePFF(raw)
		if !ok || err != nil {
			continue
		}
		if fibrecert.CheckBinding(pff.Promise, bindingFor(a.chainID, ref.Namespace, want, pff)) != nil {
			continue
		}
		cands = append(cands, candidate{raw: raw, hash: sha256.Sum256(raw), pff: pff})
	}
	if len(cands) == 0 {
		return FibreAnchor{}, fmt.Errorf("%w: no Fibre tx for the reference at height %d", gate.ErrAnchorNotFound, ref.Height)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].pff.Promise.CreationTime.Before(cands[j].pff.Promise.CreationTime)
	})
	for _, c := range cands {
		// A code that cannot be read stops the lookup: this candidate may be
		// the anchor, and a later one must not stand in for it.
		code, err := a.r.TxCode(ctx, ref.Height, c.hash)
		if err != nil {
			return FibreAnchor{}, unavailable(fmt.Errorf("tx result: %w", err))
		}
		if code != 0 {
			continue
		}
		// The first candidate with code 0 is the anchor. If its certificate
		// fails there is no anchor; a later promise must not take its place.
		if !a.o.SkipCertificate {
			if err := a.certificate(ctx, c, bindingFor(a.chainID, ref.Namespace, want, c.pff)); err != nil {
				return FibreAnchor{}, err
			}
		}
		return FibreAnchor{Height: ref.Height, BlockTime: blockUnix(vb.blockTime), TxHash: c.hash, Promise: c.pff.Promise, Proof: vb.proof}, nil
	}
	return FibreAnchor{}, fmt.Errorf("%w: no candidate with result code 0 at height %d", gate.ErrAnchorNotFound, ref.Height)
}

// verifyNamespace runs the proof steps: the header from the consensus
// endpoint, the DAH against its data hash, the namespace data against the DAH,
// and the reassembly of the txs. Every failure is the answer of an endpoint,
// not a statement about the chain.
func (a *FibreAnchors) verifyNamespace(ctx context.Context, height uint64) (verifiedBlock, error) {
	hdr, err := a.r.Header(ctx, height)
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("header at %d: %w", height, err))
	}
	if err := heightcheck.HeaderHeight(hdr.Height, height); err != nil {
		return verifiedBlock{}, unavailable(err)
	}
	if len(hdr.DataHash) == 0 {
		return verifiedBlock{}, unavailable(fmt.Errorf("header at %d has no data hash", height))
	}
	if hdr.AppVersion != node.FibreAppVersion {
		return verifiedBlock{}, unavailable(fmt.Errorf("header at %d has app version %d, want %d", height, hdr.AppVersion, node.FibreAppVersion))
	}
	raw, err := a.r.DAH(ctx, height)
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("dah at %d: %w", height, err))
	}
	if raw == nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("dah at %d: empty", height))
	}
	// A fresh value: Hash caches its result in the struct it is called on.
	dah := &da.DataAvailabilityHeader{RowRoots: raw.RowRoots, ColumnRoots: raw.ColumnRoots}
	if err := fibreproof.CheckDAH(dah, hdr.DataHash); err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("dah at %d: %w", height, err))
	}
	got, err := a.r.NamespaceData(ctx, height, libshare.PayForFibreNamespace)
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("namespace data at %d: %w", height, err))
	}
	stream, err := encodeNamespaceData(got, a.o.MaxReadBytes)
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("namespace data at %d: %w", height, err))
	}
	// Verify what the archive will hold: the stream, decoded again.
	txs, err := fibreproof.VerifyNamespaceData(dah, stream)
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("namespace data at %d: %w", height, err))
	}
	dp, err := dah.ToProto()
	if err != nil {
		return verifiedBlock{}, unavailable(err)
	}
	dahProto, err := dp.Marshal()
	if err != nil {
		return verifiedBlock{}, unavailable(fmt.Errorf("dah at %d: %w", height, err))
	}
	return verifiedBlock{txs: txs, proof: fibreproof.EncodeProof(dahProto, stream), blockTime: hdr.Time}, nil
}

var errReadLimit = errors.New("answer above the read limit")

type limitWriter struct {
	buf   bytes.Buffer
	limit uint64
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if uint64(w.buf.Len())+uint64(len(p)) > w.limit {
		return 0, errReadLimit
	}
	return w.buf.Write(p)
}

func encodeNamespaceData(nd shwap.NamespaceData, limit uint64) ([]byte, error) {
	w := &limitWriter{limit: limit}
	if _, err := nd.WriteTo(w); err != nil {
		return nil, err
	}
	return w.buf.Bytes(), nil
}

func reassemble(shares []libshare.Share) ([][]byte, error) { return fibreproof.Reassemble(shares) }

// bindingFor takes the blob size from the promise itself: the reference does
// not carry it.
func bindingFor(chainID string, ns []byte, commit [32]byte, pff fibrecert.PFF) fibrecert.Binding {
	return fibrecert.Binding{ChainID: chainID, Namespace: ns, Commitment: commit, BlobSize: pff.Promise.BlobSize}
}

// certificate applies the network's quorum rule to c against the validator
// set the chain recorded at the promise height. Evidence that is missing or
// for another height is unavailable; a certificate that fails the rule is no
// anchor.
func (a *FibreAnchors) certificate(ctx context.Context, c candidate, b fibrecert.Binding) error {
	p := c.pff.Promise
	hist, err := a.r.HistoricalInfo(ctx, p.Height)
	if err != nil {
		return unavailable(fmt.Errorf("historical info at %d: %w", p.Height, err))
	}
	hdr, err := a.r.SignedHeader(ctx, p.Height)
	if err != nil {
		return unavailable(fmt.Errorf("header at %d: %w", p.Height, err))
	}
	if err := evidenceHeights(hist, hdr, p.Height); err != nil {
		return unavailable(err)
	}
	// The list and the evidence come from the chain endpoint: a list that
	// does not bind to the promise is an endpoint failure, whatever the
	// signatures on it say.
	ev := fibrecert.ValsetEvidence{PromiseHeader: hdr}
	if _, _, err := fibrecert.ValidatorsFor(hist, p, ev); err != nil {
		return unavailable(fmt.Errorf("validator list at %d: %w", p.Height, err))
	}
	rep, _, err := fibrecert.Verify(c.raw, b, hist, ev)
	if errors.Is(err, fibrecert.ErrValsetMismatch) {
		// The list and the header both come from the chain, not from the tx.
		return unavailable(err)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", gate.ErrAnchorNotFound, err)
	}
	if rep.AtMostTwoThirds {
		a.log.Warn("fibre certificate at or below two thirds of the power",
			"signed", rep.SignedPower, "total", rep.TotalPower, "promise_height", p.Height)
	}
	return nil
}

// evidenceHeights requires the historical info and the header to decode, to
// name the promise height and the header to carry the pinned app version.
func evidenceHeights(histRaw, hdrRaw []byte, height uint64) error {
	var hi stakingtypes.HistoricalInfo
	if err := hi.Unmarshal(histRaw); err != nil {
		return fmt.Errorf("historical info: %w", err)
	}
	var h cmtproto.Header
	if err := h.Unmarshal(hdrRaw); err != nil {
		return fmt.Errorf("promise header: %w", err)
	}
	if h.Version.App != node.FibreAppVersion {
		return fmt.Errorf("promise header has app version %d, want %d", h.Version.App, node.FibreAppVersion)
	}
	if height > math.MaxInt64 || hi.Header.Height != int64(height) || h.Height != int64(height) {
		return fmt.Errorf("%w: evidence at heights %d and %d, promise at %d",
			heightcheck.ErrHeightIgnored, hi.Header.Height, h.Height, height)
	}
	return nil
}

type fibreBlobs struct {
	a      *FibreAnchors
	direct node.FibreDownloader
	bridge node.FibreDownloader
	c      *fibrecommit.Committer
}

// NewFibreBlobs serves da = 1 blobs: the anchor must exist, then the blob is
// downloaded directly and, if that fails, from the bridge fallback (nil means
// direct only). Nothing is returned unless its size is the one the promise
// paid for and the committer accepts the bytes.
func NewFibreBlobs(a *FibreAnchors, direct, bridge node.FibreDownloader, c *fibrecommit.Committer) gate.BlobSource {
	return &fibreBlobs{a: a, direct: direct, bridge: bridge, c: c}
}

func (s *fibreBlobs) Fetch(ctx context.Context, ref commitment.PayloadRef, maxSize uint64) ([]byte, error) {
	if ref.DA != commitment.DAFibre {
		return nil, fmt.Errorf("%w: da %d", gate.ErrBlobNotFound, ref.DA)
	}
	if s.a == nil || s.direct == nil || s.c == nil {
		return nil, unavailable(fmt.Errorf("%w: incomplete blob source", ErrInvalidConfig))
	}
	fa, err := s.a.Lookup(ctx, ref)
	if err != nil {
		return nil, err
	}
	// maxSize+1 bytes are enough to tell the caller the blob is too big. A
	// blob whose paid upload size exceeds that of maxSize+1 bytes cannot fit.
	limit := uint64(fibrecommit.MaxDataSize)
	if maxSize < limit {
		limit = maxSize + 1
	}
	maxUpload, err := fibrecommit.UploadSize(limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, err)
	}
	if uint64(fa.Promise.BlobSize) > maxUpload {
		return nil, fmt.Errorf("%w: promised upload size %d needs more than %d bytes", gate.ErrPayloadAboveCap, fa.Promise.BlobSize, limit)
	}

	id := fibrecommit.BlobID([32]byte(ref.Commitment))
	var errs []error
	var oversize []byte
	transport := false
	for _, src := range []struct {
		d      node.FibreDownloader
		direct bool
	}{{s.direct, true}, {s.bridge, false}} {
		if src.d == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, unavailable(err)
		}
		// The promise names the upload size, which bounds any honest blob.
		data, err := src.d.Download(ctx, id, fa.Promise.Height, uint64(fa.Promise.BlobSize))
		if err != nil {
			transport = transport || !errors.Is(err, node.ErrNotFound)
			errs = append(errs, err)
			continue
		}
		up, err := fibrecommit.UploadSize(uint64(len(data)))
		if err != nil || up != uint64(fa.Promise.BlobSize) {
			errs = append(errs, fmt.Errorf("blob of %d bytes does not match the promised upload size %d", len(data), fa.Promise.BlobSize))
			continue
		}
		if uint64(len(data)) > maxSize {
			// Only the direct client is bound to the commitment, so only its
			// answer settles that the blob is too big. Encoding it for the
			// committer would only spend memory.
			if !src.direct {
				transport = true
				errs = append(errs, fmt.Errorf("bridge blob of %d bytes is above %d and cannot be verified", len(data), maxSize))
				continue
			}
			if oversize == nil {
				oversize = append([]byte(nil), data[:maxSize+1]...)
			}
			continue
		}
		if err := s.c.Check(ref, data); err != nil {
			errs = append(errs, err)
			continue
		}
		return append([]byte(nil), data...), nil
	}
	if oversize != nil {
		return oversize, nil
	}
	if transport {
		return nil, fmt.Errorf("gatechain: blob download: %w", errors.Join(errs...))
	}
	return nil, fmt.Errorf("%w: %w", gate.ErrBlobNotFound, errors.Join(errs...))
}

func blockUnix(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}
