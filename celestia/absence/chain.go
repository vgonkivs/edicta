package absence

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// SourceArchive names proofs read from the archive in the report.
const SourceArchive = "archive"

// HeaderSource serves canonical protobuf headers by height, untrusted.
type HeaderSource interface {
	Header(ctx context.Context, height uint64) ([]byte, error)
}

// ChainDeps are the sources of a Chain; each may be nil.
type ChainDeps struct {
	// Records are the archived absence proofs (kind 14).
	Records archive.AbsenceReader
	// Intents are the archived anchor intents (kind 13).
	Intents archive.IntentReader
	// Headers serve the header at h0 when no record holds it.
	Headers HeaderSource
	// Fetch builds the proofs the archive lacks from online sources.
	Fetch *Fetcher
}

// Chain serves the verifier's anchor check of pending references from
// archived and online absence proofs. Every proof is checked against header
// hashes the verifier confirms; no source is trusted.
type Chain struct{ d ChainDeps }

var _ verifier.PendingChain = (*Chain)(nil)

// NewChain returns a Chain over d.
func NewChain(d ChainDeps) *Chain { return &Chain{d: d} }

// Header returns the header at height: from the archived proof of ref at
// that height, else from the header source, else from the fetcher's proof
// source.
func (c *Chain) Header(ctx context.Context, ref commitment.PayloadRef, height uint64) (verifier.ChainHeader, error) {
	var errs []error
	if c.d.Records != nil {
		rec, err := c.d.Records.Absence(ctx, ref.DA, ref.Commitment, height)
		if err == nil {
			hd, herr := signedHeaderInfo(rec.Header, height)
			if herr == nil {
				return hd, nil
			}
			err = herr
		}
		if cerr := ctx.Err(); cerr != nil {
			return verifier.ChainHeader{}, cerr
		}
		errs = append(errs, fmt.Errorf("archive: %w", err))
	}
	if c.d.Headers != nil {
		raw, err := c.d.Headers.Header(ctx, height)
		if err == nil {
			hd, herr := headerInfo(raw, height)
			if herr == nil {
				return hd, nil
			}
			err = herr
		}
		if cerr := ctx.Err(); cerr != nil {
			return verifier.ChainHeader{}, cerr
		}
		errs = append(errs, fmt.Errorf("header source: %w", err))
	}
	if c.d.Fetch != nil {
		raw, err := c.d.Fetch.proofs.SignedHeader(ctx, height)
		if err == nil {
			hd, herr := signedHeaderInfo(raw, height)
			if herr == nil {
				return hd, nil
			}
			err = herr
		}
		if cerr := ctx.Err(); cerr != nil {
			return verifier.ChainHeader{}, cerr
		}
		errs = append(errs, fmt.Errorf("%s: %w", c.d.Fetch.name, err))
	}
	if len(errs) == 0 {
		return verifier.ChainHeader{}, fmt.Errorf("absence: no source for the header at %d", height)
	}
	return verifier.ChainHeader{}, errors.Join(errs...)
}

func signedHeaderInfo(raw []byte, height uint64) (verifier.ChainHeader, error) {
	var pb cmtproto.SignedHeader
	if err := pb.Unmarshal(raw); err != nil {
		return verifier.ChainHeader{}, fmt.Errorf("signed header: %w", err)
	}
	if pb.Header == nil {
		return verifier.ChainHeader{}, errors.New("signed header has no header")
	}
	inner, err := pb.Header.Marshal()
	if err != nil {
		return verifier.ChainHeader{}, err
	}
	return headerInfo(inner, height)
}

func headerInfo(raw []byte, height uint64) (verifier.ChainHeader, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return verifier.ChainHeader{}, fmt.Errorf("header: %w", err)
	}
	h, err := core.HeaderFromProto(&ph)
	if err != nil {
		return verifier.ChainHeader{}, fmt.Errorf("header: %w", err)
	}
	if h.Height < 0 || uint64(h.Height) != height {
		return verifier.ChainHeader{}, fmt.Errorf("header at %d claims height %d", height, h.Height)
	}
	if h.Time.Unix() < 0 {
		return verifier.ChainHeader{}, fmt.Errorf("header at %d is before 1970", height)
	}
	hash := h.Hash()
	if len(hash) != 32 {
		return verifier.ChainHeader{}, fmt.Errorf("header at %d has no hash", height)
	}
	return verifier.ChainHeader{Hash: hash, Time: uint64(h.Time.Unix())}, nil
}

// Absence checks [ref.Height, deadline]: the archived proof of each height,
// or a fetched one where the archive has none that decodes. A header hash
// confirm refuses leaves its height unproven.
func (c *Chain) Absence(ctx context.Context, ref commitment.PayloadRef, deadline uint64, confirm verifier.Confirm) (verifier.AbsenceWindow, error) {
	h0 := ref.Height
	q := Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}
	if ref.DA == commitment.DACelestiaBlob {
		q.Signer = ref.Signer
	}
	unprovenAt := func(h uint64, err error) verifier.AbsenceWindow {
		return verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h, Cause: err}
	}
	if err := q.validateTarget(); err != nil {
		return unprovenAt(h0, err), nil
	}
	if h0 == 0 || deadline < h0 || deadline-h0 > MaxWindow {
		return unprovenAt(h0, fmt.Errorf("%w: [%d, %d]", ErrWindow, h0, deadline)), nil
	}

	recs := make(map[uint64]*archive.AbsenceProofRecord, deadline-h0+1)
	causes := map[uint64]error{}
	srcs := map[string]bool{}
	var size uint64
	for h := h0; h <= deadline; h++ {
		rec, src, err := c.record(ctx, q, h)
		if cerr := ctx.Err(); cerr != nil {
			return verifier.AbsenceWindow{}, cerr
		}
		if err != nil {
			causes[h] = err
			continue
		}
		recs[h], srcs[src] = rec, true
		size += uint64(Size(rec))
	}

	trusted := TrustedHashes{}
	chainID := ""
	tie := func(h uint64, raw []byte) {
		if _, done := trusted[h]; done || raw == nil {
			return
		}
		var pb cmtproto.SignedHeader
		if pb.Unmarshal(raw) != nil {
			return
		}
		sh, err := core.SignedHeaderFromProto(&pb)
		if err != nil || sh.Height < 0 || uint64(sh.Height) != h {
			return
		}
		hash := sh.Header.Hash()
		if confirm(ctx, h, hash) {
			trusted[h] = hash
			if chainID == "" {
				chainID = sh.ChainID
			}
		}
	}
	for h := h0; h <= deadline; h++ {
		if rec := recs[h]; rec != nil {
			tie(h, rec.Header)
			tie(h+1, rec.NextHeader)
		}
	}
	if cerr := ctx.Err(); cerr != nil {
		return verifier.AbsenceWindow{}, cerr
	}
	q.ChainID = chainID
	out := verifier.AbsenceWindow{Bytes: size, ChainID: chainID, Heights: int(deadline - h0 + 1)}
	for s := range srcs {
		out.Sources = append(out.Sources, s)
	}
	if q.DA == commitment.DAFibre && chainID == "" {
		// No header of the window is the chain's, so nothing is proven.
		out.Result, out.FirstUnproven = verifier.AbsenceUnproven, h0
		out.Cause = firstCause(causes, h0, fmt.Errorf("%w: no header of the window ties to the trusted chain", ErrHeader))
		return out, nil
	}
	w, err := VerifyWindow(q, h0, deadline, recs, trusted)
	if err != nil {
		return unprovenAt(h0, err), nil
	}
	if o := w.Heights[len(w.Heights)-1]; o.Rule == RuleResults {
		out.ResultsAtDeadline = true
	}
	switch w.Result {
	case Absent:
		out.Result = verifier.AbsenceAbsent
	case Present:
		out.Result, out.AnchorHeight = verifier.AbsencePresent, w.AnchorHeight
	default:
		out.Result, out.FirstUnproven = verifier.AbsenceUnproven, w.FirstUnproven
		out.Cause = w.Heights[w.FirstUnproven-h0].Err
		if cause, ok := causes[w.FirstUnproven]; ok {
			out.Cause = fmt.Errorf("%w: %w", out.Cause, cause)
		}
	}
	return out, nil
}

func firstCause(causes map[uint64]error, h uint64, fallback error) error {
	if err, ok := causes[h]; ok {
		return fmt.Errorf("%w: %w", fallback, err)
	}
	return fallback
}

// record reads the proof of h from the archive, or fetches it.
func (c *Chain) record(ctx context.Context, q Query, h uint64) (*archive.AbsenceProofRecord, string, error) {
	var errs []error
	if c.d.Records != nil {
		rec, err := c.d.Records.Absence(ctx, q.DA, q.Commitment, h)
		if err == nil {
			return rec, SourceArchive, nil
		}
		errs = append(errs, fmt.Errorf("archive: %w", err))
	}
	if c.d.Fetch != nil {
		rec, err := c.d.Fetch.Fetch(ctx, q, h)
		if err == nil {
			return rec, c.d.Fetch.name, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", c.d.Fetch.name, err))
	}
	if len(errs) == 0 {
		return nil, "", fmt.Errorf("%w: no absence source", ErrNoProof)
	}
	return nil, "", errors.Join(errs...)
}

// IntentSigner reads the archived anchor intent of ref and returns the hex
// address that signed its tx when the intent binds to ref: F2 (the promise
// for this blob, chain, upload size and h0, owner-signed, created_at) for
// da = 1, B2 for da = 2.
func (c *Chain) IntentSigner(ctx context.Context, ref commitment.PayloadRef, payloadSize uint64, chainID string) (string, error) {
	if c.d.Intents == nil {
		return "", nil
	}
	rec, err := c.d.Intents.Intent(ctx, ref.DA, ref.Commitment, ref.Height)
	if errors.Is(err, archive.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("absence: anchor intent: %w", err)
	}
	if !bytes.Equal(rec.Namespace, ref.Namespace) {
		return "", nil
	}
	switch ref.DA {
	case commitment.DAFibre:
		return fibreIntentSigner(rec, ref, payloadSize, chainID), nil
	case commitment.DACelestiaBlob:
		if !bytes.Equal(rec.Signer, ref.Signer) {
			return "", nil
		}
		if _, err := gatechain.CheckPFB(rec.Tx, ref); err != nil {
			return "", nil
		}
		return hex.EncodeToString(ref.Signer), nil
	}
	return "", nil
}

func fibreIntentSigner(rec *archive.AnchorIntentRecord, ref commitment.PayloadRef, payloadSize uint64, chainID string) string {
	if chainID == "" || len(ref.Commitment) != commitmentSize {
		return ""
	}
	f, ok, err := fibrecert.ParsePFF(rec.Tx)
	if !ok || err != nil {
		return ""
	}
	u, ok := fibreUploadSize(payloadSize)
	if !ok {
		return ""
	}
	b := fibrecert.Binding{ChainID: chainID, Namespace: ref.Namespace, BlobSize: u}
	copy(b.Commitment[:], ref.Commitment)
	if fibrecert.CheckBinding(f.Promise, b) != nil || f.Promise.Height != ref.Height || fibrecert.VerifyOwner(f) != nil {
		return ""
	}
	if created := f.Promise.CreationTime.Unix(); created <= 0 || uint64(created) != rec.CreatedAt {
		return ""
	}
	_, addr, err := bech32.DecodeAndConvert(f.Signer)
	if err != nil || len(addr) == 0 {
		return ""
	}
	return hex.EncodeToString(addr)
}

// fibreUploadSize is the paid upload size of a payload: 4096 bytes times the
// row count of the encoded blob (5-byte header included), rounded up to a
// multiple of 64 rows.
func fibreUploadSize(payloadSize uint64) (uint32, bool) {
	const maxPayload = 1 << 27
	if payloadSize == 0 || payloadSize > maxPayload {
		return 0, false
	}
	rows := (payloadSize + 5 + 4095) / 4096
	rows = (rows + 63) / 64 * 64
	return uint32(rows * 4096), true
}
