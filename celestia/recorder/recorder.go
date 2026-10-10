package recorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	ErrTooLarge       = errors.New("recorder: blob above MaxBlobBytes")
	ErrSignerMismatch = errors.New("recorder: anchored blob has another signer or share version")
	ErrNotVisible     = errors.New("recorder: anchor not visible on the read node in time")
	ErrOutcomeUnknown = errors.New("recorder: submit outcome unknown")
	// ErrNodeUnavailable means the read node failed for a reason other than
	// "not found"; the caller may retry.
	ErrNodeUnavailable = errors.New("recorder: node unavailable")
	ErrTooManyPending  = errors.New("recorder: too many blobs with an unresolved outcome")

	// ErrArchiveUnavailable means the archive write failed. Before a submit
	// nothing was submitted; after one, a retry resumes without paying again.
	ErrArchiveUnavailable = errors.New("recorder: archive unavailable")
	// ErrEscrowInsufficient means the escrow cannot pay for the upload;
	// nothing was submitted.
	ErrEscrowInsufficient = errors.New("recorder: escrow balance too low for this upload")
	// ErrSubmitMismatch means the node returned another blob id or promise
	// fields than computed locally; a fee may have been spent. It is sticky
	// per blob.
	ErrSubmitMismatch = errors.New("recorder: node returned another blob id than computed")
	// ErrAnchorRejected means a successful pay-for-fibre tx of the blob is on
	// chain but fails the certificate rule. It is sticky per blob: the escrow
	// was charged, so the blob is never submitted again.
	ErrAnchorRejected = errors.New("recorder: anchor on chain fails the certificate rule")
	// ErrClockSkew means the local clock, which dates the promise, is off the
	// chain head time by more than the allowed skew; nothing was submitted.
	ErrClockSkew = errors.New("recorder: local clock skewed against the chain")

	errBlobDiffers  = errors.New("recorder: anchored blob differs from the submitted one")
	errInvalidInput = errors.New("recorder: invalid configuration")
	errClosed       = errors.New("recorder: closed")
)

const (
	namespaceLen = 29
	signerLen    = 20
)

// Config configures a Recorder. Zero durations and sizes take defaults.
type Config struct {
	// Namespace is a 29-byte version 0 namespace.
	Namespace []byte
	// MaxBlobBytes defaults to 1 MiB.
	MaxBlobBytes uint64
	// SubmitTimeout bounds one Submit call including inclusion; default 90s.
	SubmitTimeout time.Duration
	// VisibleTimeout bounds the wait until the read node serves the anchor;
	// default 60s.
	VisibleTimeout time.Duration
	// PollInterval is the read node polling period; default 500ms.
	PollInterval time.Duration
	// ScanBlocks caps how many blocks one search for an earlier, ambiguous
	// submit reads per call, counted from the height before that submit. The
	// search resumes where it stopped. It cannot go below 1024.
	ScanBlocks uint64
	// SettleBlocks is the window in which an earlier process may still have
	// a submit pending in a mempool. After a restart the Recorder submits
	// only once the head is past max(intent height, the head this Recorder
	// first saw for the blob) + SettleBlocks and no earlier submit was found
	// in [intent height, that bound]. The window must exceed the mempool TTL
	// and, for a remote Submitter, its own retries, with room to spare.
	// Default 1024; a non-zero value below 256 is refused.
	SettleBlocks uint64
	// MaxPending caps blobs whose outcome is unresolved; a new blob is
	// refused with ErrTooManyPending at the cap. Default 4096.
	MaxPending int
	// Now is the clock for entry expiry; nil means time.Now.
	Now func() time.Time
	// Archive receives the payload before the submit and the anchor
	// evidence after the read-back. Nil means no archive writes, and then a
	// restart, which loses all memory of earlier submits, may submit a blob
	// again. With an archive there must be a single writer per (signer,
	// archive): two live Recorders on one archive can both submit once the
	// settle window has passed.
	Archive archive.Store
	// FastTimeoutBlocks is how many blocks above h0 the anchor tx of a
	// pending reference stays valid (NewFast only); default 100, else
	// 13..1000. It should exceed the gate's MaxH0AgeBlocks plus
	// MinFastSlackBlocks, or the gate refuses for lack of slack.
	FastTimeoutBlocks uint64
}

// headerReader is implemented by readers that can return the protobuf
// SignedHeader (header and commit) the evidence record stores.
type headerReader interface {
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
}

// Recorder implements sdk.Publisher for da = 2.
type Recorder struct {
	cfg Config
	sub Submitter
	rd  node.Reader
	eng *engine
	// fast is set by NewFast.
	fast *fastCore
}

var _ sdk.Publisher = (*Recorder)(nil)

// ValidateBasic checks the stateless fields.
func (c Config) ValidateBasic() error {
	if err := checkNamespace(c.Namespace); err != nil {
		return err
	}
	if c.SettleBlocks != 0 && c.SettleBlocks < settleFloor {
		return fmt.Errorf("%w: settle window of %d blocks is below %d", errInvalidInput, c.SettleBlocks, settleFloor)
	}
	if c.FastTimeoutBlocks != 0 && (c.FastTimeoutBlocks < minFastTimeoutBlocks || c.FastTimeoutBlocks > maxFastTimeoutBlocks) {
		return fmt.Errorf("%w: fast timeout of %d blocks is outside %d..%d", errInvalidInput, c.FastTimeoutBlocks, minFastTimeoutBlocks, maxFastTimeoutBlocks)
	}
	return nil
}

// New validates cfg and returns a Recorder.
func New(cfg Config, sub Submitter, rd node.Reader) (*Recorder, error) {
	if sub == nil || rd == nil {
		return nil, fmt.Errorf("%w: nil dependency", errInvalidInput)
	}
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if cfg.Archive != nil {
		if _, ok := rd.(headerReader); !ok {
			return nil, fmt.Errorf("%w: the reader cannot return signed headers, which the archive evidence needs", errInvalidInput)
		}
	}
	cfg.Namespace = bytes.Clone(cfg.Namespace)
	if cfg.MaxBlobBytes == 0 {
		cfg.MaxBlobBytes = 1 << 20
	}
	if cfg.SubmitTimeout <= 0 {
		cfg.SubmitTimeout = 90 * time.Second
	}
	if cfg.VisibleTimeout <= 0 {
		cfg.VisibleTimeout = 60 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.ScanBlocks < scanFloor {
		cfg.ScanBlocks = scanFloor
	}
	if cfg.SettleBlocks == 0 {
		cfg.SettleBlocks = settleDefault
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = defaultMaxPending
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Recorder{cfg: cfg, sub: sub, rd: rd, eng: newEngine(cfg.Archive, cfg.Now, cfg.MaxPending, cfg.ScanBlocks)}, nil
}

// checkNamespace accepts only user namespaces: version 0, 18 zero bytes, and a
// non-zero 10-byte id.
func checkNamespace(ns []byte) error {
	if len(ns) != namespaceLen || ns[0] != 0 {
		return fmt.Errorf("%w: namespace must be 29 bytes of version 0", errInvalidInput)
	}
	if !allZero(ns[1:19]) || allZero(ns[19:]) {
		return fmt.Errorf("%w: namespace is reserved or malformed", errInvalidInput)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Publish submits blob and returns once the anchor is verified on the read
// node; a Recorder built by NewFast returns the pending reference instead.
// It never modifies blob.
func (r *Recorder) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	if err := ctx.Err(); err != nil {
		return sdk.Published{}, err
	}
	if uint64(len(blob)) > r.cfg.MaxBlobBytes {
		return sdk.Published{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(blob))
	}
	if r.fast != nil {
		return r.publishFast(ctx, blob)
	}
	signer, err := r.sub.Signer(ctx)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: signer: %w", err)
	}
	if len(signer) != signerLen {
		return sdk.Published{}, fmt.Errorf("%w: signer of %d bytes", errInvalidInput, len(signer))
	}
	comm, err := sharev1.Commitment(r.cfg.Namespace, signer, blob)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: commitment: %w", err)
	}
	return r.eng.publish(ctx, blobBackend{r: r, signer: signer}, comm, blob)
}

// blobBackend is the da = 2 side of the engine for one call.
type blobBackend struct {
	r      *Recorder
	signer []byte
}

func (blobBackend) da() commitment.DA { return commitment.DACelestiaBlob }

// A failed submit is only searched for, never submitted again by the same
// process: the first tx may still be in a mempool.
func (blobBackend) retries() bool { return false }

func (b blobBackend) head(ctx context.Context) (uint64, time.Time, error) {
	h, err := b.r.rd.Head(ctx)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: head: %w", ErrNodeUnavailable, err)
	}
	if h.Height == 0 {
		return 0, time.Time{}, fmt.Errorf("%w: head at height 0", ErrNodeUnavailable)
	}
	return h.Height, h.Time, nil
}

func (b blobBackend) payloadRecord(comm, blob []byte, intent uint64) *archive.PayloadRecord {
	return &archive.PayloadRecord{
		DA: commitment.DACelestiaBlob, Commitment: bytes.Clone(comm), Namespace: bytes.Clone(b.r.cfg.Namespace),
		Signer: bytes.Clone(b.signer), Blob: bytes.Clone(blob), IntentHeight: intent,
	}
}

func (b blobBackend) samePayload(old *archive.PayloadRecord, blob []byte) error {
	if !bytes.Equal(old.Blob, blob) || !bytes.Equal(old.Namespace, b.r.cfg.Namespace) || !bytes.Equal(old.Signer, b.signer) {
		return archive.ErrConflict
	}
	return nil
}

// span is the settle window, which must exceed the mempool TTL.
func (b blobBackend) span(context.Context) (uint64, error) { return b.r.cfg.SettleBlocks, nil }

func (b blobBackend) present(ctx context.Context, comm []byte, height uint64) (bool, error) {
	_, err := b.r.rd.Blob(ctx, height, b.r.cfg.Namespace, comm)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, node.ErrNotFound):
		return false, nil
	case ctx.Err() != nil:
		return false, ctx.Err()
	default:
		return false, err
	}
}

func (blobBackend) preflight(context.Context, []byte, time.Time) (func(), error) {
	return func() {}, nil
}

func (b blobBackend) submit(ctx context.Context, _, blob []byte, release func()) (uint64, error) {
	release()
	sctx, cancel := context.WithTimeout(ctx, b.r.cfg.SubmitTimeout)
	res, err := b.r.sub.Submit(sctx, b.r.cfg.Namespace, blob)
	cancel()
	if err != nil {
		if errors.Is(err, node.ErrUnsupported) {
			return 0, &notBroadcastError{err: err}
		}
		return 0, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	return res.Height, nil
}

func (b blobBackend) confirm(ctx context.Context, comm, blob []byte, h uint64, _ bool) (sdk.Published, error) {
	pub, hdr, err := b.verify(ctx, h, comm, blob)
	if err != nil {
		return sdk.Published{}, err
	}
	if b.r.cfg.Archive != nil {
		if err := b.r.archiveEvidence(ctx, hdr, comm); err != nil {
			return sdk.Published{}, err
		}
	}
	return pub, nil
}

func (b blobBackend) fromEvidence(ctx context.Context, comm, blob []byte, ev *archive.EvidenceRecord) (sdk.Published, error) {
	if ev.Height == 0 || !bytes.Equal(ev.Namespace, b.r.cfg.Namespace) {
		return sdk.Published{}, archiveFault("evidence record", archive.ErrConflict)
	}
	return b.confirm(ctx, comm, blob, ev.Height, false)
}

func (b blobBackend) verify(ctx context.Context, h uint64, comm, blob []byte) (sdk.Published, node.Header, error) {
	r, signer := b.r, b.signer
	deadline := time.Now().Add(r.cfg.VisibleTimeout)
	var hdr node.Header
	err := r.poll(ctx, deadline, func() error {
		var err error
		hdr, err = r.rd.HeaderAt(ctx, h)
		return err
	})
	if err != nil {
		return sdk.Published{}, node.Header{}, fmt.Errorf("recorder: header %d: %w", h, err)
	}
	var bl node.Blob
	err = r.poll(ctx, deadline, func() error {
		var err error
		bl, err = r.rd.Blob(ctx, h, r.cfg.Namespace, comm)
		return err
	})
	if err != nil {
		return sdk.Published{}, node.Header{}, fmt.Errorf("recorder: blob at %d: %w", h, err)
	}
	if bl.ShareVersion != 1 || !bytes.Equal(bl.Signer, signer) {
		return sdk.Published{}, node.Header{}, ErrSignerMismatch
	}
	if !bytes.Equal(bl.Namespace, r.cfg.Namespace) || !bytes.Equal(bl.Commitment, comm) || !bytes.Equal(bl.Data, blob) {
		return sdk.Published{}, node.Header{}, errBlobDiffers
	}
	return sdk.Published{
		Ref: commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: bytes.Clone(r.cfg.Namespace),
			Commitment: bytes.Clone(comm), Height: h, Signer: bytes.Clone(signer)},
		BlockTime: uint64(hdr.Time.Unix()),
	}, hdr, nil
}

// poll repeats fn while it reports ErrNotFound, until the deadline
// (ErrNotVisible), the context ends, or fn fails otherwise.
func (r *Recorder) poll(ctx context.Context, deadline time.Time, fn func() error) error {
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("%w: %w", ErrNodeUnavailable, cerr)
		}
		if !errors.Is(err, node.ErrNotFound) {
			return fmt.Errorf("%w: %w", ErrNodeUnavailable, err)
		}
		if !time.Now().Before(deadline) {
			return ErrNotVisible
		}
		t := time.NewTimer(r.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%w: %w", ErrNodeUnavailable, ctx.Err())
		case <-t.C:
		}
	}
}

// archiveEvidence stores the signed header at hdr.Height and the blob
// commitment proof, after checking both against the header the node served.
func (r *Recorder) archiveEvidence(ctx context.Context, hdr node.Header, comm []byte) error {
	hr, ok := r.rd.(headerReader)
	if !ok {
		return archiveFault("evidence", errors.New("the reader cannot return signed headers"))
	}
	raw, err := hr.SignedHeader(ctx, hdr.Height)
	if err != nil {
		return fmt.Errorf("%w: signed header: %w", ErrNodeUnavailable, err)
	}
	if err := checkSignedHeader(raw, hdr); err != nil {
		return fmt.Errorf("%w: signed header: %w", ErrNodeUnavailable, err)
	}
	proof, err := r.rd.CommitmentProof(ctx, hdr.Height, r.cfg.Namespace, comm)
	if err != nil {
		return fmt.Errorf("%w: commitment proof: %w", ErrNodeUnavailable, err)
	}
	if err := proof.Verify(hdr.DataRoot, comm); err != nil {
		return fmt.Errorf("%w: commitment proof: %w", ErrNodeUnavailable, err)
	}
	pb, err := json.Marshal(proof)
	if err != nil {
		return archiveFault("commitment proof", err)
	}
	rec := &archive.EvidenceRecord{
		DA: commitment.DACelestiaBlob, Commitment: bytes.Clone(comm), Namespace: bytes.Clone(r.cfg.Namespace),
		Height: hdr.Height, Header: raw, BlobProof: pb,
	}
	if _, err := r.cfg.Archive.Put(ctx, rec); err != nil {
		return archiveFault("write evidence record", err)
	}
	return nil
}

// checkSignedHeader requires raw to be a SignedHeader with a commit whose
// header is the one the node served for hdr.Height.
func checkSignedHeader(raw []byte, hdr node.Header) error {
	var sh cmtproto.SignedHeader
	if err := sh.Unmarshal(raw); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if sh.Header == nil || sh.Commit == nil {
		return errors.New("no header or no commit")
	}
	if sh.Header.Height < 0 || uint64(sh.Header.Height) != hdr.Height {
		return fmt.Errorf("header at height %d, want %d", sh.Header.Height, hdr.Height)
	}
	if len(sh.Header.DataHash) == 0 || !bytes.Equal(sh.Header.DataHash, hdr.DataRoot) {
		return errors.New("header data hash differs from the served header")
	}
	if sh.Commit.Height != sh.Header.Height {
		return fmt.Errorf("commit at height %d, header at %d", sh.Commit.Height, sh.Header.Height)
	}
	h, err := cmttypes.HeaderFromProto(sh.Header)
	if err != nil {
		return fmt.Errorf("header: %w", err)
	}
	want := h.Hash()
	if len(want) != sha256.Size || len(sh.Commit.BlockID.Hash) != sha256.Size {
		return errors.New("header or commit block hash is not 32 bytes")
	}
	if !bytes.Equal(sh.Commit.BlockID.Hash, want) {
		return errors.New("commit is for another block than the header")
	}
	return nil
}
