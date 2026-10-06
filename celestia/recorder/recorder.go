package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

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
	// ErrSubmitMismatch means the node returned a blob ID other than the one
	// computed locally; a fee may have been spent.
	ErrSubmitMismatch = errors.New("recorder: node returned another blob id than computed")

	errBlobDiffers  = errors.New("recorder: anchored blob differs from the submitted one")
	errInvalidInput = errors.New("recorder: invalid configuration")
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
	// SettleBlocks is the window after an archived intent height in which an
	// earlier process may still have a submit pending in a mempool. After a
	// restart the Recorder submits again only once the head is past
	// intent_height + SettleBlocks and no earlier submit was found in
	// between, so the window must exceed the mempool TTL with room to spare.
	// Default 1024; a smaller non-zero value is refused.
	SettleBlocks uint64
	// MaxPending caps blobs whose outcome is unresolved; a new blob is
	// refused with ErrTooManyPending at the cap. Default 4096.
	MaxPending int
	// Now is the clock for entry expiry; nil means time.Now.
	Now func() time.Time
	// Archive receives the payload before the submit and the anchor
	// evidence after the read-back. Nil means no archive writes.
	Archive archive.Store
}

// headerReader is implemented by readers that can return the protobuf
// SignedHeader (header and commit) the evidence record stores.
type headerReader interface {
	SignedHeader(ctx context.Context, height uint64) ([]byte, error)
}

type pendingKey string

// entry is the state of one blob that has been, or is being, submitted.
type entry struct {
	scanned  uint64 // highest height already searched; starts at the head before the submit
	created  time.Time
	inflight bool
	done     *sdk.Published
	// intent is the archived intent height this entry works from; zero when
	// no payload record was written.
	intent uint64
	// windowed is set when the payload record came from an earlier process:
	// a submit of it may be pending, so submitting waits for the settle window.
	windowed bool
	// submitted is set once a submit call was made; from then on an entry is
	// only searched, never submitted again.
	submitted bool
}

// Recorder implements sdk.Publisher.
type Recorder struct {
	cfg Config
	sub Submitter
	rd  node.Reader

	mu sync.Mutex
	// entries holds a blob from the moment it is claimed for submit until it
	// is verified. An unresolved entry is never resubmitted: after an
	// ambiguous outcome the first tx may still be in a mempool, so a later
	// call only searches the chain for it. Unresolved entries are dropped
	// after pendingTTL, which bounds memory and is the only way a blob is
	// submitted again. Verified entries stay in a small FIFO so that callers
	// racing on the same blob get the same ref instead of a second submit.
	entries    map[pendingKey]*entry
	unresolved int
	finished   []pendingKey
}

const (
	defaultMaxPending = 4096
	pendingTTL        = time.Hour
	finishedKeep      = 256
	scanFloor         = 1024
	settleDefault     = 1024
	settleFloor       = 256
)

var _ sdk.Publisher = (*Recorder)(nil)

// ValidateBasic checks the stateless fields.
func (c Config) ValidateBasic() error {
	if err := checkNamespace(c.Namespace); err != nil {
		return err
	}
	if c.SettleBlocks != 0 && c.SettleBlocks < settleFloor {
		return fmt.Errorf("%w: settle window of %d blocks is below %d", errInvalidInput, c.SettleBlocks, settleFloor)
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
	return &Recorder{cfg: cfg, sub: sub, rd: rd, entries: map[pendingKey]*entry{}}, nil
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
// node. It never modifies blob.
func (r *Recorder) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	if err := ctx.Err(); err != nil {
		return sdk.Published{}, err
	}
	if uint64(len(blob)) > r.cfg.MaxBlobBytes {
		return sdk.Published{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(blob))
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
	key := pendingKey(comm)

	e, resume, err := r.claim(key)
	if err != nil {
		return sdk.Published{}, err
	}
	if e.done != nil {
		return clonePublished(*e.done), nil
	}
	if resume && e.submitted {
		head, err := r.head(ctx)
		if err != nil {
			r.release(e)
			return sdk.Published{}, err
		}
		h, found, err := r.scan(ctx, e, comm, head, math.MaxUint64)
		if err != nil {
			r.release(e)
			return sdk.Published{}, err
		}
		if !found {
			r.release(e)
			return sdk.Published{}, fmt.Errorf("%w: an earlier submit of this blob may still be pending", ErrOutcomeUnknown)
		}
		return r.confirm(ctx, key, e, h, signer, comm, blob)
	}

	head, err := r.head(ctx)
	if err != nil {
		r.unwind(key, e)
		return sdk.Published{}, err
	}
	if head == 0 {
		r.unwind(key, e)
		return sdk.Published{}, fmt.Errorf("%w: head at height 0", ErrNodeUnavailable)
	}
	if e.intent == 0 {
		r.mu.Lock()
		e.scanned = head - 1
		r.mu.Unlock()
	}

	if r.cfg.Archive != nil {
		intent, existed, err := r.archivePayload(ctx, comm, signer, blob, head)
		if err != nil {
			r.unwind(key, e)
			return sdk.Published{}, err
		}
		r.mu.Lock()
		if e.intent == 0 {
			e.intent, e.windowed = intent, existed
			e.scanned = intent - 1
		}
		windowed := e.windowed
		r.mu.Unlock()

		// An anchor archived by an earlier run is the one to answer from;
		// paying for another would leave two anchors of one blob.
		ah, anchored, err := r.archivedAnchor(ctx, comm)
		if err != nil {
			r.unwind(key, e)
			return sdk.Published{}, err
		}
		if anchored {
			return r.confirm(ctx, key, e, ah, signer, comm, blob)
		}
		if windowed {
			h, found, ready, err := r.settle(ctx, e, comm)
			if err != nil {
				r.release(e)
				return sdk.Published{}, err
			}
			if found {
				return r.confirm(ctx, key, e, h, signer, comm, blob)
			}
			if !ready {
				r.release(e)
				return sdk.Published{}, fmt.Errorf("%w: an earlier submit of this blob may still be pending", ErrOutcomeUnknown)
			}
		}
	}

	r.mu.Lock()
	e.submitted = true
	r.mu.Unlock()
	sctx, cancel := context.WithTimeout(ctx, r.cfg.SubmitTimeout)
	res, err := r.sub.Submit(sctx, r.cfg.Namespace, blob)
	cancel()
	if err != nil {
		if errors.Is(err, node.ErrUnsupported) {
			r.mu.Lock()
			e.submitted = false
			r.mu.Unlock()
			r.unwind(key, e)
			return sdk.Published{}, fmt.Errorf("recorder: submit: %w", err)
		}
		r.release(e)
		return sdk.Published{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	return r.confirm(ctx, key, e, res.Height, signer, comm, blob)
}

func clonePublished(p sdk.Published) sdk.Published {
	p.Ref.Namespace = bytes.Clone(p.Ref.Namespace)
	p.Ref.Commitment = bytes.Clone(p.Ref.Commitment)
	p.Ref.Signer = bytes.Clone(p.Ref.Signer)
	return p
}

// claim takes ownership of key for this call. resume is true when an earlier
// call already submitted it. The check and the insert share one lock hold, so
// two callers can never both submit.
func (r *Recorder) claim(key pendingKey) (e *entry, resume bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	if old, ok := r.entries[key]; ok && old.done == nil && !old.inflight && now.Sub(old.created) > pendingTTL {
		delete(r.entries, key)
		r.unresolved--
	}
	if e, ok := r.entries[key]; ok {
		switch {
		case e.done != nil:
			return e, false, nil
		case e.inflight:
			return nil, false, fmt.Errorf("%w: another publish of this blob is in progress", ErrOutcomeUnknown)
		}
		e.inflight = true
		return e, true, nil
	}
	if r.unresolved >= r.cfg.MaxPending {
		for k, old := range r.entries {
			if old.done == nil && !old.inflight && now.Sub(old.created) > pendingTTL {
				delete(r.entries, k)
				r.unresolved--
			}
		}
	}
	if r.unresolved >= r.cfg.MaxPending {
		return nil, false, fmt.Errorf("%w: %d", ErrTooManyPending, r.unresolved)
	}
	e = &entry{created: now, inflight: true}
	r.entries[key] = e
	r.unresolved++
	return e, false, nil
}

func (r *Recorder) release(e *entry) {
	r.mu.Lock()
	e.inflight = false
	r.mu.Unlock()
}

func (r *Recorder) forget(key pendingKey, e *entry) {
	r.mu.Lock()
	if r.entries[key] == e && e.done == nil {
		delete(r.entries, key)
		r.unresolved--
	}
	r.mu.Unlock()
}

// unwind ends a call that failed before or without a submit. An entry that
// already has archived state or a submit behind it is kept, so its search
// progress and the knowledge that nothing is pending survive.
func (r *Recorder) unwind(key pendingKey, e *entry) {
	r.mu.Lock()
	keep := e.submitted || e.intent != 0
	r.mu.Unlock()
	if keep {
		r.release(e)
		return
	}
	r.forget(key, e)
}

func (r *Recorder) head(ctx context.Context) (uint64, error) {
	h, err := r.rd.Head(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: head: %w", ErrNodeUnavailable, err)
	}
	return h.Height, nil
}

// settle searches the settle window after the archived intent height for an
// earlier submit. ready reports that the whole window was read and the head is
// past it, so a submit that may have been pending is either found or gone.
func (r *Recorder) settle(ctx context.Context, e *entry, comm []byte) (h uint64, found, ready bool, err error) {
	head, err := r.head(ctx)
	if err != nil {
		return 0, false, false, err
	}
	r.mu.Lock()
	intent := e.intent
	r.mu.Unlock()
	if head < intent {
		return 0, false, false, fmt.Errorf("%w: node at height %d is behind the archived intent height %d", ErrNodeUnavailable, head, intent)
	}
	end := intent + r.cfg.SettleBlocks
	if end < intent {
		end = math.MaxUint64
	}
	h, found, err = r.scan(ctx, e, comm, head, end)
	if err != nil || found {
		return h, found, false, err
	}
	r.mu.Lock()
	covered := e.scanned >= end
	r.mu.Unlock()
	return 0, false, covered && head > end, nil
}

// scan looks for the blob in the blocks after e.scanned up to min(head,
// limit), resuming where the last search stopped. It reads at most ScanBlocks
// blocks per call.
func (r *Recorder) scan(ctx context.Context, e *entry, comm []byte, head, limit uint64) (uint64, bool, error) {
	r.mu.Lock()
	lo, hi := e.scanned+1, min(head, limit)
	r.mu.Unlock()
	if hi >= lo && hi-lo >= r.cfg.ScanBlocks {
		hi = lo + r.cfg.ScanBlocks - 1
	}
	for h := lo; h <= hi; h++ {
		_, err := r.rd.Blob(ctx, h, r.cfg.Namespace, comm)
		switch {
		case err == nil:
			return h, true, nil
		case errors.Is(err, node.ErrNotFound):
		case ctx.Err() != nil:
			return 0, false, fmt.Errorf("%w: scan: %w", ErrNodeUnavailable, ctx.Err())
		default:
			return 0, false, fmt.Errorf("%w: scan: %w", ErrNodeUnavailable, err)
		}
		r.mu.Lock()
		e.scanned = h
		r.mu.Unlock()
	}
	return 0, false, nil
}

// confirm waits for the header and blob at h and checks them byte for byte.
func (r *Recorder) confirm(ctx context.Context, key pendingKey, e *entry, h uint64, signer, comm, blob []byte) (sdk.Published, error) {
	pub, hdr, err := r.verify(ctx, h, signer, comm, blob)
	if err != nil {
		r.release(e)
		return sdk.Published{}, err
	}
	if r.cfg.Archive != nil {
		if err := r.archiveEvidence(ctx, hdr, comm); err != nil {
			r.release(e)
			return sdk.Published{}, err
		}
	}
	r.finish(key, e, pub)
	return clonePublished(pub), nil
}

func (r *Recorder) verify(ctx context.Context, h uint64, signer, comm, blob []byte) (sdk.Published, node.Header, error) {
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
	var b node.Blob
	err = r.poll(ctx, deadline, func() error {
		var err error
		b, err = r.rd.Blob(ctx, h, r.cfg.Namespace, comm)
		return err
	})
	if err != nil {
		return sdk.Published{}, node.Header{}, fmt.Errorf("recorder: blob at %d: %w", h, err)
	}
	if b.ShareVersion != 1 || !bytes.Equal(b.Signer, signer) {
		return sdk.Published{}, node.Header{}, ErrSignerMismatch
	}
	if !bytes.Equal(b.Namespace, r.cfg.Namespace) || !bytes.Equal(b.Commitment, comm) || !bytes.Equal(b.Data, blob) {
		return sdk.Published{}, node.Header{}, errBlobDiffers
	}
	return sdk.Published{
		Ref: commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: bytes.Clone(r.cfg.Namespace),
			Commitment: bytes.Clone(comm), Height: h, Signer: bytes.Clone(signer)},
		BlockTime: uint64(hdr.Time.Unix()),
	}, hdr, nil
}

func (r *Recorder) finish(key pendingKey, e *entry, pub sdk.Published) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.done, e.inflight = &pub, false
	if r.entries[key] != e {
		return
	}
	r.unresolved--
	r.finished = append(r.finished, key)
	if len(r.finished) > finishedKeep {
		delete(r.entries, r.finished[0])
		r.finished = r.finished[1:]
	}
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

func archiveFault(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrArchiveUnavailable, what, err)
}

// archivePayload makes sure the archive holds the payload record and returns
// its intent height. A stored record is kept as it is, so a restart keeps the
// first intent height; existed is true when the record is not this call's.
func (r *Recorder) archivePayload(ctx context.Context, comm, signer, blob []byte, head uint64) (intent uint64, existed bool, err error) {
	old, err := r.cfg.Archive.Payload(ctx, commitment.DACelestiaBlob, comm)
	switch {
	case err == nil:
		return r.sameRecord(old, signer, blob)
	case !errors.Is(err, archive.ErrNotFound):
		return 0, false, archiveFault("read payload record", err)
	}
	rec := &archive.PayloadRecord{
		DA: commitment.DACelestiaBlob, Commitment: bytes.Clone(comm), Namespace: bytes.Clone(r.cfg.Namespace),
		Signer: bytes.Clone(signer), Blob: bytes.Clone(blob), IntentHeight: head,
	}
	out, err := r.cfg.Archive.Put(ctx, rec)
	if err != nil {
		return 0, false, archiveFault("write payload record", err)
	}
	if out == archive.Unchanged {
		// Another writer stored the same payload first; its intent height
		// is the one that counts.
		old, err := r.cfg.Archive.Payload(ctx, commitment.DACelestiaBlob, comm)
		if err != nil {
			return 0, false, archiveFault("read payload record", err)
		}
		return r.sameRecord(old, signer, blob)
	}
	return head, false, nil
}

func (r *Recorder) sameRecord(old *archive.PayloadRecord, signer, blob []byte) (uint64, bool, error) {
	if !bytes.Equal(old.Blob, blob) || !bytes.Equal(old.Namespace, r.cfg.Namespace) || !bytes.Equal(old.Signer, signer) {
		return 0, false, archiveFault("payload record", archive.ErrConflict)
	}
	if old.IntentHeight == 0 {
		return 0, false, archiveFault("payload record", archive.ErrCorrupt)
	}
	return old.IntentHeight, true, nil
}

// archivedAnchor returns the height of the anchor already archived for comm.
func (r *Recorder) archivedAnchor(ctx context.Context, comm []byte) (uint64, bool, error) {
	ev, err := r.cfg.Archive.Evidence(ctx, commitment.DACelestiaBlob, comm)
	switch {
	case err == nil:
	case errors.Is(err, archive.ErrNotFound):
		return 0, false, nil
	default:
		return 0, false, archiveFault("read evidence record", err)
	}
	if ev.Height == 0 || !bytes.Equal(ev.Namespace, r.cfg.Namespace) {
		return 0, false, archiveFault("evidence record", archive.ErrConflict)
	}
	return ev.Height, true, nil
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
	return nil
}
