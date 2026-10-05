package recorder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

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
	// submit reads, counted from the height before that submit. It cannot go
	// below 1024.
	ScanBlocks uint64
	// MaxPending caps blobs whose outcome is unresolved; a new blob is
	// refused with ErrTooManyPending at the cap. Default 4096.
	MaxPending int
	// Now is the clock for entry expiry; nil means time.Now.
	Now func() time.Time
}

type pendingKey string

// entry is the state of one blob that has been, or is being, submitted.
type entry struct {
	scanned  uint64 // highest height already searched; starts at the head before the submit
	created  time.Time
	inflight bool
	done     *sdk.Published
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
)

var _ sdk.Publisher = (*Recorder)(nil)

// New validates cfg and returns a Recorder.
func New(cfg Config, sub Submitter, rd node.Reader) (*Recorder, error) {
	if sub == nil || rd == nil {
		return nil, fmt.Errorf("%w: nil dependency", errInvalidInput)
	}
	if err := checkNamespace(cfg.Namespace); err != nil {
		return nil, err
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
	if resume {
		h, found, err := r.scan(ctx, e, comm)
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

	head, err := r.rd.Head(ctx)
	if err != nil {
		r.forget(key, e)
		return sdk.Published{}, fmt.Errorf("%w: head: %w", ErrNodeUnavailable, err)
	}
	r.mu.Lock()
	e.scanned = head.Height - 1
	r.mu.Unlock()

	sctx, cancel := context.WithTimeout(ctx, r.cfg.SubmitTimeout)
	res, err := r.sub.Submit(sctx, r.cfg.Namespace, blob)
	cancel()
	if err != nil {
		if errors.Is(err, node.ErrUnsupported) {
			r.forget(key, e)
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

// scan looks for the blob in the blocks since the submit, resuming where the
// last search stopped. It reads at most ScanBlocks blocks per call.
func (r *Recorder) scan(ctx context.Context, e *entry, comm []byte) (uint64, bool, error) {
	head, err := r.rd.Head(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("%w: head: %w", ErrNodeUnavailable, err)
	}
	r.mu.Lock()
	lo, hi := e.scanned+1, head.Height
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
	pub, err := r.verify(ctx, h, signer, comm, blob)
	if err != nil {
		r.release(e)
		return sdk.Published{}, err
	}
	r.finish(key, e, pub)
	return clonePublished(pub), nil
}

func (r *Recorder) verify(ctx context.Context, h uint64, signer, comm, blob []byte) (sdk.Published, error) {
	deadline := time.Now().Add(r.cfg.VisibleTimeout)
	var hdr node.Header
	err := r.poll(ctx, deadline, func() error {
		var err error
		hdr, err = r.rd.HeaderAt(ctx, h)
		return err
	})
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: header %d: %w", h, err)
	}
	var b node.Blob
	err = r.poll(ctx, deadline, func() error {
		var err error
		b, err = r.rd.Blob(ctx, h, r.cfg.Namespace, comm)
		return err
	})
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: blob at %d: %w", h, err)
	}
	if b.ShareVersion != 1 || !bytes.Equal(b.Signer, signer) {
		return sdk.Published{}, ErrSignerMismatch
	}
	if !bytes.Equal(b.Namespace, r.cfg.Namespace) || !bytes.Equal(b.Commitment, comm) || !bytes.Equal(b.Data, blob) {
		return sdk.Published{}, errBlobDiffers
	}
	return sdk.Published{
		Ref: commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: bytes.Clone(r.cfg.Namespace),
			Commitment: bytes.Clone(comm), Height: h, Signer: bytes.Clone(signer)},
		BlockTime: uint64(hdr.Time.Unix()),
	}, nil
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
