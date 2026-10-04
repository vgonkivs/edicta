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
	// ScanBlocks is how far back an ambiguous submit is looked for; default 64.
	ScanBlocks uint64
}

type pendingKey string

// Recorder implements sdk.Publisher.
type Recorder struct {
	cfg Config
	sub Submitter
	rd  node.Reader

	mu sync.Mutex
	// pending maps a share commitment to the head height before its submit.
	// An entry stays until the blob is verified, so the same bytes are never
	// submitted twice while the first outcome is unresolved.
	pending map[pendingKey]uint64
}

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
	if cfg.ScanBlocks == 0 {
		cfg.ScanBlocks = 64
	}
	return &Recorder{cfg: cfg, sub: sub, rd: rd, pending: map[pendingKey]uint64{}}, nil
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

	r.mu.Lock()
	h0, isPending := r.pending[key]
	r.mu.Unlock()

	if isPending {
		h, found, err := r.scan(ctx, comm, h0)
		if err != nil {
			return sdk.Published{}, err
		}
		if found {
			return r.confirm(ctx, key, h, signer, comm, blob)
		}
	} else {
		head, err := r.rd.Head(ctx)
		if err != nil {
			return sdk.Published{}, fmt.Errorf("recorder: head: %w", err)
		}
		h0 = head.Height
		r.mu.Lock()
		r.pending[key] = h0
		r.mu.Unlock()
	}

	sctx, cancel := context.WithTimeout(ctx, r.cfg.SubmitTimeout)
	res, err := r.sub.Submit(sctx, r.cfg.Namespace, blob)
	cancel()
	if err != nil {
		if errors.Is(err, node.ErrUnsupported) {
			r.forget(key)
			return sdk.Published{}, fmt.Errorf("recorder: submit: %w", err)
		}
		return sdk.Published{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	return r.confirm(ctx, key, res.Height, signer, comm, blob)
}

func (r *Recorder) forget(key pendingKey) {
	r.mu.Lock()
	delete(r.pending, key)
	r.mu.Unlock()
}

// scan looks for the blob in the recent blocks after an ambiguous submit.
func (r *Recorder) scan(ctx context.Context, comm []byte, h0 uint64) (uint64, bool, error) {
	head, err := r.rd.Head(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("recorder: head: %w", err)
	}
	lo := h0
	if head.Height > r.cfg.ScanBlocks && head.Height-r.cfg.ScanBlocks > lo {
		lo = head.Height - r.cfg.ScanBlocks
	}
	for h := lo; h <= head.Height; h++ {
		_, err := r.rd.Blob(ctx, h, r.cfg.Namespace, comm)
		switch {
		case err == nil:
			return h, true, nil
		case errors.Is(err, node.ErrNotFound):
		default:
			return 0, false, fmt.Errorf("recorder: scan: %w", err)
		}
	}
	return 0, false, nil
}

// confirm waits for the header and blob at h and checks them byte for byte.
func (r *Recorder) confirm(ctx context.Context, key pendingKey, h uint64, signer, comm, blob []byte) (sdk.Published, error) {
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
	r.forget(key)
	return sdk.Published{
		Ref: commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: bytes.Clone(r.cfg.Namespace),
			Commitment: bytes.Clone(comm), Height: h, Signer: bytes.Clone(signer)},
		BlockTime: uint64(hdr.Time.Unix()),
	}, nil
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
			return cerr
		}
		if !errors.Is(err, node.ErrNotFound) {
			return err
		}
		if !time.Now().Before(deadline) {
			return ErrNotVisible
		}
		t := time.NewTimer(r.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
