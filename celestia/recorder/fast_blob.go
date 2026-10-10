package recorder

import (
	"bytes"
	"context"
	"fmt"
	"time"

	libshare "github.com/celestiaorg/go-square/v4/share"
	squaretx "github.com/celestiaorg/go-square/v4/tx"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk"
)

const (
	defaultFastTimeoutBlocks = 100
	minFastTimeoutBlocks     = 13
	maxFastTimeoutBlocks     = 1000
)

// NewFast returns a da = 2 Recorder whose Publish returns pending
// references: the PFB is signed at the head h0 with timeout_height h0 +
// cfg.FastTimeoutBlocks, archived as the anchor intent, and broadcast as a
// BlobTx before Publish returns. It needs an archive that reads intents.
func NewFast(cfg Config, d FastDeps, rd node.Reader) (*Recorder, error) {
	if rd == nil {
		return nil, fmt.Errorf("%w: nil reader", errInvalidInput)
	}
	if err := d.check(commitment.DACelestiaBlob); err != nil {
		return nil, err
	}
	if cfg.Archive == nil {
		return nil, fmt.Errorf("%w: fast mode needs an archive", errInvalidInput)
	}
	r, err := New(cfg, noSubmitter{}, rd)
	if err != nil {
		return nil, err
	}
	if r.cfg.FastTimeoutBlocks == 0 {
		r.cfg.FastTimeoutBlocks = defaultFastTimeoutBlocks
	}
	if r.fast, err = newFastCore(r.eng, d, r.cfg.PollInterval); err != nil {
		return nil, err
	}
	r.fast.start(func(ctx context.Context) (fastDA, error) { return r.fastBlob(ctx) })
	return r, nil
}

// noSubmitter stands in for the Submitter of a fast Recorder, which never
// submits through it.
type noSubmitter struct{}

func (noSubmitter) Signer(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("%w: fast mode has no submitter", errInvalidInput)
}

func (noSubmitter) Submit(context.Context, []byte, []byte) (SubmitResult, error) {
	return SubmitResult{}, fmt.Errorf("%w: fast mode has no submitter", errInvalidInput)
}

// Close stops the confirmation loops of a fast Recorder, waiting for them
// until ctx ends. It is a no-op otherwise.
func (r *Recorder) Close(ctx context.Context) error {
	r.eng.closeIntake()
	if r.fast == nil {
		return nil
	}
	return r.fast.close(ctx)
}

func (r *Recorder) fastBlob(ctx context.Context) (fastBlob, error) {
	signer, err := r.fast.d.Signer.Address(ctx)
	if err != nil {
		return fastBlob{}, fmt.Errorf("recorder: signer: %w", err)
	}
	if len(signer) != signerLen {
		return fastBlob{}, fmt.Errorf("%w: signer of %d bytes", errInvalidInput, len(signer))
	}
	return fastBlob{blobBackend{r: r, signer: signer}}, nil
}

func (r *Recorder) publishFast(ctx context.Context, blob []byte) (sdk.Published, error) {
	b, err := r.fastBlob(ctx)
	if err != nil {
		return sdk.Published{}, err
	}
	comm, err := sharev1.Commitment(r.cfg.Namespace, b.signer, blob)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: commitment: %w", err)
	}
	return r.fast.publish(ctx, b, comm, bytes.Clone(blob))
}

// fastBlob is the da = 2 side of the fast path.
type fastBlob struct{ blobBackend }

var _ fastDA = fastBlob{}

func noRelease() {}

func (b fastBlob) draft(ctx context.Context, comm, blob []byte, head uint64, headTime time.Time) (*intentDraft, error) {
	timeout := head + b.r.cfg.FastTimeoutBlocks
	rec := &archive.AnchorIntentRecord{
		DA: commitment.DACelestiaBlob, Commitment: bytes.Clone(comm), Namespace: bytes.Clone(b.r.cfg.Namespace),
		RefHeight: head, Signer: bytes.Clone(b.blobBackend.signer), CreatedAt: unixFloor(b.r.cfg.Now()),
	}
	t := unixFloor(headTime)
	if t == 0 {
		return nil, fmt.Errorf("%w: head header has no time", ErrNodeUnavailable)
	}
	sign := func(ctx context.Context, p node.TxParams) ([]byte, error) {
		tx, err := b.r.fast.d.Signer.SignPFB(ctx, b.r.cfg.Namespace, blob, p)
		if err != nil {
			return nil, fmt.Errorf("recorder: sign: %w", err)
		}
		if _, err := gatechain.CheckPFB(tx, b.ref(rec)); err != nil {
			return nil, fmt.Errorf("%w: the signed PFB does not pay for this blob: %w", ErrSubmitMismatch, err)
		}
		return tx, nil
	}
	return &intentDraft{rec: rec, sign: sign, timeout: timeout, landBy: timeout, refTime: t, retStart: t, release: noRelease}, nil
}

func (b fastBlob) ref(rec *archive.AnchorIntentRecord) commitment.PayloadRef {
	return commitment.PayloadRef{
		DA: commitment.DACelestiaBlob, Namespace: rec.Namespace, Commitment: rec.Commitment,
		Height: rec.RefHeight, Signer: rec.Signer, Anchor: commitment.AnchorPending,
	}
}

func (b fastBlob) restore(ctx context.Context, comm, _ []byte, rec *archive.AnchorIntentRecord) (*intentDraft, error) {
	if !bytes.Equal(rec.Commitment, comm) || !bytes.Equal(rec.Namespace, b.r.cfg.Namespace) || !bytes.Equal(rec.Signer, b.blobBackend.signer) {
		return nil, archiveFault("anchor intent", archive.ErrConflict)
	}
	timeout, err := gatechain.CheckPFB(rec.Tx, b.ref(rec))
	if err != nil {
		return nil, archiveFault("anchor intent", err)
	}
	if timeout == 0 {
		timeout = rec.RefHeight + b.r.cfg.FastTimeoutBlocks
	}
	hdr, err := b.r.rd.HeaderAt(ctx, rec.RefHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: header at %d: %w", ErrNodeUnavailable, rec.RefHeight, err)
	}
	t := unixFloor(hdr.Time)
	return &intentDraft{rec: rec, timeout: timeout, landBy: timeout, refTime: t, retStart: t, release: noRelease}, nil
}

func (b fastBlob) reach(context.Context) (uint64, error) { return maxFastTimeoutBlocks, nil }

func (b fastBlob) owns(rec *archive.AnchorIntentRecord, addr []byte) bool {
	return bytes.Equal(rec.Signer, addr) && bytes.Equal(rec.Namespace, b.r.cfg.Namespace)
}

func (b fastBlob) wire(tx, blob []byte) ([]byte, error) {
	ns, err := libshare.NewNamespaceFromBytes(b.r.cfg.Namespace)
	if err != nil {
		return nil, fmt.Errorf("%w: namespace: %w", errInvalidInput, err)
	}
	bl, err := libshare.NewV1Blob(ns, blob, b.blobBackend.signer)
	if err != nil {
		return nil, fmt.Errorf("recorder: blob: %w", err)
	}
	raw, err := squaretx.MarshalBlobTx(tx, bl)
	if err != nil {
		return nil, fmt.Errorf("recorder: blob tx: %w", err)
	}
	return raw, nil
}

func unixFloor(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}
