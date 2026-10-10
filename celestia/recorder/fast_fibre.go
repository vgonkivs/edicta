package recorder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

var _ fastDA = (*FibreRecorder)(nil)

// publishFast uploads blob without paying, signs the PayForFibre tx carrying
// the promise and the validator signatures, archives it as the anchor intent
// and broadcasts it, and returns the pending reference at the promise height.
func (r *FibreRecorder) publishFast(ctx context.Context, comm, blob []byte) (sdk.Published, error) {
	return r.fast.publish(ctx, r, comm, blob)
}

// fibreParams reads the promise window and timeout the anchor must land in.
func (r *FibreRecorder) fibreParams(ctx context.Context) (node.FibreParams, error) {
	p, err := r.d.Chain.FibreParams(ctx)
	if err != nil {
		return node.FibreParams{}, fmt.Errorf("%w: fibre params: %w", ErrNodeUnavailable, err)
	}
	if p.PromiseHeightWindow == 0 || p.PromiseTimeoutS == 0 {
		return node.FibreParams{}, fmt.Errorf("%w: the node reports no promise window or timeout", ErrNodeUnavailable)
	}
	return p, nil
}

// headerTime is the time of the header at h, waited for while the node does
// not serve it yet: h0 can be the block the node has just made its head.
func (r *FibreRecorder) headerTime(ctx context.Context, h uint64) (uint64, error) {
	deadline := time.Now().Add(r.cfg.VisibleTimeout)
	for {
		hdr, err := r.d.Chain.Header(ctx, h)
		if err == nil {
			if t := unixFloor(hdr.Time); t != 0 {
				return t, nil
			}
			return 0, fmt.Errorf("%w: header at %d has no time", ErrNodeUnavailable, h)
		}
		if !errors.Is(err, node.ErrNotFound) || !time.Now().Before(deadline) {
			return 0, fmt.Errorf("%w: header at %d: %w", ErrNodeUnavailable, h, err)
		}
		t := time.NewTimer(r.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, fmt.Errorf("%w: %w", ErrNodeUnavailable, ctx.Err())
		case <-t.C:
		}
	}
}

// draft takes an upload slot and reserves the escrow cost, which the raw
// upload does not track, and uploads. The reservation lasts until the anchor
// lands or can no longer land: the escrow is charged only then.
func (r *FibreRecorder) draft(ctx context.Context, comm, blob []byte, _ uint64, headTime time.Time) (*intentDraft, error) {
	fp, err := r.fibreParams(ctx)
	if err != nil {
		return nil, err
	}
	us, err := uploadSize(blob)
	if err != nil {
		return nil, err
	}
	free, err := r.preflight(ctx, blob, headTime)
	if err != nil {
		return nil, err
	}
	cost := FibreCostUtia(us)
	release := sync.OnceFunc(func() { r.unreserve(cost) })

	uctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	id := r.nextID
	r.nextID++
	r.cancels[id] = cancel
	r.mu.Unlock()
	stop := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(r.cfg.SubmitTimeout, cancel)
	up, err := r.d.Fast.Uploader.Upload(uctx, r.cfg.Namespace, blob)
	stop()
	timer.Stop()
	time.AfterFunc(r.cfg.UploadDrain, func() {
		cancel()
		r.mu.Lock()
		delete(r.cancels, id)
		r.mu.Unlock()
		free()
	})
	if err != nil {
		release()
		return nil, fmt.Errorf("%w: upload: %w", ErrNodeUnavailable, err)
	}

	h0, created := up.PromiseHeight, unixFloor(up.Created)
	if h0 == 0 || created == 0 {
		release()
		return nil, fmt.Errorf("%w: upload returned promise height %d, creation %v", ErrSubmitMismatch, h0, up.Created)
	}
	refTime, err := r.headerTime(ctx, h0)
	if err != nil {
		release()
		return nil, err
	}
	rec := &archive.AnchorIntentRecord{
		DA: commitment.DAFibre, Commitment: bytes.Clone(comm), Namespace: bytes.Clone(r.cfg.Namespace),
		RefHeight: h0, CreatedAt: created,
	}
	msg := bytes.Clone(up.Msg)
	sign := func(ctx context.Context, p node.TxParams) ([]byte, error) {
		tx, err := r.d.Fast.Signer.SignPFF(ctx, msg, p)
		if err != nil {
			return nil, fmt.Errorf("%w: sign: %w", ErrSubmitMismatch, err)
		}
		if err := r.checkPFF(tx, rec, us); err != nil {
			return nil, err
		}
		return tx, nil
	}
	landBy := h0 + fp.PromiseHeightWindow
	return &intentDraft{
		rec: rec, sign: sign, timeout: landBy, landBy: landBy,
		expiry:  up.Created.Add(time.Duration(fp.PromiseTimeoutS) * time.Second),
		refTime: refTime, retStart: created, release: release,
		settleWait: time.Duration(fp.PromiseTimeoutS) * time.Second,
	}, nil
}

// checkPFF requires the signed tx to carry a promise for exactly this blob at
// the intent's height and creation time, signed by its owner.
func (r *FibreRecorder) checkPFF(tx []byte, rec *archive.AnchorIntentRecord, us uint64) error {
	f, ok, err := fibrecert.ParsePFF(tx)
	if err != nil || !ok {
		return fmt.Errorf("%w: not a PayForFibre tx: %w", ErrSubmitMismatch, errors.Join(err, errors.New("parse")))
	}
	b := fibrecert.Binding{ChainID: r.d.ChainID, Namespace: r.cfg.Namespace, BlobSize: uint32(us)}
	copy(b.Commitment[:], rec.Commitment)
	if err := fibrecert.CheckBinding(f.Promise, b); err != nil {
		return fmt.Errorf("%w: %w", ErrSubmitMismatch, err)
	}
	if f.Promise.Height != rec.RefHeight || unixFloor(f.Promise.CreationTime) != rec.CreatedAt {
		return fmt.Errorf("%w: promise at height %d created %v, intent at %d created %d", ErrSubmitMismatch,
			f.Promise.Height, f.Promise.CreationTime, rec.RefHeight, rec.CreatedAt)
	}
	if err := fibrecert.VerifyOwner(f); err != nil {
		return fmt.Errorf("%w: %w", ErrSubmitMismatch, err)
	}
	return nil
}

// restore follows an intent an earlier process archived. Its escrow cost is
// not reserved again: that process's reservation died with it.
func (r *FibreRecorder) restore(ctx context.Context, comm, blob []byte, rec *archive.AnchorIntentRecord) (*intentDraft, error) {
	us, err := uploadSize(blob)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rec.Commitment, comm) {
		return nil, archiveFault("anchor intent", archive.ErrConflict)
	}
	if err := r.checkPFF(rec.Tx, rec, us); err != nil {
		return nil, archiveFault("anchor intent", err)
	}
	fp, err := r.fibreParams(ctx)
	if err != nil {
		return nil, err
	}
	refTime, err := r.headerTime(ctx, rec.RefHeight)
	if err != nil {
		return nil, err
	}
	landBy := rec.RefHeight + fp.PromiseHeightWindow
	return &intentDraft{
		rec: rec, timeout: landBy, landBy: landBy,
		expiry:  time.Unix(int64(rec.CreatedAt)+1, 0).Add(time.Duration(fp.PromiseTimeoutS) * time.Second),
		refTime: refTime, retStart: rec.CreatedAt, release: noRelease,
	}, nil
}

func (r *FibreRecorder) wire(tx, _ []byte) ([]byte, error) { return tx, nil }
