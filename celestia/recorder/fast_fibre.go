package recorder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"

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
// lands, or else until a timeout settlement can no longer charge the promise.
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
		// A failed upload may still have left a signed promise with the
		// validators, and anyone holding it can settle it from the escrow.
		r.fast.hold(r.settleBy(r.cfg.Now(), fp), release)
		return nil, fmt.Errorf("%w: upload: %w", ErrNodeUnavailable, err)
	}

	h0, created := up.PromiseHeight, unixFloor(up.Created)
	if h0 == 0 || created == 0 {
		r.fast.hold(r.settleBy(r.cfg.Now(), fp), release)
		return nil, fmt.Errorf("%w: upload returned promise height %d, creation %v", ErrSubmitMismatch, h0, up.Created)
	}
	settleBy := r.settleBy(up.Created, fp)
	refTime, err := r.headerTime(ctx, h0)
	if err != nil {
		r.fast.hold(settleBy, release)
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
		refTime: refTime, retStart: created, release: release, settleBy: settleBy,
	}, nil
}

// maxWithdrawalDelay is the largest withdrawal delay x/fibre accepts. A node
// that does not report the parameter gets this bound: holding a reservation
// too long only costs capacity, releasing it too early can leave a later
// anchor without funds.
const maxWithdrawalDelay = 7 * 24 * time.Hour

// settleBy is when a promise created at created can no longer be charged by
// a timeout settlement: it must be fresher than the withdrawal delay, in
// block time, which may run ahead of this clock by the allowed skew.
func (r *FibreRecorder) settleBy(created time.Time, fp node.FibreParams) time.Time {
	delay := maxWithdrawalDelay
	if fp.WithdrawalDelayS != 0 {
		delay = time.Duration(fp.WithdrawalDelayS) * time.Second
	} else {
		r.delayWarn.Do(func() {
			r.fast.d.Log.Warn("recorder: the node reports no fibre withdrawal delay; escrow reservations are held for the chain maximum", "hold", maxWithdrawalDelay)
		})
	}
	return created.Add(delay + r.cfg.MaxClockSkew)
}

// checkPFF requires the signed tx to carry a promise for exactly this blob at
// the intent's height and creation time, signed by its owner.
func (r *FibreRecorder) checkPFF(tx []byte, rec *archive.AnchorIntentRecord, us uint64) error {
	f, ok, err := fibrecert.ParsePFF(tx)
	switch {
	case err != nil:
		return fmt.Errorf("%w: not a PayForFibre tx: %w", ErrSubmitMismatch, err)
	case !ok:
		return fmt.Errorf("%w: not a PayForFibre tx", ErrSubmitMismatch)
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
// not reserved again: reservations live in memory and died with that
// process, so until its promise settles a new upload can count on escrow
// this promise may still be charged.
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
	// The tx carries the window of the process that signed it; the current
	// one may have changed since.
	landBy, err := node.TxTimeoutHeight(rec.Tx)
	if err != nil {
		return nil, archiveFault("anchor intent", err)
	}
	if landBy == 0 {
		landBy = rec.RefHeight + fp.PromiseHeightWindow
	}
	return &intentDraft{
		rec: rec, timeout: landBy, landBy: landBy,
		expiry:  time.Unix(int64(rec.CreatedAt)+1, 0).Add(time.Duration(fp.PromiseTimeoutS) * time.Second),
		refTime: refTime, retStart: rec.CreatedAt, release: noRelease,
	}, nil
}

func (r *FibreRecorder) wire(tx, _ []byte) ([]byte, error) { return tx, nil }

func (r *FibreRecorder) reach(ctx context.Context) (uint64, error) {
	fp, err := r.fibreParams(ctx)
	if err != nil {
		return 0, err
	}
	return fp.PromiseHeightWindow, nil
}

func (r *FibreRecorder) owns(rec *archive.AnchorIntentRecord, addr []byte) bool {
	if !bytes.Equal(rec.Namespace, r.cfg.Namespace) {
		return false
	}
	f, ok, err := fibrecert.ParsePFF(rec.Tx)
	if err != nil || !ok {
		return false
	}
	bech, err := bech32.ConvertAndEncode(accountPrefix, addr)
	return err == nil && f.Signer == bech
}
