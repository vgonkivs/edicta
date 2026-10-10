package edictad

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

// anchorMissingGrace is how many blocks past the deadline the watch waits
// for the Recorder to write the evidence of an anchor that landed at the
// deadline.
const anchorMissingGrace = 10

// anchorWatch raises anchor_missing for fast-mode Authorizations whose
// anchor_deadline passed without an evidence record in the archive. It only
// alerts: it never changes an answer or a record.
type anchorWatch struct {
	lister  registry.Lister
	io      *archiveIO
	head    func(ctx context.Context) (uint64, error)
	log     *slog.Logger
	timeout time.Duration
	// lastHead is the head of the last complete pass: an entry whose
	// deadline plus grace is below it was looked at then, so each entry is
	// alerted at most once per process. After a restart old entries are
	// alerted again: the alert is at-least-once, which is safe because it
	// changes no answer and no record.
	lastHead uint64
	// retry holds entries a pass could not decide.
	retry map[commitment.Hash]struct{}
}

func (w *anchorWatch) pass(ctx context.Context) {
	hctx, cancel := context.WithTimeout(ctx, w.timeout)
	head, err := w.head(hctx)
	cancel()
	if err != nil {
		w.log.Warn("edictad: anchor watch could not read the head", "err", err)
		return
	}
	retry := map[commitment.Hash]struct{}{}
	complete := true
	var after *registry.Key
	for complete {
		if ctx.Err() != nil {
			complete = false
			break
		}
		page, err := w.lister.List(ctx, after, sweepPage)
		if err != nil {
			w.log.Error("edictad: anchor watch could not list the registry", "err", err)
			complete = false
			break
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			w.entry(ctx, e, head, retry)
		}
		after = &page[len(page)-1].Key
	}
	if complete {
		w.lastHead, w.retry = head, retry
		return
	}
	for h := range w.retry {
		retry[h] = struct{}{}
	}
	w.retry = retry
}

func (w *anchorWatch) entry(ctx context.Context, e registry.Entry, head uint64, retry map[commitment.Hash]struct{}) {
	sa, _, err := commitment.DecodeSignedAuthorization(e.Authorization)
	if err != nil || sa.Authorization.Mode != commitment.ModeFast {
		return
	}
	due := sa.Authorization.AnchorDeadline + anchorMissingGrace
	if due >= head {
		return
	}
	if _, again := w.retry[e.CommitmentHash]; due < w.lastHead && !again {
		return
	}
	ref, err := w.reference(ctx, e.CommitmentHash)
	if err == nil {
		err = w.evidence(ctx, ref)
	}
	switch {
	case err == nil:
	case errors.Is(err, archive.ErrNotFound):
		w.log.Error("edictad: anchor_missing: no anchor evidence after the deadline of a fast-mode Authorization",
			"commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "da", ref.DA, "h0", ref.Height,
			"anchor_deadline", sa.Authorization.AnchorDeadline, "head", head)
	default:
		w.log.Warn("edictad: anchor watch could not read the archive", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
		retry[e.CommitmentHash] = struct{}{}
	}
}

// errNoDecision keeps a missing decision record from reading as a missing
// anchor: the sweep repairs the record, and the next pass decides.
var errNoDecision = errors.New("edictad: no decision record")

func (w *anchorWatch) reference(ctx context.Context, h commitment.Hash) (commitment.PayloadRef, error) {
	rctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	d, err := w.io.decision(rctx, h)
	if errors.Is(err, archive.ErrNotFound) {
		return commitment.PayloadRef{}, errNoDecision
	}
	if err != nil {
		return commitment.PayloadRef{}, err
	}
	sc, err := commitment.DecodeSigned(d.Envelope)
	if err != nil {
		return commitment.PayloadRef{}, err
	}
	return sc.Commitment.PayloadRef, nil
}

func (w *anchorWatch) evidence(ctx context.Context, ref commitment.PayloadRef) error {
	rctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	_, err := w.io.evidence(rctx, ref.DA, ref.Commitment)
	return err
}
