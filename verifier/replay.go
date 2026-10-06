package verifier

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/commitment"
)

// Replay verifies the decision and then recomputes the gate's retention
// rule from the inputs the gate archived. The decision is replayed only if
// it verified as authorized, with header trust possibly unchecked. A gate
// that contradicts its own recorded inputs fails the retention_replay check
// and so the verdict.
func (v *Verifier) Replay(ctx context.Context, h commitment.Hash) (ReplayReport, error) {
	r, err := v.verify(ctx, h, nil)
	if err != nil {
		return ReplayReport{}, err
	}
	out := ReplayReport{}
	switch {
	case r.rep.Verdict != VerdictValid && r.rep.Verdict != VerdictUnchecked:
		out.K2.Reason = "the decision does not verify as authorized"
	case r.facts == nil || r.sa == nil:
		out.K2.Reason = "the anchor did not verify"
	case r.auth.K2 == nil:
		out.K2.Reason = "the Authorization record has no retention inputs"
	default:
		out.K2 = replayK2(r)
		switch {
		case !out.K2.Consistent:
			r.fail(CheckRetention, out.K2.Err)
			r.finish()
		case out.K2.Unconfirmed:
			r.unchecked(CheckRetention, errors.New("an earlier promise creation time cannot be checked against a form-0 record"))
			r.finish()
		}
	}
	out.Report = r.rep
	return out, nil
}

func replayK2(r *run) K2Replay {
	k := r.auth.K2
	rep := K2Replay{Replayable: true, AuthorizedPath: r.sa.Authorization.Path}
	switch r.c.PayloadRef.DA {
	case commitment.DAFibre:
		rep.R = min(k.RetentionLatestS, k.RetentionAtHeightS)
		rep.Start = k.BlockTime
		if k.PromiseCreated != 0 {
			rep.Start = min(k.BlockTime, k.PromiseCreated)
		}
	default:
		rep.R = k.BlobRetentionS
		rep.Start = k.BlockTime
	}
	rep.Margin = commitment.RetentionMargin(rep.R)
	// With no promise creation time the window is false by rule.
	rep.Within = commitment.WithinRetention(r.c, rep.Start, rep.R)
	if r.c.PayloadRef.DA == commitment.DAFibre && k.PromiseCreated == 0 {
		rep.Within = false
	}
	rep.Route = commitment.PathArchive
	if rep.Within {
		rep.Route = commitment.PathDA
	}

	p := r.v.cfg.Params
	a := r.auth
	switch {
	case k.BlockTime != r.facts.BlockTime:
		rep.Err = fmt.Errorf("%w: archived block time %d, verified %d", ErrGateInconsistent, k.BlockTime, r.facts.BlockTime)
	case r.c.PayloadRef.DA != commitment.DAFibre && k.BlobRetentionS != p.BlobRetentionS:
		rep.Err = fmt.Errorf("%w: archived blob retention %d, configured %d", ErrGateInconsistent, k.BlobRetentionS, p.BlobRetentionS)
	case r.c.PayloadRef.DA == commitment.DAFibre && !creationAccepted(k.PromiseCreated, r.facts, rep.AuthorizedPath):
		rep.Err = fmt.Errorf("%w: archived promise creation %d, verified %d", ErrGateInconsistent, k.PromiseCreated, r.facts.RetentionStart)
	case k.CheckedAt >= r.c.ValidUntil:
		rep.Err = fmt.Errorf("%w: checked at %d, not before valid until %d", ErrGateInconsistent, k.CheckedAt, r.c.ValidUntil)
	case a.AuthorizedAt >= r.c.ValidUntil:
		rep.Err = fmt.Errorf("%w: authorized at %d, not before valid until %d", ErrGateInconsistent, a.AuthorizedAt, r.c.ValidUntil)
	case r.sa.Authorization.Expires < a.AuthorizedAt:
		rep.Err = fmt.Errorf("%w: expires %d before it was issued at %d", ErrGateInconsistent, r.sa.Authorization.Expires, a.AuthorizedAt)
	case rep.AuthorizedPath == commitment.PathDA && !rep.Within:
		rep.Err = fmt.Errorf("%w: the DA path was authorized outside the retention window", ErrGateInconsistent)
	}
	rep.Consistent = rep.Err == nil
	rep.Unconfirmed = rep.Consistent && r.c.PayloadRef.DA == commitment.DAFibre &&
		k.PromiseCreated != 0 && k.PromiseCreated != r.facts.RetentionStart &&
		!slices.Contains(r.facts.EarlierCreations, k.PromiseCreated)
	return rep
}

// creationAccepted: the gate recorded the creation time of the candidate it
// anchored, which is the archived one or an earlier candidate's. An absent
// time is only consistent with the archive path.
func creationAccepted(created uint64, f *AnchorFacts, path commitment.PayloadPath) bool {
	if created == 0 {
		return path == commitment.PathArchive
	}
	return created == f.RetentionStart || slices.Contains(f.EarlierCreations, created) || formZeroEarlier(created, f)
}

// formZeroEarlier: a form-0 record shows no other candidates, so a smaller
// recorded time cannot be confirmed or refuted; it is reported as unchecked.
func formZeroEarlier(created uint64, f *AnchorFacts) bool {
	return f.ProofForm == 0 && created < f.RetentionStart
}
