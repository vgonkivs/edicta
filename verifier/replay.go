package verifier

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// Replay verifies the decision and then recomputes the gate's retention
// rule from the inputs the gate archived. The decision is replayed only if
// it verified as authorized, with header trust possibly unchecked.
func (v *Verifier) Replay(ctx context.Context, h commitment.Hash) (ReplayReport, error) {
	r, err := v.verify(ctx, h, nil)
	if err != nil {
		return ReplayReport{}, err
	}
	out := ReplayReport{Report: r.rep}
	switch {
	case r.rep.Verdict != VerdictValid && r.rep.Verdict != VerdictUnchecked:
		out.K2.Reason = "the decision does not verify as authorized"
	case r.auth.K2 == nil:
		out.K2.Reason = "the Authorization record has no K2 inputs"
	default:
		out.K2 = replayK2(r)
	}
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

	switch {
	case k.BlockTime != r.facts.BlockTime:
		rep.Err = fmt.Errorf("%w: archived block time %d, verified %d", ErrGateInconsistent, k.BlockTime, r.facts.BlockTime)
	case rep.AuthorizedPath == commitment.PathDA && !rep.Within:
		rep.Err = fmt.Errorf("%w: the DA path was authorized outside the retention window", ErrGateInconsistent)
	}
	rep.Consistent = rep.Err == nil
	return rep
}
