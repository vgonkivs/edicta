// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"errors"
	"time"
)

// Await polls the sources at L0, the operator's own nodes first, until the
// transaction is at the confirmation depth with its outcome, or until the
// local clock passes until. The caller builds until from chain time
// (Config.AwaitUntil); the local clock only decides when to stop polling.
//
// The error says what the executor may do:
//   - nil: executed or reverted at the depth; the report holds which. Record
//     the rail_ref.
//   - ErrNotFound: past until, a source answered and none ever served the
//     transaction. It is not executed; never sign other bytes.
//   - ErrWrongTx, ErrMalformedRailRef, ErrActionRefused: returned at once;
//     the claim itself is wrong.
//   - any other: the state is unknown (no source answered, or the
//     transaction was seen but not settled by until). Look it up again
//     later; never re-sign.
//   - the context's error when it ends first.
func (c *Checker) Await(ctx context.Context, t Target, until time.Time) (Report, error) {
	srcs := ownFirst(c.srcs)
	var answeredNotFound, seen bool
	for {
		rep, probes := c.evaluate(ctx, t, LevelNodeAttested, LevelNodeAttested, srcs)
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		switch {
		case rep.Status == StatusPass:
			return rep, nil
		case rep.Status == StatusViolated, rep.Reason == ReasonMalformedRailRef, rep.Reason == ReasonActionRefused:
			return rep, rep.Err
		}
		for _, p := range probes {
			answeredNotFound = answeredNotFound || p.notFound
			seen = seen || p.seen
		}
		now := c.now()
		if !now.Before(until) {
			switch {
			case answeredNotFound && !seen:
				rep.Reason, rep.Err = ReasonNotFound, wrapf(ErrNotFound, "not found by %s", until.UTC().Format(time.RFC3339))
			case seen && errors.Is(rep.Err, ErrNotFound):
				// Served once, gone now: a rolled-back block, not a
				// transaction that never landed.
				rep.Reason, rep.Err = ReasonUnconfirmed, wrapf(ErrUnconfirmed, "served earlier, not found now")
			}
			return rep, rep.Err
		}
		if err := c.sleep(ctx, min(c.cfg.PollInterval, until.Sub(now))); err != nil {
			return rep, err
		}
	}
}
