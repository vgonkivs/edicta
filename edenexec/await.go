// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"fmt"
	"time"
)

// Await polls every source, the operator's own nodes first, and combines
// their answers by operator into one state (Report.State), until the
// transaction has an outcome at the configured level or the local clock
// passes until. The caller builds until from chain time (Config.AwaitUntil);
// the local clock only decides when to stop polling.
//
// The error says what the executor may do:
//   - nil: executed or reverted at Report.Level. Record the rail_ref.
//   - ErrNotFound: not executed. Past until, no source served the
//     transaction in any poll of this Await, not even one set aside
//     afterwards, and at least MinSources operators answered not found in
//     the last poll.
//     Never sign other bytes; only the operator may release the nonce.
//   - ErrWrongTx, ErrMalformedRailRef, ErrActionRefused: returned at once;
//     the claim itself is wrong.
//   - ErrDisagree: past until, passing sources still disagree (disputed).
//   - ErrSettlementUnknown: past until, anything else. Look it up again
//     later; never re-sign, never release.
//   - the context's error when it ends first.
//
// Before until, a disagreement keeps the poll going: a lagging source
// catches up and a rolled-back block disappears everywhere.
//
// Report.Seen says whether any source served the transaction in any poll.
func (c *Checker) Await(ctx context.Context, t Target, until time.Time) (Report, error) {
	return c.AwaitSeen(ctx, t, until, false)
}

// AwaitSeen is Await continuing an earlier wait for the same rail_ref:
// seen is the Report.Seen of that wait. A source that once served the
// transaction and now answers not found saw a rolled-back block, or prunes
// or lags; that is no evidence of absence, so it keeps not executed out of
// reach for the rest of the wait.
func (c *Checker) AwaitSeen(ctx context.Context, t Target, until time.Time, seen bool) (Report, error) {
	srcs := ownFirst(c.srcs)
	for {
		now := c.now()
		rep := c.poll(ctx, t, srcs, !now.Before(until), seen)
		seen = rep.Seen
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		switch {
		case rep.Status == StatusViolated, rep.Reason == ReasonMalformedRailRef, rep.Reason == ReasonActionRefused:
			return rep, rep.Err
		case rep.State == AwaitExecuted, rep.State == AwaitReverted:
			return rep, nil
		case rep.State == AwaitNotExecuted:
			return rep, wrapf(ErrNotFound, "not executed: not found by %d operators by %s",
				c.cfg.MinSources, until.UTC().Format(time.RFC3339))
		case rep.State == AwaitDisputed && !now.Before(until):
			return rep, rep.Err
		case rep.State == AwaitUnknown:
			// The cause is text only: an unknown state must never read as
			// the not-found of a transaction that was not executed.
			return rep, fmt.Errorf("%w: %v", ErrSettlementUnknown, rep.Err)
		}
		if err := c.sleep(ctx, min(c.cfg.PollInterval, until.Sub(now))); err != nil {
			return rep, err
		}
	}
}

// poll evaluates the sources once at the configured level, at most L1, and
// sets the combined state; seenBefore is whether an earlier poll of the
// same wait saw the transaction.
func (c *Checker) poll(ctx context.Context, t Target, srcs []Source, untilPassed, seenBefore bool) Report {
	level := min(c.cfg.MinLevel, LevelMultiSource)
	rep, probes := c.evaluate(ctx, t, level, LevelMultiSource, srcs)
	rep.State, rep.Seen = AwaitUnknown, seenBefore
	if rep.Status == StatusViolated || rep.Reason == ReasonMalformedRailRef || rep.Reason == ReasonActionRefused {
		return rep
	}
	comb := combineProbes(probes)
	comb.seen = comb.seen || seenBefore
	rep.Seen = comb.seen
	st, lvl := awaitState(comb, level, c.cfg.MinSources, untilPassed)
	rep.State = st
	if (st == AwaitExecuted || st == AwaitReverted) && (rep.Status != StatusPass || rep.Level != lvl) {
		// The report and the combination read the same probes; a mismatch
		// is a defect here, and an outcome must never rest on it.
		err := wrapf(ErrBelowLevel, "report %s at %s, combination %s at %s", rep.Status, rep.Level, st, lvl)
		rep.State, rep.Status, rep.Reason, rep.Err = AwaitUnknown, StatusUnchecked, ReasonBelowLevel, err
	}
	return rep
}
