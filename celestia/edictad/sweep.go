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

const sweepPage = 256

type sweepStats struct{ repaired, noDecision, conflicts, failed, permanent int }

// sweeper copies Authorizations the registry holds into the archive. The
// registry is written first, so a crash or an archive outage between the two
// leaves the archive short, never ahead.
type sweeper struct {
	lister  registry.Lister
	io      *archiveIO
	q       *retryQueue
	log     *slog.Logger
	timeout time.Duration
	// recheck holds entries a scan skipped because their request was still at
	// work; each tick looks at them again. A set that is full asks for a
	// full pass instead.
	recheck  map[registry.Key]registry.Entry
	overflow bool
	// pol is set when the gate has a mandate: the sweep then also repairs
	// the policy records, ahead of the Authorization record.
	pol *polInfo
	// reveals reports whether a receipt for the action type publishes its
	// salt; nil reveals nothing.
	reveals func(actionType string) bool
	// revealDone holds the decisions whose reveal this process has seen in
	// the archive or found not to apply, so a pass does not read it again.
	revealDone map[commitment.Hash]struct{}
	// anchors is set in fast mode: every tick also looks for anchors that
	// missed their deadline.
	anchors *anchorWatch
}

// maxRevealDone bounds revealDone; a full set is dropped, which only costs
// one more read per entry.
const maxRevealDone = 1 << 16

func (s *sweeper) revealSettled(h commitment.Hash) {
	if s.revealDone == nil || len(s.revealDone) >= maxRevealDone {
		s.revealDone = map[commitment.Hash]struct{}{}
	}
	s.revealDone[h] = struct{}{}
}

// maxRecheck bounds the entries kept for another look.
const maxRecheck = 4096

// sweepResult says what a pass left undone.
type sweepResult struct {
	stats sweepStats
	// scanFailed: a registry entry could not be repaired or read.
	scanFailed bool
	// incomplete: the pass ended before the registry was read to the end.
	incomplete bool
}

// run retries the queued records, then sweeps the registry if full. The queue
// goes first: its records carry the retention inputs that a record repaired
// from the registry lacks, and the archive keeps the first write. The scan
// skips entries whose record is still queued, for the same reason. The archive
// is only repaired, never rewritten.
func (s *sweeper) run(ctx context.Context, full bool) sweepResult {
	var res sweepResult
	st := &res.stats
	for _, r := range s.q.drain() {
		perm := st.permanent
		if c, ok := r.(*chain); ok {
			rest := s.putChain(ctx, c, st)
			if h, ok := authorizationHash(r); ok && st.permanent > perm {
				s.q.markDroppedFor(h)
			}
			if rest != nil && !s.q.add(rest) {
				rest.abandon(rest.recs)
				s.log.Error("edictad: archive retry queue is full; the record is left to the next registry scan",
					"kind", r.Kind(), "commitment_hash", recordHash(r))
			}
			continue
		}
		done := s.put(ctx, r, st)
		if h, ok := authorizationHash(r); ok && st.permanent > perm {
			// Only the retry of a queued record raises the flag, never the
			// scan's own repair, or a record that cannot be written would
			// keep every tick scanning.
			s.q.markDroppedFor(h)
		}
		if !done && !s.q.add(r) {
			s.log.Error("edictad: archive retry queue is full; the record is left to the next registry scan",
				"kind", r.Kind(), "commitment_hash", recordHash(r))
		}
	}
	s.recheckHeld(ctx, st)
	if full {
		before := st.failed
		if s.pol != nil {
			s.pol.repair(ctx, s, st)
		}
		res.incomplete = !s.scan(ctx, st)
		res.scanFailed = st.failed > before
	}
	s.log.Info("edictad: archive sweep", "repaired", st.repaired, "no_decision", st.noDecision,
		"conflicts", st.conflicts, "failed", st.failed, "permanent", st.permanent)
	return res
}

// scan reports whether it read the registry to the end.
func (s *sweeper) scan(ctx context.Context, st *sweepStats) bool {
	var after *registry.Key
	for ctx.Err() == nil {
		page, err := s.lister.List(ctx, after, sweepPage)
		if err != nil {
			s.log.Error("edictad: archive sweep could not list the registry", "err", err)
			st.failed++
			return false
		}
		if len(page) == 0 {
			return true
		}
		for _, e := range page {
			if ctx.Err() != nil {
				return false
			}
			s.entry(ctx, e, st)
		}
		after = &page[len(page)-1].Key
	}
	return false
}

// recheckHeld looks again at the entries a scan left to their requests. One
// that is still at work stays; one that is settled, or that the queue now
// carries, goes; one that could not be read stays for the next tick.
func (s *sweeper) recheckHeld(ctx context.Context, st *sweepStats) {
	for k, e := range s.recheck {
		if ctx.Err() != nil {
			return
		}
		if s.q.holds(e.CommitmentHash) {
			if s.q.queued(e.CommitmentHash) {
				delete(s.recheck, k)
			}
			continue
		}
		if s.entry(ctx, e, st) {
			delete(s.recheck, k)
		}
	}
}

func (s *sweeper) hold(e registry.Entry) {
	if _, ok := s.recheck[e.Key]; !ok && len(s.recheck) >= maxRecheck {
		s.overflow = true
		return
	}
	if s.recheck == nil {
		s.recheck = map[registry.Key]registry.Entry{}
	}
	s.recheck[e.Key] = e
}

// entry repairs the archive record of one registry entry. It reports false
// if the entry has to be looked at again, including when a request holds it:
// the hold can start between recheckHeld's own check and this one.
func (s *sweeper) entry(ctx context.Context, e registry.Entry, st *sweepStats) bool {
	if s.q.queued(e.CommitmentHash) {
		return true
	}
	if s.q.holds(e.CommitmentHash) {
		s.hold(e)
		return false
	}
	if !s.repairReveal(ctx, e, st) {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	_, err := s.io.authorization(rctx, e.CommitmentHash)
	cancel()
	switch {
	case err == nil:
		return true
	case errors.Is(err, archive.ErrCorrupt):
		s.log.Error("edictad: archived Authorization is corrupt", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
		return true
	case !errors.Is(err, archive.ErrNotFound):
		st.failed++
		return false
	}
	auth := &archive.AuthorizationRecord{SignedAuthorization: e.Authorization, AuthorizedAt: e.AuthorizedAt}
	if s.pol == nil || len(e.Verdict) == 0 {
		return s.put(ctx, auth, st)
	}
	recs, err := s.pol.allowRecords(e.ClosedBucket, e.ClosedSet, e.Verdict, e.PrivatePart, e.CommitmentHash)
	if err != nil {
		s.log.Error("edictad: the registry's policy verdict does not decode", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
		st.permanent++
		return true
	}
	return s.putChain(ctx, &chain{recs: append(recs, auth)}, st) == nil
}

// repairReveal rewrites the reveal on execution of an entry with a receipt
// whose private decision is of a revealing type. It reports false when the
// entry has to be looked at again.
func (s *sweeper) repairReveal(ctx context.Context, e registry.Entry, st *sweepStats) bool {
	if s.reveals == nil || len(e.Receipt) == 0 || len(e.ActionSalt) == 0 || !s.pol.private() {
		return true
	}
	if _, ok := s.revealDone[e.CommitmentHash]; ok {
		return true
	}
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	switch _, err := s.io.reveal(rctx, e.CommitmentHash); {
	case err == nil:
		s.revealSettled(e.CommitmentHash)
		return true
	case errors.Is(err, errNoRevealReader):
		return true
	case !errors.Is(err, archive.ErrNotFound):
		st.failed++
		return false
	}
	d, err := s.io.decision(rctx, e.CommitmentHash)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			st.noDecision++
			return true
		}
		st.failed++
		return false
	}
	sc, err := commitment.DecodeSigned(d.Envelope)
	if err != nil || d.Form != archive.FormPrivate || !s.reveals(sc.Commitment.Action.Type) {
		s.revealSettled(e.CommitmentHash)
		return true
	}
	repaired := st.repaired
	done := s.put(ctx, &archive.RevealRecord{SignedReceipt: e.Receipt, ActionSalt: e.ActionSalt}, st)
	if st.repaired > repaired {
		s.revealSettled(e.CommitmentHash)
	}
	return done
}

// putChain writes the records in order and returns what is left to retry: the
// tail from the first record that failed for a reason a retry may cure. A
// record that cannot be written, or whose dependency is missing, ends the
// chain without a retry, so that nothing is written ahead of it.
func (s *sweeper) putChain(ctx context.Context, c *chain, st *sweepStats) *chain {
	for i, r := range c.recs {
		perm, nodec, repaired := st.permanent, st.noDecision, st.repaired
		if !s.put(ctx, r, st) {
			return c.tail(i)
		}
		c.settle(r, st.repaired > repaired)
		if st.permanent > perm || st.noDecision > nodec {
			c.abandon(c.recs[i+1:])
			return nil
		}
	}
	return nil
}

// put reports whether the record needs no further retry.
func (s *sweeper) put(ctx context.Context, r archive.Record, st *sweepStats) bool {
	wctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	_, err := s.io.put(wctx, r)
	switch {
	case err == nil:
		st.repaired++
	case errors.Is(err, archive.ErrNotFound):
		st.noDecision++
	case errors.Is(err, archive.ErrConflict) && r.Kind() == archive.KindPolicySuccessor:
		s.log.Error("edictad: a second allow consumed the same policy state: possible fork of the gate's counter", "err", err)
		st.conflicts++
	case errors.Is(err, archive.ErrConflict) && r.Kind() == archive.KindAuthorization:
		s.log.Error("edictad: a second Authorization exists for a commitment; the registry's is authoritative", "err", err)
		st.conflicts++
	case errors.Is(err, archive.ErrConflict):
		s.log.Error("edictad: archive record conflicts with the stored one", "kind", r.Kind(), "err", err)
		st.conflicts++
	case permanent(err):
		s.log.Error("edictad: archive record cannot be written and is dropped", "kind", r.Kind(),
			"commitment_hash", recordHash(r), "err", err)
		st.permanent++
	default:
		st.failed++
		return false
	}
	return true
}

// loop re-runs the sweep on every tick while work is left: a full registry
// pass after a pass that failed or was cut short, or after the queue dropped a
// record, and the queue whenever it holds records. needFull asks for a full
// pass right away.
func (s *sweeper) loop(ctx context.Context, tick <-chan time.Time, interval time.Duration, needFull bool) {
	if tick == nil {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	immediate := needFull
	for {
		if !immediate {
			select {
			case <-ctx.Done():
				return
			case <-tick:
			}
		}
		immediate = false
		if s.anchors != nil {
			s.anchors.pass(ctx)
		}
		if s.q.takeDropped() {
			needFull = true
		}
		if !needFull && s.q.len() == 0 && len(s.recheck) == 0 {
			continue
		}
		res := s.run(ctx, needFull)
		needFull = needFull && (res.scanFailed || res.incomplete)
		if s.overflow {
			s.overflow, needFull = false, true
		}
		if ctx.Err() != nil {
			return
		}
	}
}
