package edictad

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/gate/registry"
)

const sweepPage = 256

type sweepStats struct{ repaired, noDecision, conflicts, failed int }

// sweeper copies Authorizations the registry holds into the archive. The
// registry is written first, so a crash or an archive outage between the two
// leaves the archive short, never ahead.
type sweeper struct {
	lister  registry.Lister
	io      *archiveIO
	q       *retryQueue
	log     *slog.Logger
	timeout time.Duration
}

// run retries the queued records, then sweeps the registry if full. The queue
// goes first: its records carry K2 inputs that a record repaired from the
// registry lacks, and the archive keeps the first write. The archive is only
// repaired, never rewritten. scanFailed is true if the registry pass left work.
func (s *sweeper) run(ctx context.Context, full bool) (st sweepStats, scanFailed bool) {
	for _, r := range s.q.drain() {
		if !s.put(ctx, r, &st) {
			s.q.add(r)
		}
	}
	if full {
		before := st.failed
		s.scan(ctx, &st)
		scanFailed = st.failed > before
	}
	s.log.Info("edictad: archive sweep", "repaired", st.repaired, "no_decision", st.noDecision,
		"conflicts", st.conflicts, "failed", st.failed)
	return st, scanFailed
}

func (s *sweeper) scan(ctx context.Context, st *sweepStats) {
	var after *registry.Key
	for ctx.Err() == nil {
		page, err := s.lister.List(ctx, after, sweepPage)
		if err != nil {
			s.log.Error("edictad: archive sweep could not list the registry", "err", err)
			st.failed++
			return
		}
		if len(page) == 0 {
			return
		}
		for _, e := range page {
			s.entry(ctx, e, st)
		}
		after = &page[len(page)-1].Key
	}
}

func (s *sweeper) entry(ctx context.Context, e registry.Entry, st *sweepStats) {
	rctx, cancel := context.WithTimeout(ctx, s.timeout)
	_, err := s.io.authorization(rctx, e.CommitmentHash)
	cancel()
	switch {
	case err == nil:
		return
	case errors.Is(err, archive.ErrCorrupt):
		s.log.Error("edictad: archived Authorization is corrupt", "commitment_hash", hex.EncodeToString(e.CommitmentHash[:]), "err", err)
		return
	case !errors.Is(err, archive.ErrNotFound):
		st.failed++
		return
	}
	s.put(ctx, &archive.AuthorizationRecord{SignedAuthorization: e.Authorization, AuthorizedAt: e.AuthorizedAt}, st)
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
	case errors.Is(err, archive.ErrConflict):
		s.log.Error("edictad: a second Authorization exists for a commitment; the registry's is authoritative", "err", err)
		st.conflicts++
	default:
		st.failed++
		return false
	}
	return true
}

// loop re-runs the sweep on every tick while work is left: a full registry
// pass after a pass that failed, and the queue whenever it holds records.
func (s *sweeper) loop(ctx context.Context, tick <-chan time.Time, interval time.Duration, needFull bool) {
	if tick == nil {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		if !needFull && s.q.len() == 0 {
			continue
		}
		_, needFull = s.run(ctx, needFull)
	}
}
