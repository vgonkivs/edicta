package edictad

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// maxArchiveCalls bounds the archive calls in flight. fsarchive takes no
// context for file I/O, so a stuck disk would otherwise pile up goroutines.
const maxArchiveCalls = 64

var errArchiveBusy = errors.New("edictad: archive calls at the in-flight limit")

// archiveIO runs store calls so that the caller returns at its context's end.
// A call that finishes late is harmless: every write is idempotent.
type archiveIO struct {
	st  archive.Store
	sem chan struct{}
}

func newArchiveIO(st archive.Store) *archiveIO {
	return &archiveIO{st: st, sem: make(chan struct{}, maxArchiveCalls)}
}

func call[T any](ctx context.Context, a *archiveIO, f func(context.Context) (T, error)) (T, error) {
	var zero T
	select {
	case a.sem <- struct{}{}:
	default:
		return zero, errArchiveBusy
	}
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() { <-a.sem }()
		v, err := f(ctx)
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

func (a *archiveIO) put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	return call(ctx, a, func(ctx context.Context) (archive.Outcome, error) { return a.st.Put(ctx, r) })
}

func (a *archiveIO) decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	return call(ctx, a, func(ctx context.Context) (*archive.DecisionRecord, error) { return a.st.Decision(ctx, h) })
}

func (a *archiveIO) authorization(ctx context.Context, h commitment.Hash) (*archive.AuthorizationRecord, error) {
	return call(ctx, a, func(ctx context.Context) (*archive.AuthorizationRecord, error) { return a.st.Authorization(ctx, h) })
}

// errArchive marks every failure of the archive stage. The cause is kept as
// text only: a verification sentinel inside it would be read by the HTTP
// mapping as a refusal of the decision instead of a fault of the archive.
var errArchive = errors.New("edictad: archive")

func archiveFault(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errArchive, fmt.Sprintf(format, a...))
}

// archiver is the gate's archive stage over the store.
type archiver struct{ io *archiveIO }

var _ gate.Archiver = (*archiver)(nil)

// Put stores the decision record. A different record under the same key is
// accepted only if it is the same decision: the stored envelope verifies, has
// the same commitment hash and was stored with the same action bytes. That
// admits a re-signed retry and refuses a record that squats the key.
func (a *archiver) Put(ctx context.Context, rec gate.DecisionRecord) error {
	_, err := a.io.put(ctx, &archive.DecisionRecord{Envelope: rec.Envelope, Action: rec.Action})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, archive.ErrConflict):
		return a.checkStored(ctx, rec)
	}
	return archiveFault("put decision: %v", err)
}

func (a *archiver) checkStored(ctx context.Context, rec gate.DecisionRecord) error {
	d, err := a.io.decision(ctx, rec.CommitmentHash)
	if err != nil {
		return archiveFault("read stored decision: %v", err)
	}
	sc, err := commitment.DecodeSigned(d.Envelope)
	if err != nil {
		return archiveFault("stored decision does not decode: %v", err)
	}
	h, err := commitment.Verify(sc)
	if err != nil {
		return archiveFault("stored decision does not verify: %v", err)
	}
	if h != rec.CommitmentHash {
		return archiveFault("stored decision has another commitment hash")
	}
	if !bytes.Equal(d.Action, rec.Action) {
		return archiveFault("stored decision has other action bytes")
	}
	return nil
}

// retryQueue holds records that could not be written after the gate had
// decided; the sweeper retries them. It is bounded: the registry is the
// authority and a sweep repairs what a full queue dropped.
type retryQueue struct {
	mu    sync.Mutex
	items []archive.Record
}

const maxRetryQueue = 1024

func (q *retryQueue) add(r archive.Record) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= maxRetryQueue {
		return false
	}
	q.items = append(q.items, r)
	return true
}

func (q *retryQueue) drain() []archive.Record {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.items
	q.items = nil
	return out
}

func (q *retryQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// writer writes the records that follow the gate's decision. A failure is
// logged and queued, never returned to the client.
type writer struct {
	io      *archiveIO
	q       *retryQueue
	log     *slog.Logger
	timeout time.Duration
}

func (w *writer) write(ctx context.Context, r archive.Record) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.timeout)
	defer cancel()
	_, err := w.io.put(wctx, r)
	switch {
	case err == nil:
	case errors.Is(err, archive.ErrConflict):
		w.log.Error("edictad: archive record conflicts with the stored one", "kind", r.Kind(), "err", err)
	case errors.Is(err, archive.ErrNotFound):
		w.log.Error("edictad: archive record depends on a record that is missing", "kind", r.Kind(), "err", err)
	default:
		queued := w.q.add(r)
		w.log.Error("edictad: archive write failed", "kind", r.Kind(), "queued", queued, "err", err)
	}
}

// verdicts are the rejection markers, in the order they are matched: an
// error that wraps several (ErrAnchorTooOld wraps ErrPayloadUnavailable) gets
// the first.
var verdicts = []struct {
	name string
	err  error
}{
	{"ErrAnchorTooOld", gate.ErrAnchorTooOld},
	{"ErrActionMismatch", commitment.ErrActionMismatch},
	{"ErrAnchorNotFound", gate.ErrAnchorNotFound},
	{"ErrArchiveRecomputeUnsupported", gate.ErrArchiveRecomputeUnsupported},
	{"ErrDACommitmentMismatch", gate.ErrDACommitmentMismatch},
	{"ErrExpired", commitment.ErrExpired},
	{"ErrIssuedBeforeAnchor", commitment.ErrIssuedBeforeAnchor},
	{"ErrNonceUsed", gate.ErrNonceUsed},
	{"ErrNotYetValid", commitment.ErrNotYetValid},
	{"ErrPayloadHashMismatch", commitment.ErrPayloadHashMismatch},
	{"ErrPayloadSizeMismatch", commitment.ErrPayloadSizeMismatch},
	{"ErrPayloadUnavailable", gate.ErrPayloadUnavailable},
	{"ErrRetentionUnavailable", gate.ErrRetentionUnavailable},
}

// operational errors say nothing about the decision, so they leave no marker.
var operational = []error{
	gate.ErrChainUnavailable, gate.ErrArchiveUnavailable, gate.ErrRegistryUnavailable,
	gate.ErrAllowlistUnavailable, gate.ErrClockRegression, gate.ErrClosed,
	context.Canceled, context.DeadlineExceeded,
}

// markerName is the verdict name a refusal is recorded under, if it is one.
func markerName(err error) (string, bool) {
	for _, o := range operational {
		if errors.Is(err, o) {
			return "", false
		}
	}
	for _, v := range verdicts {
		if errors.Is(err, v.err) {
			return v.name, true
		}
	}
	return "", false
}

func k2Record(k gate.K2Inputs) *archive.K2Inputs {
	return &archive.K2Inputs{
		DA:                 k.DA,
		CheckedAt:          k.CheckedAt,
		BlockTime:          k.BlockTime,
		BlobRetentionS:     k.BlobRetentionS,
		RetentionLatestS:   k.RetentionLatestS,
		RetentionAtHeightS: k.RetentionAtHeightS,
		RetentionSource:    archive.RetentionSource(k.RetentionSource),
		PromiseCreated:     k.RetentionStart,
	}
}
