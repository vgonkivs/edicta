package edictad

import (
	"bytes"
	"context"
	"encoding/hex"
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
// decided; the sweeper retries them. It is bounded: when it is full the record
// is dropped and dropped is set, which makes the sweeper scan the registry for
// what is missing. It lives in memory only, so what is still queued at exit is
// found again by the scan at the next start.
type retryQueue struct {
	mu      sync.Mutex
	items   []archive.Record
	auth    map[commitment.Hash]int // queued Authorization records by decision
	dropped bool
	// pending counts the requests between the registry mark and the end of
	// their record write or queueing, by decision. It is a count because
	// identical requests overlap.
	pending map[commitment.Hash]int
	// dropAfter holds the decisions whose record failed for good while a
	// request still held them; the flag is raised when the last hold ends.
	dropAfter map[commitment.Hash]bool
}

// begin marks a decision as being authorized by a request of this process. It
// must run before the gate marks the registry, so that no scan can see the
// entry while its request is still to write the record with the retention
// inputs only that request has. It does not rely on the wall clock.
func (q *retryQueue) begin(h commitment.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending == nil {
		q.pending = map[commitment.Hash]int{}
	}
	q.pending[h]++
}

func (q *retryQueue) end(h commitment.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending[h] > 1 {
		q.pending[h]--
		return
	}
	delete(q.pending, h)
	if q.dropAfter[h] {
		delete(q.dropAfter, h)
		q.dropped = true
	}
}

// markDroppedFor asks for a registry scan for h's record. While a request
// holds h the flag waits for the hold to end: a tick in between could take it
// and run a pass that skips the entry.
func (q *retryQueue) markDroppedFor(h commitment.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending[h] == 0 {
		q.dropped = true
		return
	}
	if q.dropAfter == nil {
		q.dropAfter = map[commitment.Hash]bool{}
	}
	q.dropAfter[h] = true
}

const maxRetryQueue = 1024

func (q *retryQueue) add(r archive.Record) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= maxRetryQueue {
		q.dropped = true
		return false
	}
	q.items = append(q.items, r)
	if h, ok := authorizationHash(r); ok {
		if q.auth == nil {
			q.auth = map[commitment.Hash]int{}
		}
		q.auth[h]++
	}
	return true
}

func (q *retryQueue) drain() []archive.Record {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.items
	q.items, q.auth = nil, nil
	return out
}

func (q *retryQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// holds reports whether the decision's Authorization record is queued or its
// request is still at work on it.
func (q *retryQueue) holds(h commitment.Hash) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.auth[h] > 0 || q.pending[h] > 0
}

// queued reports whether the decision's Authorization record is in the queue,
// which retries it itself.
func (q *retryQueue) queued(h commitment.Hash) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.auth[h] > 0
}

// takeDropped reports and clears the drop flag.
func (q *retryQueue) takeDropped() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	d := q.dropped
	q.dropped = false
	return d
}

func authorizationHash(r archive.Record) (commitment.Hash, bool) {
	a, ok := r.(*archive.AuthorizationRecord)
	if !ok {
		return commitment.Hash{}, false
	}
	sa, _, err := commitment.DecodeSignedAuthorization(a.SignedAuthorization)
	if err != nil {
		return commitment.Hash{}, false
	}
	var h commitment.Hash
	copy(h[:], sa.Authorization.CommitmentHash)
	return h, true
}

func recordHash(r archive.Record) string {
	var h commitment.Hash
	switch r := r.(type) {
	case *archive.RejectionRecord:
		h = r.CommitmentHash
	default:
		var ok bool
		if h, ok = authorizationHash(r); !ok {
			return ""
		}
	}
	return hex.EncodeToString(h[:])
}

// permanent reports a write error that retrying cannot cure: the record is
// damaged or fails the archive's own validation.
func permanent(err error) bool {
	if errors.Is(err, archive.ErrCorrupt) {
		return true
	}
	for _, e := range []error{
		commitment.ErrMalformed, commitment.ErrWrongType, commitment.ErrMissingField, commitment.ErrFieldSize,
		commitment.ErrInvalidEnum, commitment.ErrZeroValue, commitment.ErrUnsupportedVersion, commitment.ErrIntRange,
		commitment.ErrTooLarge, commitment.ErrNonCanonical, commitment.ErrUnknownKey, commitment.ErrInvalidNamespace,
		commitment.ErrInvalidString, commitment.ErrTimeOrder,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
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
	case permanent(err):
		w.log.Error("edictad: archive record cannot be written and is dropped", "kind", r.Kind(),
			"commitment_hash", recordHash(r), "err", err)
		if h, ok := authorizationHash(r); ok {
			// The registry still has the Authorization; a scan repairs the
			// record without the retention inputs.
			w.q.markDroppedFor(h)
		}
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
