package recorder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

const (
	defaultMaxPending = 4096
	pendingTTL        = time.Hour
	finishedKeep      = 256
	scanFloor         = 1024
	settleDefault     = 1024
	settleFloor       = 256
	// headFreshness bounds how far the head's header time may be from the
	// local clock when a blob is first seen: a node that lags would put the
	// first-seen height below an earlier process's submit and shrink the
	// settle window past it.
	headFreshness = 2 * time.Minute
)

type pendingKey string

// entry is the state of one blob that has been, or is being, submitted.
type entry struct {
	scanned  uint64 // highest height already searched
	created  time.Time
	inflight bool
	done     *sdk.Published
	// sticky is an outcome that must never be retried: paying again could
	// create a second anchor.
	sticky error
	// intent is the archived intent height this entry works from; zero when
	// no payload record was written.
	intent uint64
	// windowed is set when the payload record came from an earlier process:
	// a submit of it may be pending, so submitting waits for the settle window.
	windowed bool
	// submitted is set once a submit call was made. It is not evicted
	// without an archive, because forgetting it would allow a second submit.
	submitted bool
	// firstSeen is the head at this entry's first call. Any submit by an
	// earlier process happened at or below it, so a settle window that
	// reaches past it cannot miss one.
	firstSeen uint64
	// ceil is the head after this process's last submit returned; the
	// promise of that attempt was read at or below it.
	ceil uint64
	// span only grows, so a smaller window parameter cannot shorten a wait
	// already in use.
	span uint64
	// maxHead is the highest head seen; a lower one is another or a lagging node.
	maxHead uint64
}

func (e *entry) evictable(now time.Time, archived bool) bool {
	return e.done == nil && !e.inflight && e.sticky == nil && (!e.submitted || archived) && now.Sub(e.created) > pendingTTL
}

// notBroadcastError marks a submit failure that happened before anything was
// broadcast, so the call counts as never made.
type notBroadcastError struct{ err error }

func (e *notBroadcastError) Error() string { return "recorder: submit: " + e.err.Error() }
func (e *notBroadcastError) Unwrap() error { return e.err }

// backend is what differs between the data availability layers; the
// claim, settle, scan and evidence-first logic that prevents a second payment
// is the same and lives in engine.
type backend interface {
	da() commitment.DA
	// head is the read node's head height and the time of its header.
	head(ctx context.Context) (uint64, time.Time, error)
	payloadRecord(comm, blob []byte, intent uint64) *archive.PayloadRecord
	// samePayload reports a conflict between a stored record and this call.
	samePayload(old *archive.PayloadRecord, blob []byte) error
	// retries reports whether a failed submit of this process may be
	// submitted again once its settle window has passed.
	retries() bool
	// span is how many blocks after a ceiling height an attempt started at or
	// below that ceiling can still land.
	span(ctx context.Context) (uint64, error)
	// present is one scan step: whether the blob is anchored at height.
	present(ctx context.Context, comm []byte, height uint64) (bool, error)
	// preflight runs the checks that must pass before a submit. The returned
	// release is handed to submit, which owns it from then on.
	preflight(ctx context.Context, blob []byte, headTime time.Time) (release func(), err error)
	// submit pays for the blob and returns the node's unverified claim of
	// the height. An error is already classified; one wrapping
	// notBroadcastError means nothing was sent.
	submit(ctx context.Context, comm, blob []byte, release func()) (claimed uint64, err error)
	// confirm verifies the anchor at height, archives the evidence, and
	// answers. claimed is true when height is only the node's claim.
	confirm(ctx context.Context, comm, blob []byte, height uint64, claimed bool) (sdk.Published, error)
	// fromEvidence answers from an archived evidence record.
	fromEvidence(ctx context.Context, comm, blob []byte, ev *archive.EvidenceRecord) (sdk.Published, error)
}

// engine holds the per-blob state of one Recorder.
type engine struct {
	archive    archive.Store
	now        func() time.Time
	maxPending int
	scanBlocks uint64

	mu         sync.Mutex
	entries    map[pendingKey]*entry
	unresolved int
	finished   []pendingKey
	closed     bool
}

func newEngine(store archive.Store, now func() time.Time, maxPending int, scanBlocks uint64) *engine {
	return &engine{archive: store, now: now, maxPending: maxPending, scanBlocks: scanBlocks, entries: map[pendingKey]*entry{}}
}

func clonePublished(p sdk.Published) sdk.Published {
	p.Ref.Namespace = bytes.Clone(p.Ref.Namespace)
	p.Ref.Commitment = bytes.Clone(p.Ref.Commitment)
	p.Ref.Signer = bytes.Clone(p.Ref.Signer)
	return p
}

func archiveFault(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrArchiveUnavailable, what, err)
}

// claim takes ownership of key for this call. The check and the insert share
// one lock hold, so two callers can never both submit.
func (g *engine) claim(key pendingKey) (*entry, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, errClosed
	}
	now, archived := g.now(), g.archive != nil
	if old, ok := g.entries[key]; ok && old.evictable(now, archived) {
		delete(g.entries, key)
		g.unresolved--
	}
	if e, ok := g.entries[key]; ok {
		switch {
		case e.done != nil:
			return e, nil
		case e.sticky != nil:
			return nil, e.sticky
		case e.inflight:
			return nil, fmt.Errorf("%w: another publish of this blob is in progress", ErrOutcomeUnknown)
		}
		e.inflight = true
		return e, nil
	}
	if g.unresolved >= g.maxPending {
		for k, old := range g.entries {
			if old.evictable(now, archived) {
				delete(g.entries, k)
				g.unresolved--
			}
		}
	}
	if g.unresolved >= g.maxPending {
		return nil, fmt.Errorf("%w: %d", ErrTooManyPending, g.unresolved)
	}
	e := &entry{created: now, inflight: true}
	g.entries[key] = e
	g.unresolved++
	return e, nil
}

func (g *engine) release(e *entry) {
	g.mu.Lock()
	e.inflight = false
	g.mu.Unlock()
}

// unwind ends a call that failed before or without a submit. An entry that
// already has archived state or a submit behind it is kept, so its search
// progress and the knowledge that nothing is pending survive.
func (g *engine) unwind(key pendingKey, e *entry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e.submitted || e.intent != 0 {
		e.inflight = false
		return
	}
	if g.entries[key] == e && e.done == nil {
		delete(g.entries, key)
		g.unresolved--
	}
}

func (g *engine) finish(key pendingKey, e *entry, pub sdk.Published) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e.done, e.inflight = &pub, false
	if g.entries[key] != e {
		return
	}
	g.unresolved--
	g.finished = append(g.finished, key)
	if len(g.finished) > finishedKeep {
		delete(g.entries, g.finished[0])
		g.finished = g.finished[1:]
	}
}

func (g *engine) stick(e *entry, err error) {
	g.mu.Lock()
	e.sticky, e.inflight = err, false
	g.mu.Unlock()
}

// publish runs one call for the blob with commitment comm.
func (g *engine) publish(ctx context.Context, b backend, comm, blob []byte) (sdk.Published, error) {
	key := pendingKey(comm)
	e, err := g.claim(key)
	if err != nil {
		return sdk.Published{}, err
	}
	if e.done != nil {
		return clonePublished(*e.done), nil
	}
	pub, err := g.run(ctx, b, key, e, comm, blob)
	if err != nil {
		if errors.Is(err, ErrSubmitMismatch) || errors.Is(err, ErrAnchorRejected) {
			g.stick(e, err)
		}
		return sdk.Published{}, err
	}
	return pub, nil
}

func (g *engine) run(ctx context.Context, b backend, key pendingKey, e *entry, comm, blob []byte) (sdk.Published, error) {
	head, headTime, err := b.head(ctx)
	if err != nil {
		g.unwind(key, e)
		return sdk.Published{}, err
	}
	if err := g.observe(e, head, headTime); err != nil {
		g.unwind(key, e)
		return sdk.Published{}, err
	}

	g.mu.Lock()
	scanOnly := e.submitted && !b.retries()
	g.mu.Unlock()
	if scanOnly {
		return g.resume(ctx, b, key, e, comm, blob, head)
	}

	if g.archive != nil {
		intent, existed, err := g.archivePayload(ctx, b, comm, blob, head)
		if err != nil {
			g.unwind(key, e)
			return sdk.Published{}, err
		}
		g.mu.Lock()
		if e.intent == 0 {
			e.intent, e.windowed = intent, existed
			e.scanned = intent - 1
		}
		g.mu.Unlock()
		pub, answered, err := g.answerFromEvidence(ctx, b, key, e, comm, blob)
		if err != nil || answered {
			return pub, err
		}
	}

	g.mu.Lock()
	needSettle := e.windowed || e.submitted
	g.mu.Unlock()
	if needSettle {
		h, found, ready, err := g.settle(ctx, b, e, comm, head)
		if err != nil {
			g.release(e)
			return sdk.Published{}, err
		}
		if found {
			return g.confirm(ctx, b, key, e, comm, blob, h, false)
		}
		if !ready {
			g.release(e)
			return sdk.Published{}, fmt.Errorf("%w: an earlier submit of this blob may still be pending", ErrOutcomeUnknown)
		}
	}

	release, err := b.preflight(ctx, blob, headTime)
	if err != nil {
		g.unwind(key, e)
		return sdk.Published{}, err
	}

	g.mu.Lock()
	e.submitted = true
	g.mu.Unlock()
	claimed, err := b.submit(ctx, comm, blob, release)
	if b.retries() {
		// The attempt read its promise height at or below this head, also
		// after a failed call, whose upload may still land.
		later, _, herr := b.head(context.WithoutCancel(ctx))
		if herr != nil {
			later = head
		}
		g.mu.Lock()
		e.ceil = max(e.ceil, later)
		g.mu.Unlock()
	}
	if err != nil {
		var nb *notBroadcastError
		if errors.As(err, &nb) {
			g.mu.Lock()
			e.submitted = false
			g.mu.Unlock()
			g.unwind(key, e)
			return sdk.Published{}, err
		}
		g.release(e)
		return sdk.Published{}, err
	}
	return g.confirm(ctx, b, key, e, comm, blob, claimed, true)
}

// observe records the head of this call and refuses one that cannot be
// trusted to bound earlier submits.
func (g *engine) observe(e *entry, head uint64, headTime time.Time) error {
	if head == 0 {
		return fmt.Errorf("%w: head at height 0", ErrNodeUnavailable)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if head < e.maxHead {
		return fmt.Errorf("%w: head %d went backwards from %d", ErrNodeUnavailable, head, e.maxHead)
	}
	if e.firstSeen == 0 {
		if d := absDuration(g.now().Sub(headTime)); d > headFreshness {
			return fmt.Errorf("%w: head time is %s off the clock", ErrNodeUnavailable, d)
		}
		e.firstSeen = head
	}
	e.maxHead = head
	if e.intent == 0 && !e.submitted {
		e.scanned = head - 1
	}
	return nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// resume searches the chain for the blob of an earlier submit of this process
// that is never submitted again.
func (g *engine) resume(ctx context.Context, b backend, key pendingKey, e *entry, comm, blob []byte, head uint64) (sdk.Published, error) {
	h, found, err := g.scan(ctx, b, e, comm, head, math.MaxUint64)
	if err != nil {
		g.release(e)
		return sdk.Published{}, err
	}
	if !found {
		g.release(e)
		return sdk.Published{}, fmt.Errorf("%w: an earlier submit of this blob may still be pending", ErrOutcomeUnknown)
	}
	return g.confirm(ctx, b, key, e, comm, blob, h, false)
}

// answerFromEvidence answers from evidence an earlier run archived: paying
// for another anchor would leave two of one blob.
func (g *engine) answerFromEvidence(ctx context.Context, b backend, key pendingKey, e *entry, comm, blob []byte) (sdk.Published, bool, error) {
	ev, err := g.archive.Evidence(ctx, b.da(), comm)
	switch {
	case err == nil:
	case errors.Is(err, archive.ErrNotFound):
		return sdk.Published{}, false, nil
	default:
		g.unwind(key, e)
		return sdk.Published{}, false, archiveFault("read evidence record", err)
	}
	pub, err := b.fromEvidence(ctx, comm, blob, ev)
	if err != nil {
		g.unwind(key, e)
		return sdk.Published{}, false, err
	}
	g.finish(key, e, pub)
	return clonePublished(pub), true, nil
}

func (g *engine) confirm(ctx context.Context, b backend, key pendingKey, e *entry, comm, blob []byte, h uint64, claimed bool) (sdk.Published, error) {
	pub, err := b.confirm(ctx, comm, blob, h, claimed)
	if err != nil {
		g.release(e)
		return sdk.Published{}, err
	}
	g.finish(key, e, pub)
	return clonePublished(pub), nil
}

// archivePayload makes sure the archive holds the payload record and returns
// its intent height. A stored record is kept as it is, so a restart keeps the
// first intent height; existed is true when the record is not this call's.
func (g *engine) archivePayload(ctx context.Context, b backend, comm, blob []byte, head uint64) (intent uint64, existed bool, err error) {
	old, err := g.archive.Payload(ctx, b.da(), comm)
	switch {
	case err == nil:
		return g.sameRecord(b, old, blob)
	case !errors.Is(err, archive.ErrNotFound):
		return 0, false, archiveFault("read payload record", err)
	}
	out, err := g.archive.Put(ctx, b.payloadRecord(comm, blob, head))
	if err != nil {
		return 0, false, archiveFault("write payload record", err)
	}
	if out == archive.Unchanged {
		// Another writer stored the same payload first; its intent height
		// is the one that counts.
		old, err := g.archive.Payload(ctx, b.da(), comm)
		if err != nil {
			return 0, false, archiveFault("read payload record", err)
		}
		return g.sameRecord(b, old, blob)
	}
	return head, false, nil
}

func (g *engine) sameRecord(b backend, old *archive.PayloadRecord, blob []byte) (uint64, bool, error) {
	if err := b.samePayload(old, blob); err != nil {
		return 0, false, archiveFault("payload record", err)
	}
	if old.IntentHeight == 0 {
		return 0, false, archiveFault("payload record", archive.ErrCorrupt)
	}
	return old.IntentHeight, true, nil
}

// settle searches [intent, ceiling + span] for an earlier submit. The ceiling
// is the highest head at or below which an earlier attempt can have read its
// promise height: for a record of an earlier process, max(intent, first seen
// head), because that process may have submitted any time after the intent;
// for an attempt of this process, the head after it returned. ready reports
// that the whole window was read and the head is past it, so a submit that
// may have been pending is either found or gone.
func (g *engine) settle(ctx context.Context, b backend, e *entry, comm []byte, head uint64) (h uint64, found, ready bool, err error) {
	span, err := b.span(ctx)
	if err != nil {
		return 0, false, false, err
	}
	g.mu.Lock()
	if head < e.intent {
		intent := e.intent
		g.mu.Unlock()
		return 0, false, false, fmt.Errorf("%w: node at height %d is behind the archived intent height %d", ErrNodeUnavailable, head, intent)
	}
	var ceiling uint64
	if e.windowed {
		ceiling = max(e.intent, e.firstSeen)
	}
	if e.submitted {
		ceiling = max(ceiling, e.ceil)
	}
	e.span = max(e.span, span)
	end := ceiling + e.span
	if end < ceiling {
		end = math.MaxUint64
	}
	g.mu.Unlock()

	h, found, err = g.scan(ctx, b, e, comm, head, end)
	if err != nil || found {
		return h, found, false, err
	}
	g.mu.Lock()
	covered := e.scanned >= end
	g.mu.Unlock()
	return 0, false, covered && head > end, nil
}

// scan looks for the blob in the blocks after e.scanned up to min(head,
// limit), resuming where the last search stopped. It reads at most
// scanBlocks blocks per call.
func (g *engine) scan(ctx context.Context, b backend, e *entry, comm []byte, head, limit uint64) (uint64, bool, error) {
	g.mu.Lock()
	lo, hi := e.scanned+1, min(head, limit)
	g.mu.Unlock()
	if hi >= lo && hi-lo >= g.scanBlocks {
		hi = lo + g.scanBlocks - 1
	}
	for h := lo; h <= hi; h++ {
		ok, err := b.present(ctx, comm, h)
		if err != nil {
			return 0, false, fmt.Errorf("%w: scan: %w", ErrNodeUnavailable, err)
		}
		if ok {
			return h, true, nil
		}
		g.mu.Lock()
		e.scanned = h
		g.mu.Unlock()
	}
	return 0, false, nil
}

// closeIntake makes every later claim fail.
func (g *engine) closeIntake() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}
