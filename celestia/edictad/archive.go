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
	"github.com/vgonkivs/edicta/policy"
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
	// private is set under a mandate with auditors: its rules and state
	// then go to the archive only sealed.
	private bool
}

// errClearInPrivate refuses a clear mandate, bucket or closed set under a
// private mandate. The records are built sealed, so this is a last guard.
var errClearInPrivate = errors.New("edictad: a private mandate's record must be sealed")

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
	if a.private {
		switch r.Kind() {
		case archive.KindMandate, archive.KindPolicyBucket, archive.KindPolicyClosed:
			return 0, fmt.Errorf("%w: kind %d", errClearInPrivate, r.Kind())
		}
	}
	return call(ctx, a, func(ctx context.Context) (archive.Outcome, error) { return a.st.Put(ctx, r) })
}

func (a *archiveIO) decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	return call(ctx, a, func(ctx context.Context) (*archive.DecisionRecord, error) { return a.st.Decision(ctx, h) })
}

var errNoRevealReader = errors.New("edictad: the archive does not read reveals")

func (a *archiveIO) reveal(ctx context.Context, h commitment.Hash) (*archive.RevealRecord, error) {
	rr, ok := a.st.(archive.RevealReader)
	if !ok {
		return nil, errNoRevealReader
	}
	return call(ctx, a, func(ctx context.Context) (*archive.RevealRecord, error) { return rr.Reveal(ctx, h) })
}

func (a *archiveIO) evidence(ctx context.Context, da commitment.DA, c []byte) (*archive.EvidenceRecord, error) {
	return call(ctx, a, func(ctx context.Context) (*archive.EvidenceRecord, error) { return a.st.Evidence(ctx, da, c) })
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

var (
	_ gate.Archiver       = (*archiver)(nil)
	_ gate.RevealArchiver = (*archiver)(nil)
)

// Put stores the decision record. A different record under the same key is
// accepted only if it is the same decision: the stored envelope verifies, has
// the same commitment hash and was stored with the same action bytes. That
// admits a re-signed retry and refuses a record that squats the key. A
// private decision writes its sealed action first and holds no action
// bytes or salt itself.
func (a *archiver) Put(ctx context.Context, rec gate.DecisionRecord) error {
	dec := &archive.DecisionRecord{Envelope: rec.Envelope, Form: archive.FormPublic, Action: rec.Action, ActionSalt: rec.ActionSalt}
	if rec.Private() {
		if _, err := a.io.put(ctx, &archive.PrivateBlobRecord{
			PlaintextKind: policy.PrivateAction, Hash: bytes.Clone(rec.ActionHash[:]), Envelope: rec.PrivateAction,
		}); err != nil {
			return archiveFault("put private action: %v", err)
		}
		dec = &archive.DecisionRecord{Envelope: rec.Envelope, Form: archive.FormPrivate}
	}
	_, err := a.io.put(ctx, dec)
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
	wantForm := uint64(archive.FormPublic)
	if rec.Private() {
		wantForm = archive.FormPrivate
	}
	if d.Form != wantForm || !bytes.Equal(d.Action, rec.Action) || !bytes.Equal(d.ActionSalt, rec.ActionSalt) {
		return archiveFault("stored decision has another form, other action bytes or another salt")
	}
	return nil
}

// PutReveal stores the reveal on execution of a private decision.
func (a *archiver) PutReveal(ctx context.Context, rec gate.RevealRecord) error {
	if _, err := a.io.put(ctx, &archive.RevealRecord{SignedReceipt: rec.Receipt, ActionSalt: rec.ActionSalt}); err != nil {
		return archiveFault("put reveal: %v", err)
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

// chain is a group of records that must reach the archive in this order: a
// record is never written before the ones ahead of it. When a write has to be
// retried, the queue keeps the tail from the failed record on.
type chain struct {
	recs []archive.Record
	// deny is set on a private deny's chain: its policy_deny record settles
	// the dedup reservation.
	deny *denyHold
}

// denyHold is a private deny's dedup reservation, held until the store has
// acknowledged or refused the policy_deny record.
type denyHold struct {
	x *denyIndex
	k denyKey
}

// tail is the chain from record i on, still carrying the reservation.
func (c *chain) tail(i int) *chain { return &chain{recs: c.recs[i:], deny: c.deny} }

// settle commits the reservation once the policy_deny record is stored and
// releases it when the store refused it, so a later retry writes it again.
func (c *chain) settle(r archive.Record, acked bool) {
	if c.deny == nil || r.Kind() != archive.KindPolicyDeny {
		return
	}
	if acked {
		c.deny.x.commit(c.deny.k)
		return
	}
	c.deny.x.release(c.deny.k)
}

// abandon releases the reservation when the chain stops for good before its
// policy_deny record was settled.
func (c *chain) abandon(rest []archive.Record) {
	if c.deny == nil {
		return
	}
	for _, r := range rest {
		if r.Kind() == archive.KindPolicyDeny {
			c.deny.x.release(c.deny.k)
			return
		}
	}
}

func (c *chain) Kind() archive.Kind {
	if len(c.recs) == 0 {
		return 0
	}
	return c.recs[len(c.recs)-1].Kind()
}

func authorizationHash(r archive.Record) (commitment.Hash, bool) {
	if c, ok := r.(*chain); ok {
		for _, m := range c.recs {
			if h, ok := authorizationHash(m); ok {
				return h, true
			}
		}
		return commitment.Hash{}, false
	}
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

// policyRecordHash is the commitment hash of a policy verdict record.
func policyRecordHash(r archive.Record) (commitment.Hash, bool) {
	var b []byte
	switch r := r.(type) {
	case *archive.PolicyAllowRecord:
		b = r.SignedVerdict
	case *archive.PolicyDenyRecord:
		b = r.SignedVerdict
	}
	sv, _, err := policy.DecodeSignedVerdict(b)
	if err != nil {
		return commitment.Hash{}, false
	}
	var h commitment.Hash
	copy(h[:], sv.Verdict.CommitmentHash)
	return h, true
}

func recordHash(r archive.Record) string {
	if c, ok := r.(*chain); ok && len(c.recs) > 0 {
		return recordHash(c.recs[len(c.recs)-1])
	}
	var h commitment.Hash
	switch r := r.(type) {
	case *archive.RejectionRecord:
		h = r.CommitmentHash
	case *archive.PolicyAllowRecord, *archive.PolicyDenyRecord:
		var ok bool
		if h, ok = policyRecordHash(r); !ok {
			return ""
		}
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
	if errors.Is(err, archive.ErrCorrupt) || errors.Is(err, errClearInPrivate) {
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
	if c, ok := r.(*chain); ok {
		w.writeChain(ctx, c)
		return
	}
	if w.writeOne(ctx, r) == writeRetry {
		w.queue(r)
	}
}

func (w *writer) queue(r archive.Record) bool {
	queued := w.q.add(r)
	w.log.Error("edictad: archive write failed", "kind", r.Kind(), "queued", queued)
	return queued
}

// writeChain writes the records in order and stops at the first one that has
// to be retried, queueing it and the ones behind it as one chain. A record
// that can never be written ends the chain too: the registry still holds the
// Authorization, and the scan repairs the rest in order.
func (w *writer) writeChain(ctx context.Context, c *chain) {
	for i, r := range c.recs {
		res := w.writeOne(ctx, r)
		switch res {
		case writeRetry:
			if !w.queue(c.tail(i)) {
				c.abandon(c.recs[i:])
			}
			return
		case writeStop:
			c.abandon(c.recs[i:])
			if h, ok := authorizationHash(c); ok {
				w.q.markDroppedFor(h)
			}
			return
		}
		c.settle(r, res == writeDone)
	}
}

type writeResult int

const (
	writeDone writeResult = iota
	// writeRefused: the store answered and keeps something else, or lacks
	// a record this one depends on. The chain goes on, but the record is
	// not stored.
	writeRefused
	writeRetry
	writeStop
)

func (w *writer) writeOne(ctx context.Context, r archive.Record) writeResult {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.timeout)
	defer cancel()
	_, err := w.io.put(wctx, r)
	switch {
	case err == nil:
	case errors.Is(err, archive.ErrConflict) && r.Kind() == archive.KindPolicySuccessor:
		w.log.Error("edictad: a second allow consumed the same policy state: possible fork of the gate's counter", "err", err)
		return writeRefused
	case errors.Is(err, archive.ErrConflict):
		w.log.Error("edictad: archive record conflicts with the stored one", "kind", r.Kind(), "err", err)
		return writeRefused
	case errors.Is(err, archive.ErrNotFound):
		w.log.Error("edictad: archive record depends on a record that is missing", "kind", r.Kind(), "err", err)
		return writeRefused
	case permanent(err):
		w.log.Error("edictad: archive record cannot be written and is dropped", "kind", r.Kind(),
			"commitment_hash", recordHash(r), "err", err)
		if h, ok := authorizationHash(r); ok {
			// The registry still has the Authorization; a scan repairs the
			// record without the retention inputs.
			w.q.markDroppedFor(h)
		}
		return writeStop
	default:
		w.log.Error("edictad: archive write failed", "kind", r.Kind(), "err", err)
		return writeRetry
	}
	return writeDone
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
	{"ErrMandateRefMissing", gate.ErrMandateRefMissing},
	{"ErrNonceUsed", gate.ErrNonceUsed},
	{"ErrNotYetValid", commitment.ErrNotYetValid},
	{"ErrPayloadHashMismatch", commitment.ErrPayloadHashMismatch},
	{"ErrPayloadSizeMismatch", commitment.ErrPayloadSizeMismatch},
	{"ErrPayloadUnavailable", gate.ErrPayloadUnavailable},
	{"ErrRetentionUnavailable", gate.ErrRetentionUnavailable},
	{"ErrAnchorIntentInvalid", gate.ErrAnchorIntentInvalid},
	{"ErrCertInvalid", gate.ErrCertInvalid},
	{"ErrH0TooOld", gate.ErrH0TooOld},
	{"ErrAnchorWindowClosed", gate.ErrAnchorWindowClosed},
}

// operational errors say nothing about the decision, so they leave no marker.
var operational = []error{
	gate.ErrChainUnavailable, gate.ErrArchiveUnavailable, gate.ErrRegistryUnavailable,
	gate.ErrAllowlistUnavailable, gate.ErrClockRegression, gate.ErrClosed,
	gate.ErrAnchorIntentUnavailable, gate.ErrAnchorIntentRejected,
	context.Canceled, context.DeadlineExceeded,
}

// markerName is the verdict name a refusal is recorded under, if it is one.
func markerName(err error) (string, bool) {
	for _, o := range operational {
		if errors.Is(err, o) {
			return "", false
		}
	}
	if name := policy.ReasonOf(err); name != "" {
		return name, true
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
		FastWindow:         k.FastWindow,
	}
}
