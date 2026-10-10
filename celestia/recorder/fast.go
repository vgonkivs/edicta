package recorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	// ErrIntentStale means the anchor tx of an intent was signed for an
	// account sequence the chain has passed, so it can never land. The intent
	// stays archived and is never re-signed: the anchor tx is bound by its
	// exact bytes. This blob is not published again by this Recorder.
	ErrIntentStale = errors.New("recorder: anchor tx signed for a stale account sequence; publish a new blob")
	// ErrAnchorTxRejected means the node refused the anchor tx, or the chain
	// executed it with a nonzero code. It is sticky per blob.
	ErrAnchorTxRejected = errors.New("recorder: the node refused the anchor tx")
	// ErrAnchorExpired means the anchor of a pending reference did not land
	// before the chain stopped accepting it. It is sticky per blob.
	ErrAnchorExpired = errors.New("recorder: the anchor did not land in its window")
)

const (
	accountPrefix = "celestia"
	// intentProbeBack and intentProbeAhead bound where a restart looks for
	// the intent of a payload record written by an earlier process: the
	// promise height of a Fibre upload is the uploader's head, read right
	// after the record's head from the same node.
	intentProbeBack  = 8
	intentProbeAhead = 64
	// broadcastAttempts covers the node refusing a promise whose height it
	// has as head before the app committed that block.
	broadcastAttempts = 4
	defaultRetryWait  = 500 * time.Millisecond
	// scanPerTick bounds the heights one confirmation tick reads when the
	// anchor tx hash is not known.
	scanPerTick = 64
	// rebroadcastPolls is how many poll intervals the confirmation loop waits
	// after the last send of an anchor tx it cannot find before sending the
	// archived bytes again: a node drops txs from its mempool on restart,
	// eviction or a full pool, and nobody else sends them again.
	rebroadcastPolls = 30
)

// AnchorNode is the operator's own consensus node the fast path signs for
// and broadcasts through.
type AnchorNode interface {
	Account(ctx context.Context, address string) (node.AccountInfo, error)
	MinGasPrice(ctx context.Context) (*big.Rat, error)
	Broadcast(ctx context.Context, txRaw []byte) ([32]byte, error)
	Tx(ctx context.Context, hash [32]byte) (node.TxStatus, error)
}

// FastDeps switch a Recorder to pending references: Publish returns once the
// payload and the anchor intent are archived and the anchor tx is accepted by
// the node, and a background loop writes the evidence when the anchor lands.
type FastDeps struct {
	// Signer signs the anchor txs; for da = 2 it is the blob signer.
	Signer node.AnchorSigner
	Node   AnchorNode
	// Uploader is required for da = 1 and must sign promises with the key of
	// Signer, the escrow owner.
	Uploader node.FibreUploader
	Log      *slog.Logger
}

func (d FastDeps) check(da commitment.DA) error {
	if d.Signer == nil || d.Node == nil {
		return fmt.Errorf("%w: fast mode needs an anchor signer and a node", errInvalidInput)
	}
	if da == commitment.DAFibre && d.Uploader == nil {
		return fmt.Errorf("%w: fast mode for da = 1 needs an uploader", errInvalidInput)
	}
	return nil
}

// intentDraft is a new or archived intent with what the core needs to sign,
// send and follow it.
type intentDraft struct {
	rec *archive.AnchorIntentRecord
	// sign signs the anchor tx at p and checks it; nil for an archived intent.
	sign func(ctx context.Context, p node.TxParams) ([]byte, error)
	// timeout is the tx timeout_height a new signature carries.
	timeout uint64
	// landBy is the last height the anchor can land at.
	landBy uint64
	// expiry, when set, is the time after which the anchor cannot land.
	expiry   time.Time
	refTime  uint64
	retStart uint64
	// release ends the escrow reservation of the upload.
	release func()
	// settleWait is how long after the expiry the reservation is kept: an
	// expired Fibre promise can still be charged by a timeout settlement.
	settleWait time.Duration
}

// fastDA is the da-specific side of the fast path.
type fastDA interface {
	backend
	// draft prepares a new intent at the head; for da = 1 it uploads.
	draft(ctx context.Context, comm, blob []byte, head uint64, headTime time.Time) (*intentDraft, error)
	// restore rebuilds the draft of an archived intent.
	restore(ctx context.Context, comm, blob []byte, rec *archive.AnchorIntentRecord) (*intentDraft, error)
	// wire is what goes to the node for an anchor tx.
	wire(tx, blob []byte) ([]byte, error)
}

type fastEntry struct {
	inflight bool
	// ours is set once this process wrote or found the payload record in
	// this call chain; a record of an earlier process needs its intent found.
	ours  bool
	draft *intentDraft
	// hash is the hash of the archived anchor tx, the only one ever sent.
	hash [32]byte
	// seq is the account sequence the archived anchor tx is signed for.
	seq uint64
	// sentAt is when the archived anchor tx was last sent.
	sentAt  time.Time
	scan    bool
	scanned uint64
	pending *sdk.Published
	done    *sdk.Published
	sticky  error
	looping bool
	d       fastDA
	blob    []byte
}

// fastCore holds the per-blob state and the account sequence of one
// Recorder's fast path.
type fastCore struct {
	eng       *engine
	intents   archive.IntentReader
	d         FastDeps
	poll      time.Duration
	retryWait time.Duration

	seqMu sync.Mutex
	// floor is the sequence a node refusal proved the account has reached,
	// while the committed sequence may still lag behind it.
	floor uint64
	bech  string

	mu      sync.Mutex
	entries map[pendingKey]*fastEntry
	ctx     context.Context
	cancel  context.CancelFunc
	loops   sync.WaitGroup
}

func newFastCore(eng *engine, d FastDeps, poll time.Duration) (*fastCore, error) {
	ir, ok := eng.archive.(archive.IntentReader)
	if eng.archive == nil || !ok {
		return nil, fmt.Errorf("%w: fast mode needs an archive that reads anchor intents", errInvalidInput)
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &fastCore{
		eng: eng, intents: ir, d: d, poll: poll, retryWait: min(defaultRetryWait, poll),
		entries: map[pendingKey]*fastEntry{}, ctx: ctx, cancel: cancel,
	}, nil
}

// close stops the confirmation loops and waits for them until ctx ends.
func (f *fastCore) close(ctx context.Context) error {
	f.cancel()
	done := make(chan struct{})
	go func() { f.loops.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fastCore) claim(key pendingKey) (*fastEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ctx.Err() != nil {
		return nil, errClosed
	}
	e, ok := f.entries[key]
	if !ok {
		if len(f.entries) >= defaultMaxPending {
			f.prune()
		}
		if len(f.entries) >= defaultMaxPending {
			return nil, fmt.Errorf("%w: %d", ErrTooManyPending, len(f.entries))
		}
		e = &fastEntry{}
		f.entries[key] = e
	}
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

// prune drops settled entries. A dropped blob published again is found
// through its archived payload record and intent.
func (f *fastCore) prune() {
	for k, e := range f.entries {
		if (e.done != nil || e.sticky != nil || e.draft == nil) && !e.inflight && !e.looping {
			delete(f.entries, k)
		}
	}
}

func (f *fastCore) unclaim(e *fastEntry) {
	f.mu.Lock()
	e.inflight = false
	f.mu.Unlock()
}

func (f *fastCore) stick(e *fastEntry, err error) error {
	f.mu.Lock()
	if e.sticky == nil && e.done == nil {
		e.sticky = err
	}
	f.mu.Unlock()
	return err
}

// publish returns the pending reference of blob, or the included one when
// its evidence is archived.
func (f *fastCore) publish(ctx context.Context, d fastDA, comm, blob []byte) (sdk.Published, error) {
	e, err := f.claim(pendingKey(comm))
	if err != nil {
		return sdk.Published{}, err
	}
	if e.done != nil {
		return clonePublished(*e.done), nil
	}
	defer f.unclaim(e)

	head, headTime, err := d.head(ctx)
	if err != nil {
		return sdk.Published{}, err
	}
	if e.draft == nil {
		pub, answered, sent, err := f.prepare(ctx, d, e, comm, blob, head, headTime)
		if err != nil || answered {
			return pub, err
		}
		if sent {
			return f.pendingOf(e), nil
		}
	}
	return f.resume(ctx, d, e, comm, blob, head)
}

func (f *fastCore) pendingOf(e *fastEntry) sdk.Published {
	f.mu.Lock()
	defer f.mu.Unlock()
	return clonePublished(*e.pending)
}

// prepare archives the payload and either finds the intent of an earlier
// process or makes, archives and sends a new one. answered is set when the
// call is answered from evidence, sent when a new intent went out.
func (f *fastCore) prepare(ctx context.Context, d fastDA, e *fastEntry, comm, blob []byte, head uint64, headTime time.Time) (pub sdk.Published, answered, sent bool, err error) {
	intentHeight, existed, err := f.eng.archivePayload(ctx, d, comm, blob, head)
	if err != nil {
		return sdk.Published{}, false, false, err
	}
	ev, err := f.eng.archive.Evidence(ctx, d.da(), comm)
	switch {
	case err == nil:
		pub, err := d.fromEvidence(ctx, comm, blob, ev)
		if err != nil {
			return sdk.Published{}, false, false, err
		}
		f.finish(e, pub)
		return clonePublished(pub), true, false, nil
	case !errors.Is(err, archive.ErrNotFound):
		return sdk.Published{}, false, false, archiveFault("read evidence record", err)
	}
	if existed && !e.ours {
		rec, err := f.findIntent(ctx, d.da(), comm, intentHeight)
		if err != nil {
			return sdk.Published{}, false, false, err
		}
		if rec == nil {
			// A crash between the upload and the intent write leaves no
			// intent and no returned reference for the promise: refusing the
			// blob costs at most that one blob, never a dangling reference.
			return sdk.Published{}, false, false, f.stick(e, fmt.Errorf("%w: an earlier process archived this blob without an intent in reach; publish a new blob", ErrOutcomeUnknown))
		}
		dr, err := d.restore(ctx, comm, blob, rec)
		if err != nil {
			return sdk.Published{}, false, false, err
		}
		if err := f.adopt(d, e, dr, blob); err != nil {
			return sdk.Published{}, false, false, err
		}
		return sdk.Published{}, false, false, nil
	}
	e.ours = true
	dr, err := d.draft(ctx, comm, blob, head, headTime)
	if err != nil {
		return sdk.Published{}, false, false, err
	}
	sent, err = f.send(ctx, d, e, dr, blob)
	return sdk.Published{}, false, sent, err
}

// findIntent looks for an archived intent of comm near the payload record's
// height; nil means none in reach.
func (f *fastCore) findIntent(ctx context.Context, da commitment.DA, comm []byte, around uint64) (*archive.AnchorIntentRecord, error) {
	lo := around - min(around-1, intentProbeBack)
	for h := lo; h <= around+intentProbeAhead; h++ {
		rec, err := f.intents.Intent(ctx, da, comm, h)
		switch {
		case err == nil:
			return rec, nil
		case !errors.Is(err, archive.ErrNotFound):
			return nil, archiveFault("read anchor intent", err)
		}
	}
	return nil, nil
}

func (f *fastCore) adopt(d fastDA, e *fastEntry, dr *intentDraft, blob []byte) error {
	seq, err := node.TxSequence(dr.rec.Tx)
	if err != nil {
		return archiveFault("anchor intent", err)
	}
	ref := commitment.PayloadRef{
		DA: d.da(), Namespace: bytes.Clone(dr.rec.Namespace), Commitment: bytes.Clone(dr.rec.Commitment),
		Height: dr.rec.RefHeight, Signer: bytes.Clone(dr.rec.Signer), Anchor: commitment.AnchorPending,
	}
	f.mu.Lock()
	e.ours = true
	e.draft = dr
	e.d = d
	e.blob = blob
	e.scanned = dr.rec.RefHeight - 1
	e.hash = sha256.Sum256(dr.rec.Tx)
	e.seq = seq
	e.sentAt = time.Now()
	e.pending = &sdk.Published{Ref: ref, BlockTime: dr.refTime, RetentionStart: dr.retStart}
	f.mu.Unlock()
	// Every archived intent is followed to its end, whatever its first
	// broadcast answered: it may land, or need sending again.
	f.loop(d, e, dr.rec.Commitment)
	return nil
}

func (f *fastCore) sent(e *fastEntry) {
	f.mu.Lock()
	e.sentAt = time.Now()
	f.mu.Unlock()
}

// live reports whether e follows an intent whose anchor tx may still take
// its sequence: neither landed, nor refused, stale or expired.
func live(e *fastEntry) bool {
	return e.draft != nil && e.done == nil && e.sticky == nil && !e.scan
}

// highestLive is the highest sequence a live intent is signed for.
func (f *fastCore) highestLive() (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var hi uint64
	found := false
	for _, e := range f.entries {
		if live(e) && (!found || e.seq > hi) {
			hi, found = e.seq, true
		}
	}
	return hi, found
}

// kick sends the live intent signed for seq again: the node reported that
// sequence missing, and every later intent of this account waits for it.
func (f *fastCore) kick(ctx context.Context, seq uint64) {
	f.mu.Lock()
	var k *fastEntry
	for _, e := range f.entries {
		if live(e) && e.seq == seq {
			k = e
			break
		}
	}
	var d fastDA
	var tx, blob []byte
	if k != nil {
		d, tx, blob = k.d, k.draft.rec.Tx, k.blob
	}
	f.mu.Unlock()
	if k == nil || d == nil {
		return
	}
	raw, err := d.wire(tx, blob)
	if err != nil {
		return
	}
	if _, err := f.d.Node.Broadcast(ctx, raw); err != nil && !errors.Is(err, node.ErrAlreadyInMempool) {
		f.d.Log.Warn("recorder: resending the anchor tx of a missing sequence failed", "sequence", seq, "err", err)
	}
}

// send signs the new intent at the account's next sequence, archives it and
// broadcasts it, all under the sequence lock so that intents leave in
// sequence order.
func (f *fastCore) send(ctx context.Context, d fastDA, e *fastEntry, dr *intentDraft, blob []byte) (bool, error) {
	f.seqMu.Lock()
	defer f.seqMu.Unlock()
	p, err := f.params(ctx, dr.timeout)
	if err != nil {
		dr.release()
		return false, err
	}
	tx, err := dr.sign(ctx, p)
	if err != nil {
		dr.release()
		if errors.Is(err, ErrSubmitMismatch) {
			return false, f.stick(e, err)
		}
		return false, err
	}
	dr.rec.Tx = tx
	switch _, err := f.eng.archive.Put(ctx, dr.rec); {
	case err == nil:
	case errors.Is(err, archive.ErrConflict):
		// Another intent of this process holds the key: follow that one.
		stored, rerr := f.intents.Intent(ctx, d.da(), dr.rec.Commitment, dr.rec.RefHeight)
		if rerr != nil {
			dr.release()
			return false, archiveFault("read anchor intent", rerr)
		}
		dr.rec = stored
		return false, f.adopt(d, e, dr, blob)
	default:
		dr.release()
		return false, archiveFault("write anchor intent", err)
	}
	if err := f.adopt(d, e, dr, blob); err != nil {
		return false, err
	}
	f.floor = 0

	raw, err := d.wire(tx, blob)
	if err != nil {
		return false, err
	}
	err = f.broadcast(ctx, raw)
	f.sent(e)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, node.ErrSequenceMismatch):
		n, ok := node.ExpectedSequence(err)
		if !ok || n <= p.Sequence {
			// An earlier tx of this account is missing from the mempool: once
			// that gap fills this tx is valid, and a retry resumes it.
			if ok && n < p.Sequence {
				f.kick(ctx, n)
			}
			return false, fmt.Errorf("%w: the node expects another sequence than %d: %w", ErrOutcomeUnknown, p.Sequence, err)
		}
		f.floor = max(f.floor, n)
		time.AfterFunc(dr.settleWait, dr.release)
		return false, f.stick(e, fmt.Errorf("%w: %w", ErrIntentStale, err))
	case errors.Is(err, errProcessed):
		f.markScan(e)
		return true, nil
	case errors.Is(err, node.ErrRejected):
		dr.release()
		return false, f.stick(e, fmt.Errorf("%w: %w", ErrAnchorTxRejected, err))
	}
	// Whether the node kept the tx is unknown: the intent stays live and holds
	// its sequence.
	return false, fmt.Errorf("%w: broadcast: %w", ErrOutcomeUnknown, err)
}

func (f *fastCore) markScan(e *fastEntry) {
	f.mu.Lock()
	e.scan = true
	f.mu.Unlock()
}

// params returns the signing state for the next tx. The committed sequence
// lags while intents of this account wait in the mempool, so the next one
// never goes below the sequence after the highest live intent: taking a live
// intent's sequence would make one of the two fail, and that intent's
// reference may already be authorized.
func (f *fastCore) params(ctx context.Context, timeout uint64) (node.TxParams, error) {
	if f.bech == "" {
		addr, err := f.d.Signer.Address(ctx)
		if err != nil {
			return node.TxParams{}, fmt.Errorf("recorder: signer: %w", err)
		}
		if f.bech, err = bech32.ConvertAndEncode(accountPrefix, addr); err != nil {
			return node.TxParams{}, fmt.Errorf("%w: signer address: %w", errInvalidInput, err)
		}
	}
	acc, err := f.d.Node.Account(ctx, f.bech)
	if err != nil {
		return node.TxParams{}, fmt.Errorf("%w: account: %w", ErrNodeUnavailable, err)
	}
	next := max(acc.Sequence, f.floor)
	if hi, ok := f.highestLive(); ok {
		next = max(next, hi+1)
	}
	price, err := f.d.Node.MinGasPrice(ctx)
	if err != nil {
		return node.TxParams{}, fmt.Errorf("%w: gas price: %w", ErrNodeUnavailable, err)
	}
	return node.TxParams{AccountNumber: acc.Number, Sequence: next, GasPrice: price, TimeoutHeight: timeout}, nil
}

// errProcessed marks a Fibre promise the chain has already settled: some tx
// carrying it landed, under a hash this Recorder may not know.
var errProcessed = errors.New("recorder: promise already processed")

// broadcast sends raw, retrying the transient refusal of a promise at a fresh
// height.
func (f *fastCore) broadcast(ctx context.Context, raw []byte) error {
	var err error
	for i := 0; i < broadcastAttempts; i++ {
		if i > 0 {
			t := time.NewTimer(f.retryWait)
			select {
			case <-ctx.Done():
				t.Stop()
				return fmt.Errorf("%w: %w", ErrNodeUnavailable, ctx.Err())
			case <-t.C:
			}
		}
		_, err = f.d.Node.Broadcast(ctx, raw)
		switch {
		case err == nil, errors.Is(err, node.ErrAlreadyInMempool):
			return nil
		case errors.Is(err, node.ErrRejected) && strings.Contains(err.Error(), "historical validator set"):
			continue
		case errors.Is(err, node.ErrRejected) && strings.Contains(err.Error(), "already been processed"):
			return fmt.Errorf("%w: %w", errProcessed, err)
		}
		return err
	}
	return err
}

// resume answers from an intent this entry follows: it looks the anchor up
// and sends the archived tx again when the node does not know it.
func (f *fastCore) resume(ctx context.Context, d fastDA, e *fastEntry, comm, blob []byte, head uint64) (sdk.Published, error) {
	f.mu.Lock()
	dr, hash, scan := e.draft, e.hash, e.scan
	f.mu.Unlock()
	st, err := f.lookup(ctx, hash)
	if err != nil {
		return sdk.Published{}, err
	}
	if st.Found {
		return f.landed(ctx, d, e, comm, blob, st)
	}
	if !scan {
		if f.expired(dr, head) {
			time.AfterFunc(dr.settleWait, dr.release)
			return sdk.Published{}, f.stick(e, ErrAnchorExpired)
		}
		st, err := f.resend(ctx, d, e, dr, blob)
		if err != nil {
			return sdk.Published{}, err
		}
		if st.Found {
			return f.landed(ctx, d, e, comm, blob, st)
		}
	}
	return f.pendingOf(e), nil
}

func (f *fastCore) lookup(ctx context.Context, hash [32]byte) (node.TxStatus, error) {
	st, err := f.d.Node.Tx(ctx, hash)
	if err != nil {
		return node.TxStatus{}, fmt.Errorf("%w: tx lookup: %w", ErrNodeUnavailable, err)
	}
	return st, nil
}

func (f *fastCore) expired(dr *intentDraft, head uint64) bool {
	return head > dr.landBy || !dr.expiry.IsZero() && !f.eng.now().Before(dr.expiry)
}

// landed answers from an anchor tx the node reports as committed.
func (f *fastCore) landed(ctx context.Context, d fastDA, e *fastEntry, comm, blob []byte, st node.TxStatus) (sdk.Published, error) {
	if st.Code != 0 {
		e.draft.release()
		return sdk.Published{}, f.stick(e, fmt.Errorf("%w: executed with code %d at height %d", ErrAnchorTxRejected, st.Code, st.Height))
	}
	pub, err := d.confirm(ctx, comm, blob, st.Height, true)
	if err != nil {
		if errors.Is(err, ErrAnchorRejected) || errors.Is(err, ErrSignerMismatch) {
			e.draft.release()
			return sdk.Published{}, f.stick(e, err)
		}
		return sdk.Published{}, err
	}
	e.draft.release()
	f.finish(e, pub)
	return clonePublished(pub), nil
}

func (f *fastCore) finish(e *fastEntry, pub sdk.Published) {
	f.mu.Lock()
	c := clonePublished(pub)
	e.done = &c
	f.mu.Unlock()
}

// resend broadcasts the archived tx again. It never signs the anchor anew:
// the intent is bound by its exact tx bytes, and the gate looks it up and
// rebroadcasts it by their hash. A found status means the archived tx landed
// while it was being sent.
func (f *fastCore) resend(ctx context.Context, d fastDA, e *fastEntry, dr *intentDraft, blob []byte) (node.TxStatus, error) {
	f.seqMu.Lock()
	defer f.seqMu.Unlock()
	raw, err := d.wire(dr.rec.Tx, blob)
	if err != nil {
		return node.TxStatus{}, err
	}
	err = f.broadcast(ctx, raw)
	f.sent(e)
	switch {
	case err == nil:
		return node.TxStatus{}, nil
	case errors.Is(err, errProcessed):
		f.markScan(e)
		return node.TxStatus{}, nil
	case errors.Is(err, node.ErrSequenceMismatch):
		return f.mismatched(ctx, e, dr, err)
	case errors.Is(err, node.ErrRejected):
		dr.release()
		return node.TxStatus{}, f.stick(e, fmt.Errorf("%w: %w", ErrAnchorTxRejected, err))
	}
	return node.TxStatus{}, fmt.Errorf("%w: broadcast: %w", ErrNodeUnavailable, err)
}

// mismatched handles the node refusing the archived tx for its sequence.
// The tx may have landed since it was looked up, which also moves the
// sequence past it. Otherwise only a sequence the account has already passed
// proves it can never land; a lower expected sequence means an earlier tx of
// this account is missing from the mempool, and once that gap fills the
// archived tx is valid again.
func (f *fastCore) mismatched(ctx context.Context, e *fastEntry, dr *intentDraft, mismatch error) (node.TxStatus, error) {
	st, err := f.lookup(ctx, sha256.Sum256(dr.rec.Tx))
	if err != nil {
		return node.TxStatus{}, err
	}
	if st.Found {
		return st, nil
	}
	signed, err := node.TxSequence(dr.rec.Tx)
	if err != nil {
		return node.TxStatus{}, archiveFault("anchor intent", err)
	}
	expected, ok := node.ExpectedSequence(mismatch)
	if !ok || expected <= signed {
		if ok && expected < signed {
			f.kick(ctx, expected)
		}
		return node.TxStatus{}, fmt.Errorf("%w: the node expects another sequence than the archived tx's %d: %w", ErrNodeUnavailable, signed, mismatch)
	}
	f.floor = max(f.floor, expected)
	// A Fibre promise that will never be paid can still be charged by its
	// timeout settlement, so the escrow stays reserved until then.
	time.AfterFunc(dr.settleWait, dr.release)
	return node.TxStatus{}, f.stick(e, fmt.Errorf("%w: the archived anchor tx at sequence %d can never land; the pending reference is dead and its deadline will prove the anchor absent: %w",
		ErrIntentStale, signed, mismatch))
}

// loop starts the confirmation loop of e once.
func (f *fastCore) loop(d fastDA, e *fastEntry, comm []byte) {
	f.mu.Lock()
	if e.looping || e.done != nil || f.ctx.Err() != nil {
		f.mu.Unlock()
		return
	}
	e.looping = true
	f.loops.Add(1)
	f.mu.Unlock()
	go func() {
		defer f.loops.Done()
		defer func() {
			f.mu.Lock()
			e.looping = false
			f.mu.Unlock()
		}()
		t := time.NewTicker(f.poll)
		defer t.Stop()
		for {
			select {
			case <-f.ctx.Done():
				return
			case <-t.C:
			}
			if f.tick(d, e, comm) {
				return
			}
		}
	}()
}

// tick is one confirmation step; it reports whether the loop is over.
func (f *fastCore) tick(d fastDA, e *fastEntry, comm []byte) bool {
	ctx := f.ctx
	f.mu.Lock()
	if e.done != nil || e.sticky != nil {
		f.mu.Unlock()
		return true
	}
	if e.inflight {
		// A Publish of the same blob does the lookup itself.
		f.mu.Unlock()
		return false
	}
	dr, hash, scan, blob, sentAt := e.draft, e.hash, e.scan, e.blob, e.sentAt
	f.mu.Unlock()

	st, err := f.d.Node.Tx(ctx, hash)
	if err != nil {
		f.d.Log.Warn("recorder: anchor tx lookup failed", "err", err)
		return false
	}
	if st.Found {
		return f.settle(ctx, d, e, comm, blob, st)
	}
	head, _, err := d.head(ctx)
	if err != nil {
		f.d.Log.Warn("recorder: head read failed in the confirmation loop", "err", err)
		return false
	}
	if scan {
		if h, ok := f.scanStep(ctx, d, e, comm, min(head, dr.landBy)); ok {
			return f.settle(ctx, d, e, comm, blob, node.TxStatus{Found: true, Height: h})
		}
	}
	if f.expired(dr, head) {
		time.AfterFunc(dr.settleWait, dr.release)
		_ = f.stick(e, ErrAnchorExpired)
		f.d.Log.Error("recorder: the anchor of a pending reference did not land in its window", "da", d.da(),
			"ref_height", dr.rec.RefHeight, "land_by", dr.landBy)
		return true
	}
	if scan || time.Since(sentAt) < rebroadcastPolls*f.poll {
		return false
	}
	st, err = f.resend(ctx, d, e, dr, blob)
	switch {
	case err != nil:
		f.mu.Lock()
		over := e.sticky != nil
		f.mu.Unlock()
		if over {
			f.d.Log.Error("recorder: the anchor tx of a pending reference was refused when sent again", "da", d.da(),
				"ref_height", dr.rec.RefHeight, "err", err)
			return true
		}
		f.d.Log.Warn("recorder: sending the anchor tx again failed", "err", err)
	case st.Found:
		return f.settle(ctx, d, e, comm, blob, st)
	}
	return false
}

func (f *fastCore) settle(ctx context.Context, d fastDA, e *fastEntry, comm, blob []byte, st node.TxStatus) bool {
	_, err := f.landed(ctx, d, e, comm, blob, st)
	if err == nil {
		return true
	}
	f.mu.Lock()
	over := e.sticky != nil
	f.mu.Unlock()
	if over {
		f.d.Log.Error("recorder: the anchor of a pending reference landed but cannot be confirmed", "da", d.da(), "height", st.Height, "err", err)
	} else {
		f.d.Log.Warn("recorder: anchor evidence not written yet", "da", d.da(), "height", st.Height, "err", err)
	}
	return over
}

// scanStep searches the heights after e.scanned up to limit for an anchor
// whose tx hash is not known.
func (f *fastCore) scanStep(ctx context.Context, d fastDA, e *fastEntry, comm []byte, limit uint64) (uint64, bool) {
	f.mu.Lock()
	lo := e.scanned + 1
	f.mu.Unlock()
	hi := min(limit, lo+scanPerTick-1)
	for h := lo; h <= hi && h >= lo; h++ {
		ok, err := d.present(ctx, comm, h)
		if err != nil {
			return 0, false
		}
		if ok {
			return h, true
		}
		f.mu.Lock()
		e.scanned = h
		f.mu.Unlock()
	}
	return 0, false
}
