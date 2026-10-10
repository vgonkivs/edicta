package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// AnchorIntent is the archived anchor intent of a pending reference: the
// signed anchor tx, without the blob. Signer is set for da = 2 only.
// CreatedAt is floor(promise creation) for da = 1.
type AnchorIntent struct {
	DA         commitment.DA
	Commitment []byte
	Namespace  []byte
	RefHeight  uint64
	Tx         []byte
	Signer     []byte
	CreatedAt  uint64
}

// IntentFacts is what an intent verifier established from the record and
// the chain. The Fibre-only fields are zero for da = 2 and TimeoutHeight is
// zero for da = 1.
type IntentFacts struct {
	DA             commitment.DA
	RefTime        uint64 // header time at h0, whole seconds
	Head           uint64 // the head h, read with the h0 header
	HeadTime       uint64 // header time at h
	CreatedAt      uint64 // floor(promise creation)
	PromiseTimeout uint64 // payment_promise_timeout at h, seconds
	ChainWindow    uint64 // payment_promise_height_window at h
	TimeoutHeight  uint64 // the PFB's timeout_height, 0 for none
	CertSigned     int64
	CertTotal      int64
}

// IntentVerifier checks one da's intent against the reference and the
// chain: the tx and its binding (ErrAnchorIntentInvalid), the headers at h0
// and at the head (ErrChainUnavailable) and, for da = 1, the availability
// certificate (ErrCertInvalid).
type IntentVerifier interface {
	VerifyIntent(ctx context.Context, ref commitment.PayloadRef, rec *AnchorIntent, payloadSize uint64) (IntentFacts, error)
}

// TxStatus is the gate node's answer for the intent tx.
type TxStatus struct {
	Included bool
	Height   uint64
	Code     uint32
}

// IntentBroadcaster looks the intent tx up on the gate's own node and
// broadcasts it. Broadcast treats "already known" as success and wraps a
// refusal of the node in ErrAnchorIntentRejected.
type IntentBroadcaster interface {
	Lookup(ctx context.Context, rec *AnchorIntent) (TxStatus, error)
	// Broadcast sends the tx; for da = 2 together with blob as the v1 blob of
	// the record's namespace and signer.
	Broadcast(ctx context.Context, da commitment.DA, rec *AnchorIntent, blob []byte) error
}

// IntentSource reads the anchor intent of (da, commitment, ref_height). The
// gate answers any failure, an absent record included, with the retryable
// ErrAnchorIntentUnavailable.
type IntentSource interface {
	Intent(ctx context.Context, da commitment.DA, commit []byte, refHeight uint64) (*AnchorIntent, error)
}

// Deadline computes the anchor deadline of a pending reference from the
// head, the facts, the gate configuration and the mandate's bound, all in
// blocks. A slack failure, and for da = 1 a promise about to expire, comes
// back as ErrAnchorWindowClosed with provisional set: an anchor already
// included in the window waives it.
func Deadline(h0, head uint64, f IntentFacts, cfg Config, mandateDelay uint64) (deadline uint64, provisional bool, err error) {
	// The verifier refuses such a PFB too; checked here as well because a
	// deadline at or below h0 would authorize an anchor window of zero blocks.
	if f.DA == commitment.DACelestiaBlob && f.TimeoutHeight > 0 && f.TimeoutHeight <= h0 {
		return 0, false, fmt.Errorf("%w: timeout_height %d is not above the reference height %d", ErrAnchorIntentInvalid, f.TimeoutHeight, h0)
	}
	if head < h0 {
		return 0, false, fmt.Errorf("%w: head %d below the reference height %d", ErrChainUnavailable, head, h0)
	}
	if head-h0 > cfg.MaxH0AgeBlocks {
		return 0, false, fmt.Errorf("%w: head %d is %d blocks past h0 %d, limit %d", ErrH0TooOld, head, head-h0, h0, cfg.MaxH0AgeBlocks)
	}
	window := min(cfg.FastWindowBlocks, mandateDelay)
	if f.DA == commitment.DAFibre {
		window = min(window, f.ChainWindow)
	}
	if window < 1 {
		return 0, false, fmt.Errorf("%w: window is zero", ErrAnchorWindowClosed)
	}
	deadline = satAdd(h0, window)
	if f.DA == commitment.DACelestiaBlob && f.TimeoutHeight > 0 && f.TimeoutHeight < deadline {
		deadline = f.TimeoutHeight
	}
	if deadline <= h0 {
		return 0, false, fmt.Errorf("%w: deadline %d is not above the reference height %d", ErrAnchorWindowClosed, deadline, h0)
	}
	if deadline < satAdd(head, cfg.MinFastSlackBlocks) {
		return deadline, true, fmt.Errorf("%w: deadline %d, head %d, slack %d", ErrAnchorWindowClosed, deadline, head, cfg.MinFastSlackBlocks)
	}
	if f.DA == commitment.DAFibre && satAdd(f.HeadTime, cfg.MinPromiseSlackSeconds) >= satAdd(f.CreatedAt, f.PromiseTimeout) {
		return deadline, true, fmt.Errorf("%w: promise created at %d expires after %d s, head time %d, slack %d s",
			ErrAnchorWindowClosed, f.CreatedAt, f.PromiseTimeout, f.HeadTime, cfg.MinPromiseSlackSeconds)
	}
	return deadline, false, nil
}

// checkFastDeps requires what stage K-fast reads: the intent source, the
// broadcaster and an intent verifier for every allowed da.
func checkFastDeps(cfg Config, d Deps) error {
	if d.Intents == nil || isNilDep(d.Intents) {
		return fmt.Errorf("%w: fast mode needs an intent source", ErrInvalidConfig)
	}
	if d.Broadcaster == nil || isNilDep(d.Broadcaster) {
		return fmt.Errorf("%w: fast mode needs an intent broadcaster", ErrInvalidConfig)
	}
	for _, da := range cfg.AllowedDA {
		if v := d.IntentVerifiers[da]; v == nil || isNilDep(v) {
			return fmt.Errorf("%w: fast mode needs an intent verifier for da %d", ErrInvalidConfig, da)
		}
	}
	return nil
}

// checkPending admits a pending reference only at a fast-mode gate with a
// mandate, and only for a namespace the operator listed: the gate looks up
// and rebroadcasts for these namespaces only.
func (g *Gate) checkPending(ref commitment.PayloadRef) error {
	if !ref.Pending() {
		return nil
	}
	if !g.cfg.FastMode || g.pol == nil {
		return ErrAnchorPending
	}
	for _, ns := range g.cfg.PendingNamespaces {
		if bytes.Equal(ns, ref.Namespace) {
			return nil
		}
	}
	return fmt.Errorf("%w: %x", ErrNamespaceNotAllowed, ref.Namespace)
}

// fastOutcome is what stage K-fast hands to the later stages.
type fastOutcome struct {
	refTime   uint64
	createdAt uint64
	deadline  uint64
	// payloadErr is a size or hash mismatch of the archived blob, found
	// while preparing the broadcast. It belongs to the payload stage, so the
	// caller reports it only after the anchor time and retention checks.
	payloadErr error
}

func (g *Gate) rebroadcast() bool { return g.cfg.RebroadcastIntent == nil || *g.cfg.RebroadcastIntent }

// kFast runs stage K-fast for a pending reference. It writes nothing; the
// broadcast it may make never creates an Authorization.
func (g *Gate) kFast(ctx context.Context, c *commitment.Commitment) (fastOutcome, error) {
	ref := c.PayloadRef
	h0 := ref.Height
	rec, err := g.readIntent(ctx, ref)
	if err != nil {
		return fastOutcome{}, err
	}
	switch {
	case rec.DA != ref.DA || !bytes.Equal(rec.Commitment, ref.Commitment) || rec.RefHeight != h0:
		return fastOutcome{}, fmt.Errorf("%w: the record is for another reference", ErrAnchorIntentUnavailable)
	case !bytes.Equal(rec.Namespace, ref.Namespace):
		return fastOutcome{}, fmt.Errorf("%w: namespace differs from the reference", ErrAnchorIntentInvalid)
	case ref.DA == commitment.DACelestiaBlob && !bytes.Equal(rec.Signer, ref.Signer):
		return fastOutcome{}, fmt.Errorf("%w: signer differs from the reference", ErrAnchorIntentInvalid)
	}

	v := g.d.IntentVerifiers[ref.DA]
	if v == nil {
		return fastOutcome{}, fmt.Errorf("%w: no intent verifier for da %d", ErrAnchorPending, ref.DA)
	}
	vctx, cancel := g.chainCtx(ctx)
	f, err := v.VerifyIntent(vctx, ref, rec, c.PayloadSize)
	cancel()
	if err != nil {
		return fastOutcome{}, g.intentErr(ctx, err)
	}
	// A head time of 0 would let any promise pass the promise slack check.
	if f.DA != ref.DA || f.RefTime == 0 || (ref.DA == commitment.DAFibre && f.HeadTime == 0) {
		return fastOutcome{}, fmt.Errorf("%w: intent verifier reported da %d, reference time %d, head time %d", ErrChainUnavailable, f.DA, f.RefTime, f.HeadTime)
	}
	if ref.DA == commitment.DAFibre && f.CreatedAt != rec.CreatedAt {
		return fastOutcome{}, fmt.Errorf("%w: created_at %d, promise creation %d", ErrAnchorIntentInvalid, rec.CreatedAt, f.CreatedAt)
	}

	deadline, provisional, err := Deadline(h0, f.Head, f, g.cfg, g.pol.mandate.FastModeMaxDelay)
	if err != nil && !provisional {
		return fastOutcome{}, err
	}
	out := fastOutcome{refTime: f.RefTime, deadline: deadline}
	if ref.DA == commitment.DAFibre {
		out.createdAt = rec.CreatedAt
	}
	broadcast := ref.DA == commitment.DACelestiaBlob || g.rebroadcast()
	if !broadcast && !provisional {
		return out, nil
	}

	lctx, cancel := g.chainCtx(ctx)
	st, lerr := g.d.Broadcaster.Lookup(lctx, rec)
	cancel()
	switch {
	case lerr != nil:
		return fastOutcome{}, g.chainErr(ctx, "intent lookup", lerr)
	case st.Included && st.Code == 0 && st.Height >= h0 && st.Height <= deadline:
		return out, nil
	case st.Included:
		return fastOutcome{}, fmt.Errorf("%w: anchor included at %d with code %d, window [%d, %d]", ErrAnchorWindowClosed, st.Height, st.Code, h0, deadline)
	case provisional:
		return fastOutcome{}, err
	}

	var blob []byte
	if ref.DA == commitment.DACelestiaBlob {
		var payloadErr error
		if blob, payloadErr, err = g.intentBlob(ctx, c); err != nil {
			return fastOutcome{}, err
		}
		if payloadErr != nil {
			out.payloadErr = payloadErr
			return out, nil
		}
	}
	bctx, cancel := g.chainCtx(ctx)
	berr := g.d.Broadcaster.Broadcast(bctx, ref.DA, rec, blob)
	cancel()
	if berr != nil {
		if cerr := ctx.Err(); cerr != nil {
			return fastOutcome{}, fmt.Errorf("gate: %w", cerr)
		}
		if errors.Is(berr, ErrAnchorIntentRejected) || errors.Is(berr, ErrChainUnavailable) {
			return fastOutcome{}, fmt.Errorf("broadcast: %w", berr)
		}
		return fastOutcome{}, fmt.Errorf("%w: %w", ErrAnchorIntentRejected, berr)
	}
	return out, nil
}

// includedAnchor is stage K for an included reference: the anchor at the
// reference height and the header time there.
func (g *Gate) includedAnchor(ctx context.Context, ref commitment.PayloadRef) (Anchor, uint64, error) {
	anchor, err := g.findAnchor(ctx, ref)
	if err != nil {
		return Anchor{}, 0, g.anchorErr(ctx, "anchor", err)
	}
	if anchor.Height != ref.Height {
		return Anchor{}, 0, fmt.Errorf("%w: anchor at height %d, reference at %d", ErrAnchorNotFound, anchor.Height, ref.Height)
	}
	blockTime, err := g.blockTime(ctx, ref.Height)
	if err != nil {
		return Anchor{}, 0, g.anchorErr(ctx, "header", err)
	}
	return anchor, blockTime, nil
}

// readIntent reads the intent under the archive deadline. Every failure,
// absence included, is the retryable ErrAnchorIntentUnavailable.
func (g *Gate) readIntent(ctx context.Context, ref commitment.PayloadRef) (*AnchorIntent, error) {
	actx, cancel := context.WithTimeout(ctx, g.cfg.ArchiveTimeout)
	defer cancel()
	rec, err := g.d.Intents.Intent(actx, ref.DA, ref.Commitment, ref.Height)
	if err == nil && rec == nil {
		err = errors.New("no record")
	}
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("gate: %w", cerr)
		}
		return nil, fmt.Errorf("%w: %w", ErrAnchorIntentUnavailable, err)
	}
	return rec, nil
}

// intentErr keeps the verifier's sentinel and turns anything else into an
// operational failure, so an unexpected error never reads as a verdict.
func (g *Gate) intentErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("gate: %w", cerr)
	}
	for _, s := range []error{ErrAnchorIntentInvalid, ErrCertInvalid, ErrChainUnavailable} {
		if errors.Is(err, s) {
			return fmt.Errorf("intent: %w", err)
		}
	}
	return fmt.Errorf("%w: intent: %w", ErrChainUnavailable, err)
}

// intentBlob reads the archived blob for a da = 2 broadcast under the fetch
// budget and refuses to send one that does not match the commitment. A size
// or hash mismatch comes back as payloadErr, with no blob to send.
func (g *Gate) intentBlob(ctx context.Context, c *commitment.Commitment) (blob []byte, payloadErr, err error) {
	held, err := g.sem.acquire(ctx, c.PayloadSize)
	if err != nil {
		return nil, nil, fmt.Errorf("gate: %w", err)
	}
	defer g.sem.release(held)
	actx, cancel := context.WithTimeout(ctx, g.cfg.ArchiveTimeout)
	defer cancel()
	blob, err = g.d.Archive.Fetch(actx, c.PayloadRef, c.PayloadSize)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, fmt.Errorf("gate: %w", cerr)
		}
		return nil, nil, fmt.Errorf("%w: archived blob for the broadcast: %w", ErrAnchorIntentRejected, err)
	}
	// A blob off its DA commitment would be refused by the node, so that is
	// the broadcast's rejection. A blob on its commitment would be anchored,
	// and then a size or hash mismatch is the payload verdict, which no retry
	// can change.
	if err := g.d.Committers[commitment.DACelestiaBlob].Check(c.PayloadRef, blob); err != nil {
		return nil, nil, fmt.Errorf("%w: archived blob for the broadcast: %v", ErrAnchorIntentRejected, err)
	}
	if err := commitment.CheckPayload(c, blob); err != nil {
		return nil, fmt.Errorf("archived blob for the broadcast: %w", err), nil
	}
	return blob, nil, nil
}
