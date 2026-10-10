package verifier

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

var (
	// ErrAnchorAbsent is the anchor fail of a pending reference whose anchor
	// is proven absent at every height of [h0, anchor_deadline].
	ErrAnchorAbsent = errors.New("verifier: anchor_absent: the anchor is proven absent over the whole window")
	// ErrAnchorUnpaid is the unchecked anchor of a pending reference whose
	// window holds the anchor included with a non-zero result code.
	ErrAnchorUnpaid = errors.New("verifier: anchor_unpaid: anchor included, non-zero result code")
	// ErrNoAbsenceSource marks a window checked with no absence source.
	ErrNoAbsenceSource = errors.New("verifier: no absence source")
)

// RuleAnchorAbsent is the rule the anchor check of a pending reference fails
// with when the absence is proven.
const RuleAnchorAbsent = "anchor_absent"

// IntentSignerUnknown is the intent signer of a da = 1 reference without an
// archived intent that binds to it.
const IntentSignerUnknown = "unknown"

// FastAssumptions is what the report states for a valid fast-mode decision.
var FastAssumptions = []string{
	"mode: fast. The gate authorized before the L1 anchor. The anchor landed at height H (window h0..deadline, in blocks).",
	"Proven: payload bytes match the commitment; anchored on L1 no later than T_H (anchor inclusion proven); policy evaluated on T_ref (header h0).",
	"Attested by the gate (not proven): the availability evidence was verified before the Authorization",
	"  (Fibre: validators' custody certificate; celestia_blob: the signed anchor tx accepted by the gate's node).",
}

// AnchorTxResultText is the anchor tx result a da = 1 report carries once the
// anchor proof verified. The archive admits only code 0 and the code is the
// node's word, so it is informational and never an assumption of the verdict.
const AnchorTxResultText = "code 0, node-reported, not part of the claim"

// Publication says what became of the anchor of a pending reference.
type Publication string

const (
	PublicationAnchored Publication = "anchored"
	PublicationFailed   Publication = "failed"
	PublicationUnknown  Publication = "unknown"
)

// FastInfo is the report of a decision whose verified Authorization has
// mode = 2. AnchorHeight is 0 when no anchor height is known.
type FastInfo struct {
	H0             uint64
	AnchorDeadline uint64
	AnchorHeight   uint64
	Publication    Publication
	// IntentSigner is set with anchor_absent: the hex address that signed
	// the anchor intent tx, read from chain data, or IntentSignerUnknown.
	IntentSigner string
	// Absence is set when an absence window was checked.
	Absence *AbsenceWindow
}

// AbsenceResult is what a window of absence proofs shows.
type AbsenceResult string

const (
	AbsenceAbsent   AbsenceResult = "absent"
	AbsencePresent  AbsenceResult = "present"
	AbsenceUnproven AbsenceResult = "unproven"
	// AbsencePresentUnpaid: a height of the window holds an included PFF
	// candidate whose result code is proven non-zero, and none shows code 0.
	AbsencePresentUnpaid AbsenceResult = "present_unpaid"
)

// AbsenceWindow is the outcome of the absence proofs of [h0, deadline].
type AbsenceWindow struct {
	Result AbsenceResult
	// AnchorHeight is the first height that shows the anchor (present).
	AnchorHeight uint64
	// UnpaidHeight is the first height present unpaid (present_unpaid).
	UnpaidHeight uint64
	// FirstUnproven and Cause name the first height not proven (unproven).
	FirstUnproven uint64
	Cause         error
	// Heights and Bytes are the heights checked and the proof bytes read.
	Heights int
	Bytes   uint64
	// ResultsAtDeadline: a candidate at the deadline needs the header at
	// deadline + 1 for its results proof.
	ResultsAtDeadline bool
	// ChainID is the chain id of the headers the proofs rest on, once
	// confirmed; empty when none was.
	ChainID string
	// Sources name where the proofs came from.
	Sources []string
}

// ChainHeader is a header served by an untrusted source: its hash and its
// time in seconds, both computed from the same header bytes.
type ChainHeader struct {
	Hash []byte
	Time uint64
}

// Confirm reports whether hash is the hash of the trusted chain at height.
type Confirm func(ctx context.Context, height uint64, hash []byte) bool

// PendingChain serves the anchor check of a pending reference with what the
// evidence record does not hold. Nothing it returns is trusted: the verifier
// ties every header hash a result rests on to the chain, through header
// trust or through the Confirm it passes.
type PendingChain interface {
	// Header returns the header at height from any source; ref names the
	// reference whose records may hold it.
	Header(ctx context.Context, ref commitment.PayloadRef, height uint64) (ChainHeader, error)
	// Absence checks the absence proofs of [ref.Height, deadline]. A height
	// whose proof rests on a header hash confirm refuses is not proven. The
	// error is for a cancelled context only.
	Absence(ctx context.Context, ref commitment.PayloadRef, deadline uint64, confirm Confirm) (AbsenceWindow, error)
	// IntentSigner returns the hex address that signed the archived anchor
	// intent tx of ref, read from the tx, when the intent binds to ref (for
	// da = 1 on chainID and the upload size of payloadSize too); "" when no
	// intent binds.
	IntentSigner(ctx context.Context, ref commitment.PayloadRef, payloadSize uint64, chainID string) (string, error)
}

// Checkpointer is implemented by a header trust that can name the height of
// its trusted header. Without it a pending reference with no usable evidence
// cannot tell "not decidable yet" from "not proven".
type Checkpointer interface {
	CheckpointHeight(ctx context.Context) (uint64, error)
}

// pendingAnchor is the anchor check of a pending reference: the evidence
// inside the window, or else the absence proofs over it.
func (r *run) pendingAnchor() error {
	ref := r.c.PayloadRef
	h0 := ref.Height
	blocked := func(on CheckName) {
		why := fmt.Errorf("the %s check did not pass", on)
		r.unchecked(CheckAnchorTime, ReasonBlocked, why, string(CheckAnchor))
		r.unchecked(CheckHeaderTrust, ReasonBlocked, why, string(CheckAnchor))
		r.rep.HeaderTrust.Status = TrustUnchecked
	}
	if r.sa == nil {
		r.unchecked(CheckAnchor, ReasonBlocked, errors.New("a pending reference has no window without a verified Authorization"),
			string(CheckAuthorization))
		blocked(CheckAnchor)
		return nil
	}
	deadline := r.sa.Authorization.AnchorDeadline
	fast := &FastInfo{H0: h0, AnchorDeadline: deadline, Publication: PublicationUnknown}
	r.rep.Fast = fast

	av := r.v.anchors[ref.DA]
	if av == nil {
		r.unchecked(CheckAnchor, ReasonDAUnsupported, fmt.Errorf("%w: da %d", ErrAnchorUnsupported, ref.DA))
		blocked(CheckAnchor)
		return nil
	}
	ev, err := r.v.archive.Evidence(r.ctx, ref.DA, ref.Commitment)
	var (
		facts     *AnchorFacts
		evProblem error
	)
	switch {
	case err == nil && ev.Height < h0:
		r.corrupt(CheckAnchor, ErrAnchorInvalid, fmt.Errorf("evidence at height %d, below h0 %d: a PFF cannot precede its reference height", ev.Height, h0))
		blocked(CheckAnchor)
		return nil
	case err == nil:
		at := ref
		at.Height = ev.Height
		f, ferr := r.evidenceFacts(av, at, ev)
		if errors.Is(ferr, ErrAnchorUnsupported) {
			r.unchecked(CheckAnchor, ReasonDAUnsupported, ferr)
			blocked(CheckAnchor)
			return nil
		}
		if ferr == nil && ref.DA == commitment.DAFibre && f.PromiseHeight != h0 {
			ferr = fmt.Errorf("promise height %d, the reference height h0 is %d", f.PromiseHeight, h0)
		}
		if ferr != nil {
			evProblem = ferr
		} else {
			facts = &f
		}
	case !soft(err):
		return fmt.Errorf("verifier: archive evidence: %w", err)
	case errors.Is(err, archive.ErrCorrupt):
		evProblem = err
	}
	if evProblem != nil {
		r.warn("anchor: the archived evidence does not verify (source_corrupt), so the absence proofs decide: %v", evProblem)
	}

	if facts != nil {
		H := ev.Height
		if H <= deadline {
			return r.pendingInWindow(H, *facts)
		}
		// Late evidence counts for the report only once its header is the
		// chain's.
		if r.confirm(r.ctx, H, facts.AnchorHeaderHash) {
			fast.AnchorHeight = H
		} else {
			r.warn("anchor: the evidence at height %d does not tie to the trusted chain, so it is not reported", H)
		}
		if err := r.alive(); err != nil {
			return err
		}
	}
	return r.pendingWindow(fast)
}

// pendingInWindow passes the anchor on evidence at h0 <= H <= deadline once
// header trust, reaching the deadline, ties the evidence headers to the
// chain. Evidence whose header the trusted chain does not have does not
// verify, and the absence proofs decide.
func (r *run) pendingInWindow(H uint64, facts AnchorFacts) error {
	ref := r.c.PayloadRef
	h0 := ref.Height
	fast := r.rep.Fast
	evidence := []headerAt{{H, facts.AnchorHeaderHash}}
	if ref.DA == commitment.DAFibre {
		facts.BlockTime = facts.PromiseBlockTime
		evidence = append(evidence, headerAt{h0, facts.PromiseHeaderHash})
	}
	// T_ref is the time of the header at h0, not of the evidence at H, even
	// when no header trust is supplied.
	headers := evidence
	refMissing := error(nil)
	if ref.DA != commitment.DAFibre {
		hd, err := r.refHeader(h0)
		if err != nil {
			if cerr := r.alive(); cerr != nil {
				return cerr
			}
			refMissing = err
		} else {
			facts.BlockTime, facts.RetentionStart = hd.Time, hd.Time
			headers = append(headers, headerAt{h0, hd.Hash})
		}
	}
	if r.v.trust == nil {
		r.adoptFacts(facts)
		fast.AnchorHeight = H
		r.pass(CheckAnchor)
		if refMissing != nil {
			r.rep.HeaderTrust.Status = TrustUnchecked
			r.unchecked(CheckHeaderTrust, ReasonHeaderSourceUnavailable, fmt.Errorf("%w: header at h0 %d for T_ref: %w", ErrHeaderTrust, h0, refMissing))
			r.anchorTime()
			return nil
		}
		if err := r.trustHeaders(headers); err != nil {
			return err
		}
		r.anchorTime()
		return nil
	}
	if err := r.askCheckpoint(); err != nil {
		return err
	}
	if r.checkpointH != 0 && r.checkpointH < H {
		r.evidencePending(H)
		return nil
	}

	t, err := r.tallyTrust(headers)
	if err != nil {
		return err
	}
	for _, h := range evidence {
		if t.refused[h.height] {
			if r.checkpointH == 0 {
				r.noteCheckpoint(t.cpH)
			}
			r.warn("anchor: the evidence header at height %d is not the trusted chain's (source_corrupt), so the absence proofs decide: %v", h.height, t.problem)
			return r.pendingWindow(fast)
		}
	}
	for _, h := range evidence {
		if !t.tied[h.height] {
			// A checkpoint the trust named below the deadline makes the
			// reference not decidable yet whatever the tie shows, so a tie
			// problem must not turn anchor_pending into blocked.
			if r.checkpointH != 0 && r.checkpointH < fast.AnchorDeadline {
				r.warn("anchor: header trust did not tie the evidence header at height %d: %v", h.height, t.problem)
				r.evidencePending(H)
				return nil
			}
			r.unchecked(CheckAnchor, ReasonBlocked, fmt.Errorf("header trust did not tie the evidence header at height %d", h.height), string(CheckHeaderTrust))
			r.applyTrust(headers, t)
			r.unchecked(CheckAnchorTime, ReasonBlocked, errors.New("the anchor check did not pass"), string(CheckAnchor))
			return nil
		}
	}
	// Every header trust kind is held to the deadline, including one that
	// names its checkpoint only in its results: evidence tied below D cannot
	// pass, since the window must hang from one chain that reaches D. When
	// the two answers differ, the lower one counts.
	cp := t.cpH
	if r.checkpointH != 0 && (cp == 0 || r.checkpointH < cp) {
		cp = r.checkpointH
	}
	if cp < fast.AnchorDeadline {
		r.evidenceTiedBelowDeadline(H, cp, headers, t)
		return nil
	}

	r.adoptFacts(facts)
	fast.AnchorHeight = H
	r.pass(CheckAnchor)
	if refMissing != nil {
		r.rep.HeaderTrust.Status = TrustUnchecked
		r.unchecked(CheckHeaderTrust, ReasonHeaderSourceUnavailable, fmt.Errorf("%w: header at h0 %d for T_ref: %w", ErrHeaderTrust, h0, refMissing))
		r.anchorTime()
		return nil
	}
	r.applyTrust(headers, t)
	r.anchorTime()
	if c, ok := r.rep.Check(CheckHeaderTrust); ok && c.Status == StatusPass {
		fast.Publication = PublicationAnchored
	}
	return nil
}

// evidencePending: header trust must reach the deadline before evidence in
// the window counts, so that every height of the window hangs from one
// trusted chain.
func (r *run) evidencePending(H uint64) {
	why := errors.New("the anchor check did not pass")
	r.unchecked(CheckAnchor, ReasonAnchorPending, fmt.Errorf("%w: evidence at height %d, and the trusted header %d is below the deadline %d",
		ErrAnchorInvalid, H, r.checkpointH, r.rep.Fast.AnchorDeadline))
	r.unchecked(CheckAnchorTime, ReasonBlocked, why, string(CheckAnchor))
	r.unchecked(CheckHeaderTrust, ReasonBlocked, why, string(CheckAnchor))
	r.rep.HeaderTrust.Status = TrustUnchecked
}

// evidenceTiedBelowDeadline: the evidence headers are the chain's, but the
// checkpoint is below the deadline (or unknown), so the verdict waits for a
// checkpoint that reaches it. The report keeps the checkpoint and the tied
// hashes, so the auditor sees that only the checkpoint is missing.
func (r *run) evidenceTiedBelowDeadline(H, cp uint64, headers []headerAt, t trustTally) {
	deadline := r.rep.Fast.AnchorDeadline
	why := errors.New("the anchor check did not pass")
	ht := &r.rep.HeaderTrust
	ht.Hashes = make(map[uint64][]byte, len(headers))
	for _, h := range headers {
		if t.tied[h.height] {
			ht.Hashes[h.height] = h.hash
		}
	}
	ht.CheckpointH, ht.CheckpointHash, ht.CrossCheck = t.cpH, t.cpHash, t.cross
	ht.Status = TrustUnchecked
	if cp == 0 {
		r.unchecked(CheckAnchor, ReasonBlocked, fmt.Errorf("evidence ties at %d; header trust did not name its checkpoint height, and the verdict needs a checkpoint >= D (height %d)", H, deadline),
			string(CheckHeaderTrust))
		r.unchecked(CheckHeaderTrust, ReasonNoTrustedHeader, fmt.Errorf("%w: the checkpoint height is unknown, so it is not shown to reach the anchor deadline %d", ErrHeaderTrust, deadline))
		r.unchecked(CheckAnchorTime, ReasonBlocked, why, string(CheckAnchor))
		return
	}
	r.unchecked(CheckAnchor, ReasonAnchorPending, fmt.Errorf("%w: evidence ties at %d; verdict needs a checkpoint >= D (height %d), the trusted header is %d",
		ErrAnchorInvalid, H, deadline, cp))
	r.unchecked(CheckAnchorTime, ReasonBlocked, why, string(CheckAnchor))
	r.unchecked(CheckHeaderTrust, ReasonBlocked, why, string(CheckAnchor))
}

// askCheckpoint learns the trusted header height from a header trust that
// can name it.
func (r *run) askCheckpoint() error {
	cp, ok := r.v.trust.(Checkpointer)
	if !ok {
		return nil
	}
	t, err := cp.CheckpointHeight(r.ctx)
	if cerr := r.alive(); cerr != nil {
		return cerr
	}
	if err == nil {
		r.noteCheckpoint(t)
	}
	return nil
}

func (r *run) refHeader(h0 uint64) (ChainHeader, error) {
	if r.v.pending == nil {
		return ChainHeader{}, errors.New("no header source for a pending reference")
	}
	hd, err := r.v.pending.Header(r.ctx, r.c.PayloadRef, h0)
	if err != nil {
		return ChainHeader{}, err
	}
	if len(hd.Hash) == 0 {
		return ChainHeader{}, fmt.Errorf("the header source gave no hash at height %d", h0)
	}
	return hd, nil
}

// pendingWindow decides the anchor from the absence proofs when no evidence
// inside the window verifies.
func (r *run) pendingWindow(fast *FastInfo) error {
	ref := r.c.PayloadRef
	h0, deadline := ref.Height, fast.AnchorDeadline
	blockedOthers := func() {
		why := errors.New("the anchor check did not pass")
		r.unchecked(CheckAnchorTime, ReasonBlocked, why, string(CheckAnchor))
		r.unchecked(CheckHeaderTrust, ReasonBlocked, why, string(CheckAnchor))
		r.rep.HeaderTrust.Status = TrustUnchecked
	}
	pending := func(need uint64) {
		r.unchecked(CheckAnchor, ReasonAnchorPending, fmt.Errorf("%w: no usable evidence, and the trusted header %d is below %d", ErrAnchorInvalid, r.checkpointH, need))
		blockedOthers()
	}
	if r.v.trust == nil {
		r.unchecked(CheckAnchor, ReasonBlocked, errors.New("absence proofs need header trust"), string(CheckHeaderTrust))
		r.rep.HeaderTrust.Status = TrustUnchecked
		r.unchecked(CheckAnchorTime, ReasonBlocked, errors.New("the anchor check did not pass"), string(CheckAnchor))
		r.unchecked(CheckHeaderTrust, ReasonNoTrustedHeader, errors.New("no trusted header supplied"))
		return nil
	}
	if err := r.askCheckpoint(); err != nil {
		return err
	}
	if r.checkpointH != 0 && r.checkpointH < deadline {
		pending(deadline)
		return nil
	}

	w := AbsenceWindow{Result: AbsenceUnproven, FirstUnproven: h0,
		Cause: fmt.Errorf("%w: give --absence-source or another archive copy", ErrNoAbsenceSource)}
	if r.v.pending != nil {
		var err error
		w, err = r.v.pending.Absence(r.ctx, ref, deadline, r.confirm)
		if cerr := r.alive(); cerr != nil {
			return cerr
		}
		if err != nil {
			w = AbsenceWindow{Result: AbsenceUnproven, FirstUnproven: h0, Cause: err}
		}
	}
	fast.Absence = &w
	// A checkpoint learned while the proofs were tied may still be below what
	// the window needs; anchor_pending decides before every other row except
	// a height proven present with code 0.
	need := deadline
	if w.ResultsAtDeadline {
		need = deadline + 1
	}
	if r.checkpointH != 0 && r.checkpointH < need && w.Result != AbsencePresent {
		pending(need)
		return nil
	}
	switch w.Result {
	case AbsenceAbsent:
		fast.Publication = PublicationFailed
		fast.IntentSigner = r.intentSigner(w.ChainID)
		if err := r.alive(); err != nil {
			return err
		}
		r.fail(CheckAnchor, fmt.Errorf("%w: heights %d to %d, deadline signed by the gate", ErrAnchorAbsent, h0, deadline))
	case AbsencePresent:
		fast.AnchorHeight = w.AnchorHeight
		r.unchecked(CheckAnchor, ReasonEvidenceUnavailable,
			fmt.Errorf("%w: an absence proof shows the anchor at height %d, and its full evidence is not archived", ErrArchiveIncomplete, w.AnchorHeight))
	case AbsencePresentUnpaid:
		// The included PFF published the payload, so the window is not
		// absent; v1.0 still needs code 0 for presence, so it cannot pass.
		r.unchecked(CheckAnchor, ReasonAnchorUnpaid,
			fmt.Errorf("%w: unpaid_height %d: the anchor is included with a non-zero result code", ErrAnchorUnpaid, w.UnpaidHeight))
	default:
		cause := w.Cause
		if cause == nil {
			cause = errors.New("not proven")
		}
		r.unchecked(CheckAnchor, ReasonAbsenceUnproven, fmt.Errorf("%w: height %d not proven absent: %w", ErrAnchorInvalid, w.FirstUnproven, cause), w.Sources...)
	}
	blockedOthers()
	return nil
}

// confirm ties a header hash of an absence proof to the trusted chain.
func (r *run) confirm(ctx context.Context, height uint64, hash []byte) bool {
	if r.v.trust == nil || len(hash) == 0 {
		return false
	}
	res, err := r.v.trust.Trusted(ctx, height, hash)
	r.noteCheckpoint(res.CheckpointH)
	return err == nil && res.Checked && res.CrossCheck != CrossMismatch
}

func (r *run) noteCheckpoint(h uint64) {
	r.checkpointH = max(r.checkpointH, h)
}

// intentSigner is the attribution of anchor_absent: the address that signed
// the intent tx, from chain data. Without an intent that binds, da = 2
// falls back to payload_ref.signer, which the agent signed.
func (r *run) intentSigner(chainID string) string {
	ref := r.c.PayloadRef
	if r.v.pending != nil {
		s, err := r.v.pending.IntentSigner(r.ctx, ref, r.c.PayloadSize, chainID)
		if err == nil && s != "" {
			return s
		}
		if err != nil {
			r.warn("anchor: the anchor intent was not read: %v", err)
		}
	}
	if ref.DA == commitment.DACelestiaBlob && len(ref.Signer) > 0 {
		return hex.EncodeToString(ref.Signer)
	}
	return IntentSignerUnknown
}
