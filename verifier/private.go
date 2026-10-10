package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
)

// opener opens private records with the configured auditor keys; nil when
// there are none.
func (v *Verifier) opener() (*privatebox.Opener, error) {
	if len(v.cfg.AuditorKeys) == 0 {
		return nil, nil
	}
	o, err := privatebox.NewOpenerFromKeys(v.cfg.AuditorKeys...)
	if err != nil {
		return nil, fmt.Errorf("%w: auditor keys: %w", ErrInvalidConfig, err)
	}
	return o, nil
}

// readPrivate reads the private blob under (kind, key) and opens it. The
// plaintext must hash to want under its own tag (for an action, the salted
// action hash under actionType). It returns the plaintext without its
// salt-free framing and the kid of the entry that opened it.
func (v *Verifier) readPrivate(ctx context.Context, kind policy.PrivateKind, key, want commitment.Hash, actionType string) ([]byte, []byte, srcStatus, error) {
	pr, ok := v.archive.(archive.PrivateReader)
	if !ok {
		return nil, nil, srcMissing, nil
	}
	rec, err := pr.PrivateBlob(ctx, kind, key)
	if err != nil {
		switch {
		case errors.Is(err, archive.ErrNotFound):
			return nil, nil, srcMissing, nil
		case errors.Is(err, archive.ErrCorrupt):
			return nil, nil, srcCorrupt, nil
		}
		return nil, nil, 0, fmt.Errorf("verifier: archive private blob: %w", err)
	}
	o, err := v.opener()
	if err != nil {
		return nil, nil, 0, err
	}
	if o == nil {
		return nil, nil, srcPrivate, nil
	}
	pt, kid, err := o.Open(kind, rec.Envelope)
	switch {
	case errors.Is(err, policy.ErrPrivateUnopened):
		return nil, nil, srcPrivate, nil
	case err != nil:
		return nil, nil, srcCorrupt, nil
	}
	h, err := policy.PlaintextHash(kind, pt, actionType)
	if err != nil || h != want {
		return nil, nil, srcCorrupt, nil
	}
	return pt, kid, srcOK, nil
}

// logicalStatus says what the merge of a private-form verdict found.
type logicalStatus int

const (
	logicalOK logicalStatus = iota
	// logicalInconsistent: the decrypted state does not hash to key 20
	// under the mandate's salt.
	logicalInconsistent
	// logicalSelfInconsistent: the PrivatePart hashes to the signed
	// private_hash but breaks the presence rule.
	logicalSelfInconsistent
	logicalSource
)

type logicalVerdict struct {
	st  logicalStatus
	src srcStatus
	v   *policy.Verdict
}

// partRead is a PrivatePart as read from the archive: decoded, or the
// status of a read that failed.
type partRead struct {
	part *policy.PrivatePart
	src  srcStatus
}

// readPart reads and decodes the PrivatePart under its private_hash, once per
// run.
func (p *policyRun) readPart(key commitment.Hash) (partRead, error) {
	if r, ok := p.parts[key]; ok {
		return r, nil
	}
	pt, _, st, err := p.v.readPrivate(p.ctx, policy.PrivatePartKind, key, key, "")
	if err != nil {
		return partRead{}, err
	}
	r := partRead{src: st}
	if st == srcOK {
		part, derr := policy.DecodePrivatePart(pt)
		if derr != nil {
			r = partRead{src: srcCorrupt}
		} else {
			r.part = part
		}
	}
	p.parts[key] = r
	return r, nil
}

// logical is the public-form verdict a private-form one stands for: the
// merge with its opened PrivatePart. A public-form verdict is itself. Only
// the decoded part is shared between verdicts naming one private_hash: the
// merge and the state check belong to each signed verdict.
func (p *policyRun) logical(v *policy.Verdict, m *policy.Mandate) (logicalVerdict, error) {
	if !v.Private() {
		return logicalVerdict{v: v}, nil
	}
	r, err := p.readPart(commitment.Hash(v.PrivateHash))
	if err != nil {
		return logicalVerdict{}, err
	}
	if r.part == nil {
		return logicalVerdict{st: logicalSource, src: r.src}, nil
	}
	merged := policy.MergeUnchecked(v, r.part)
	l := logicalVerdict{v: merged}
	if v.Outcome == policy.OutcomeAllow && r.part.PrevState != nil {
		h, herr := policy.NewStateHasher(m).StateHash(r.part.PrevState)
		if herr != nil || !bytes.Equal(h[:], v.BlindPrevStateHash) {
			l.st = logicalInconsistent
			return l, nil
		}
	}
	if merged.Validate() != nil {
		l.st = logicalSelfInconsistent
	}
	return l, nil
}

// derive fills what a self-inconsistent PrivatePart left out with what the
// verifier knows on its own: the facts of its extractor, the verified
// reference time, and eval_time from them. The check to report is returned
// when the facts have no derivation.
func (p *policyRun) derive(v *policy.Verdict) (*policy.Verdict, *Check) {
	d := *v
	x := p.v.extractors
	if d.Facts == nil || d.Extractor == "" {
		id, ok := x.ID(p.in.ActionType)
		if !ok {
			return nil, p.unchecked(ReasonPolicyNoExtractor, fmt.Errorf("no extractor for %q", p.in.ActionType))
		}
		if d.Facts == nil {
			if p.in.Action == nil {
				return nil, p.unchecked(ReasonPolicyPrivate, errors.New("the action is private"))
			}
			_, f, err := x.Extract(p.in.ActionType, p.in.Action)
			if err != nil {
				return nil, p.unchecked(ReasonBlocked, err, "gate_integrity")
			}
			d.Facts = &f
		}
		d.Extractor = id
	}
	// Without a verified reference time anchor_time stays 0: the facts and
	// the per-action rules still run and can fail, only the evaluation on
	// the state is blocked.
	if d.AnchorTime == 0 && p.in.THVerified {
		d.AnchorTime = p.in.TH
	}
	if d.PrevState != nil && d.EvalTime == 0 && d.AnchorTime != 0 {
		d.EvalTime = policy.EvalTime(*d.PrevState, d.AnchorTime)
	}
	return &d, nil
}

// readStruct reads a closed set or bucket of a mandate's counter: clear in
// public mode, sealed under its blinded key in private mode.
func (p *policyRun) privateStruct(kind policy.PrivateKind, h []byte, m *policy.Mandate) ([]byte, srcStatus, error) {
	plain := commitment.Hash(h)
	key := policy.NewStateHasher(m).BlobKey(kind, plain)
	pt, _, st, err := p.v.readPrivate(p.ctx, kind, key, plain, "")
	return pt, st, err
}

// noKeyHop checks one hop of a walk on public fields only: the link to the
// previous verdict and commitment, and the blinded state link.
func noKeyHop(prev *allowRec, next *policy.Verdict) bool {
	ph, ok := next.PrevStateHash()
	return bytes.Equal(prev.hash[:], next.PrevVerdictHash) && bytes.Equal(prev.sv.Verdict.CommitmentHash, next.PrevCommitmentHash) &&
		ok && bytes.Equal(ph[:], prev.sv.Verdict.NewStateHash)
}

// forkPrivate is the fork search over held verdicts some of which are in
// private form: two allows of one gate fork when they read the same
// prev_state.seq of one counter (opened verdicts) or the same blinded
// prev_state_hash under one mandate_hash.
func (p *policyRun) forkPrivate() {
	type held struct {
		v    *policy.Verdict // as signed
		hash commitment.Hash
		ck   *[32]byte
		seq  *uint64
	}
	var hs []held
	for _, h := range p.signed {
		if h.v.GateID != p.target.GateID {
			continue
		}
		e := held{v: h.v, hash: h.hash}
		if m, ok := p.mandates[commitment.Hash(h.v.MandateHash)]; ok {
			ck := m.CounterKey()
			e.ck = &ck
			if l, err := p.logical(h.v, m); err == nil && l.v != nil && l.v.PrevState != nil &&
				(l.st == logicalOK) {
				s := l.v.PrevState.Seq
				e.seq = &s
			}
		} else if p.badMand[commitment.Hash(h.v.MandateHash)] != srcPrivate {
			continue
		}
		hs = append(hs, e)
	}
	for i := range hs {
		for j := i + 1; j < len(hs); j++ {
			a, b := hs[i], hs[j]
			if bytes.Equal(a.v.CommitmentHash, b.v.CommitmentHash) {
				continue
			}
			bySeq := a.ck != nil && b.ck != nil && *a.ck == *b.ck && a.seq != nil && b.seq != nil && *a.seq == *b.seq
			if bySeq || policy.IsHashFork(a.v, b.v) {
				p.violate(p.heldRaw[a.hash], p.heldRaw[b.hash])
				return
			}
		}
	}
}
