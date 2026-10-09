package verifier

import (
	"errors"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// walkPrivate is the walk over private-form verdicts. Every hop checks the
// verdict and blinded state links on public fields; with the key it also
// opens both verdicts and runs the rest of the public-mode hop on the merged
// ones. Without the key a walk that reaches genesis is unchecked, never ok.
func (p *policyRun) walkPrivate(allow *allowRec, m *policy.Mandate) error {
	maxSteps := uint64(p.v.cfg.MaxWalkSteps)
	if maxSteps == 0 {
		maxSteps = DefaultMaxWalkSteps
	}
	info := &WalkInfo{MaxSteps: maxSteps, End: WalkEndFinding, SeqPrivate: true}
	p.walkInfo = info
	curRaw := allow
	var cur policy.Held
	curOK := false
	if !p.noKey && m != nil {
		l, err := p.logical(&allow.sv.Verdict, m)
		if err != nil {
			return err
		}
		if l.st == logicalOK && l.v.PrevState != nil {
			cur, curOK = policy.Held{V: l.v, Hash: allow.hash, M: m}, true
			info.SeqPrivate = false
			info.ToSeq, info.FromSeq, info.Total = l.v.PrevState.Seq, l.v.PrevState.Seq, l.v.PrevState.Seq+1
			p.held = []policy.Held{cur}
		}
	}
	p.signed = []signedVerdict{{v: &allow.sv.Verdict, hash: allow.hash}}
	p.heldRaw[allow.hash] = allow.raw
	scales := policy.NewScaleChain()
	for !curRaw.sv.Verdict.ReadsGenesis() {
		if info.Steps >= maxSteps {
			info.End = WalkEndMaxSteps
			p.walkTrunc = true
			return nil
		}
		pa, st, err := p.loadAllow(commitment.Hash(curRaw.sv.Verdict.PrevCommitmentHash))
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		if !noKeyHop(pa, &curRaw.sv.Verdict) {
			p.violate(pa.raw, curRaw.raw)
			return nil
		}
		p.heldRaw[pa.hash] = pa.raw
		p.signed = append(p.signed, signedVerdict{v: &pa.sv.Verdict, hash: pa.hash})
		if p.noKey {
			curRaw = pa
			info.Steps++
			continue
		}
		pm, st, err := p.loadMandate(commitment.Hash(pa.sv.Verdict.MandateHash))
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		lp, err := p.logical(&pa.sv.Verdict, pm)
		if err != nil {
			return err
		}
		switch lp.st {
		case logicalSource:
			p.walkStop(lp.src)
			return nil
		case logicalInconsistent:
			p.violate(pa.raw)
			return nil
		}
		prev := policy.Held{V: lp.v, Hash: pa.hash, M: pm}
		if lp.st == logicalSelfInconsistent || lp.v.PrevState == nil || !curOK {
			// Only the public links of this hop can be judged.
			if lp.st == logicalSelfInconsistent && p.ppViol == nil {
				p.ppViol = pa.raw
			}
			info.SeqPrivate = true
			curRaw, cur, curOK = pa, prev, lp.st == logicalOK && lp.v.PrevState != nil
			info.Steps++
			continue
		}
		set, st, err := p.loadSet(lp.v.PrevState.ClosedRoot, pm)
		if err != nil {
			return err
		}
		if st != srcOK {
			p.walkStop(st)
			return nil
		}
		p.held = append(p.held, prev)
		scales.Add(cur)
		if lerr := policy.CheckLink(prev, cur, set, scales); lerr != nil {
			var se *policy.ScaleError
			switch {
			case errors.As(lerr, &se):
				p.violate(pa.raw, p.heldRaw[se.With.Hash])
			case errors.Is(lerr, policy.ErrTransition):
				p.violate(pa.raw)
			default:
				p.violate(pa.raw, curRaw.raw)
			}
			return nil
		}
		curRaw, cur = pa, prev
		info.Steps++
		info.FromSeq = lp.v.PrevState.Seq
	}
	info.End = WalkEndGenesis
	if p.noKey && p.violation == nil {
		p.walkUnchk = p.unchecked(ReasonPolicyPrivate, errors.New("the walk read only the public links of private verdicts"))
	}
	return nil
}
