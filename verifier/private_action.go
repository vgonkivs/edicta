package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// ActionRevealer is implemented by the execution checkers of profiles whose
// executed transactions are public. From the receipt's rail reference it
// rebuilds the action bytes of the transaction, keeping only tx bytes that
// hash to the reference.
type ActionRevealer interface {
	PublicExecution() bool
	ActionFromTx(ctx context.Context, in ExecutionInput) ([]byte, error)
}

// checkPrivateAction opens the private action record of a private-form
// decision with the auditor keys.
func (r *run) checkPrivateAction() error {
	key := commitment.Hash(r.c.Action.Hash)
	path, _ := archive.PrivateBlobPath(policy.PrivateAction, key)
	pt, _, st, err := r.v.readPrivate(r.ctx, policy.PrivateAction, key, key, r.c.Action.Type)
	if err != nil {
		return err
	}
	// An archive that cannot read private blobs cannot show the record
	// absent; without a key nothing would open it anyway.
	if _, reads := r.v.archive.(archive.PrivateReader); !reads && len(r.v.cfg.AuditorKeys) == 0 {
		st = srcPrivate
	}
	switch st {
	case srcOK:
		r.salt, r.action = bytes.Clone(pt[:commitment.ActionSaltSize]), bytes.Clone(pt[commitment.ActionSaltSize:])
		r.rep.ActionSource = ActionSourcePrivateBlob
		r.pass(CheckAction)
	case srcMissing:
		r.unchecked(CheckAction, ReasonDecisionUnavailable, errors.New("no private action record of the decision"), path)
	case srcPrivate:
		r.unchecked(CheckAction, ReasonPolicyPrivate, errors.New("private decision record: the action is encrypted to the auditors"))
	default:
		r.unchecked(CheckAction, ReasonSourceCorrupt, fmt.Errorf("%w: the private action record does not open to the committed action", ErrActionInvalid), path)
	}
	return nil
}

// reveal is the reveal path of a private action on a public rail: the salt
// the gate published after the receipt, and the action bytes the checker
// rebuilds from the executed transaction. Bytes that hash with that salt to
// the agent-signed action hash are the committed action, whoever served the
// salt. The path does not run when any of its inputs is missing.
func (r *run) reveal(chk ExecutionChecker) error {
	ar, ok := chk.(ActionRevealer)
	if !ok || !ar.PublicExecution() {
		return nil
	}
	rr, ok := r.v.archive.(archive.RevealReader)
	if !ok {
		return nil
	}
	rec, err := rr.Reveal(r.ctx, r.h)
	if err != nil {
		if soft(err) {
			return nil
		}
		return fmt.Errorf("verifier: archive reveal: %w", err)
	}
	sr, _, err := commitment.VerifyReceipt(rec.SignedReceipt)
	if err != nil || !bytes.Equal(sr.Receipt.CommitmentHash, r.h[:]) || sr.Receipt.GateID != r.c.Scope.GateID {
		return nil
	}
	known := false
	for _, k := range r.v.cfg.GateKeys {
		known = known || bytes.Equal(k, sr.Receipt.GatePubKey)
	}
	if !known {
		return nil
	}
	a, err := ar.ActionFromTx(r.ctx, ExecutionInput{
		CommitmentHash: r.h, ActionType: r.c.Action.Type, RailRef: sr.Receipt.RailRef, AnchorHeight: r.c.PayloadRef.Height,
	})
	if err != nil {
		if cerr := r.ctx.Err(); cerr != nil {
			return cerr
		}
		return nil
	}
	if h, herr := commitment.ActionHash(r.c.Action.Type, rec.ActionSalt, a); herr != nil || !bytes.Equal(h[:], r.c.Action.Hash) {
		r.replaceCheck(Check{Name: CheckAction, Status: StatusUnchecked, Reason: ReasonSourceCorrupt,
			Sources: []string{archive.HashPath(archive.KindReveal, r.h)},
			Err:     fmt.Errorf("%w: the revealed salt and the executed transaction do not give the action hash", ErrActionInvalid)})
		return nil
	}
	r.action, r.salt = bytes.Clone(a), bytes.Clone(rec.ActionSalt)
	r.rep.ActionSource = ActionSourceReveal
	r.replaceCheck(Check{Name: CheckAction, Status: StatusPass})
	return nil
}
