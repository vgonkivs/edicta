// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// SettlementInput is what a profile's settlement report may rely on: the
// action bytes the action check matched, the rail_ref of a receipt that
// passed, and the times of the signed objects.
type SettlementInput struct {
	CommitmentHash commitment.Hash
	ActionType     string
	Action         []byte
	RailRef        string
	// Expires is the Authorization's expiry; TRef the verified reference
	// time, 0 when the anchor facts did not verify.
	Expires uint64
	TRef    uint64
}

// SettlementChecker produces a profile-defined settlement report. The
// report is verdict-neutral: whatever it says, and whatever error the
// checker returns, the verdict and the checks stay what the core gives.
type SettlementChecker interface {
	CheckSettlement(ctx context.Context, in SettlementInput) (any, error)
}

// Why a requested settlement report did not run.
const (
	SettlementNoChecker = "no_checker"
)

// SettlementInfo is the settlement report of a run. Blocked names the check
// that kept it from running, or SettlementNoChecker; otherwise Result is the
// profile's report and Err the checker's error, if any.
type SettlementInfo struct {
	Blocked string
	Result  any
	Err     error
}

// WithSettlement also produces the settlement report of the action's
// profile. It never changes the verdict.
func WithSettlement() Option { return func(o *options) { o.settlement = true } }

// settlement runs after the verdict is final, so nothing it does can move it.
func (r *run) settlement() {
	info := &SettlementInfo{}
	r.rep.RailSettlement = info
	passed := func(n CheckName) bool {
		c, ok := r.rep.Check(n)
		return ok && c.Status == StatusPass
	}
	switch {
	case r.c == nil:
		info.Blocked = string(CheckDecision)
		return
	case !r.rep.AuthorizationVerified || r.rep.Authorization == nil:
		info.Blocked = string(CheckAuthorization)
		return
	case !passed(CheckReceipt) || r.rep.Receipt == nil:
		info.Blocked = string(CheckReceipt)
		return
	case !passed(CheckAction) || r.action == nil:
		info.Blocked = string(CheckAction)
		return
	}
	if err := commitment.CheckAction(r.c, r.action, r.salt); err != nil {
		info.Blocked = string(CheckAction)
		return
	}
	chk := r.v.settlements[r.c.Action.Type]
	if chk == nil {
		info.Blocked = SettlementNoChecker
		return
	}
	in := SettlementInput{
		CommitmentHash: r.h, ActionType: r.c.Action.Type, Action: bytes.Clone(r.action),
		RailRef: r.rep.Receipt.RailRef, Expires: r.rep.Authorization.Expires,
	}
	if r.facts != nil {
		in.TRef = r.facts.BlockTime
	}
	info.Result, info.Err = checkSettlement(r.ctx, chk, in)
}

// checkSettlement runs a checker on bytes an executor chose; a panic in it
// becomes the report's error, so it can never end the run before the core
// report is printed with its own exit code.
func checkSettlement(ctx context.Context, chk SettlementChecker, in SettlementInput) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = nil, fmt.Errorf("settlement checker panicked: %v", p)
		}
	}()
	return chk.CheckSettlement(ctx, in)
}
