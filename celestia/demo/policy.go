package demo

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/policy"
)

const (
	principalFile = "principal.ed25519"
	mandateFile   = "mandate.cbor"

	// The per-action maximum is twice the demo amount, so the rogue
	// executor's amount + 1 stays inside it. The 24h sum covers the demo
	// decision and the rogue executor's genuine one with room to spare.
	perActionFactor = 2
	periodFactor    = 3
	mandateHours    = 24
	mandateLife     = 24 * time.Hour
	mandateLead     = 2 * time.Minute
)

// buildMandate is the demo's one mandate: a single agent, bank sends in utia
// to the funder only, capped per action and per rolling day.
func (r *Runner) buildMandate(gateID string) (*policy.Mandate, error) {
	id, err := randBytes(16)
	if err != nil {
		return nil, err
	}
	now := r.deps.now()
	return &policy.Mandate{
		Format:    1,
		Principal: r.keys.principal.Public().(ed25519.PublicKey),
		GateID:    gateID,
		Agents:    [][]byte{r.keys.agent.Public().(ed25519.PublicKey)},
		NotBefore: uint64(now.Add(-mandateLead).Unix()),
		NotAfter:  uint64(now.Add(mandateLife).Unix()),
		Kinds:     []string{"transfer"},
		Assets: []policy.AssetRule{{
			Asset:        "cosmos:" + r.preset.ChainID + "/" + r.preset.Denom,
			Scale:        6,
			PerActionMax: policy.AmountFromUint64(perActionFactor * r.cfg.AmountUTIA),
			Periods:      []policy.PeriodLimit{{Hours: mandateHours, Max: policy.AmountFromUint64(periodFactor * r.cfg.AmountUTIA)}},
			Recipients:   []string{"cosmos:" + r.preset.ChainID + ":" + r.funder.addr},
		}},
		MandateID: id,
		Version:   1,
	}, nil
}

// writeMandate signs the mandate with the run's principal key, writes it for
// the gate and keeps the text to show.
func (r *Runner) writeMandate(gateID string) (string, error) { return r.writeMandateWith(gateID, nil) }

func (r *Runner) writeMandateWith(gateID string, mm func(*policy.Mandate)) (string, error) {
	m, err := r.buildMandate(gateID)
	if err != nil {
		return "", err
	}
	if mm != nil {
		mm(m)
	}
	signed, mh, err := policy.SignMandate(r.keys.principal, m)
	if err != nil {
		return "", fmt.Errorf("demo: mandate: %w", err)
	}
	path := filepath.Join(r.runDir, mandateFile)
	if err := writeNew(path, signed); err != nil {
		return "", fmt.Errorf("demo: mandate file: %w", err)
	}
	r.mandateText = policy.Render(m)
	r.mandateHash = mh
	r.principalHex = hex.EncodeToString(m.Principal)
	return path, nil
}

// authorizer is the part of the API client the authorize step and the
// over-limit attempt use.
type authorizer interface {
	AuthorizeWithVerdict(ctx context.Context, envelope, action, salt []byte) (auth, verdict []byte, err error)
}

// attemptOverLimit commits an amount above the per-action maximum. The agent
// is genuine and its commitment valid; only the mandate refuses it, so no
// Authorization exists and there is nothing for an executor to send.
func (r *Runner) attemptOverLimit(ctx context.Context) (AttemptResult, error) {
	amount := (perActionFactor * r.cfg.AmountUTIA) + 1
	d, err := r.newDecision(ctx, amount)
	if err != nil {
		return AttemptResult{}, err
	}
	if err := r.commit(ctx, d); err != nil {
		return AttemptResult{}, err
	}
	return r.judgeOverLimit(ctx, r.authClient, d), nil
}

func (r *Runner) judgeOverLimit(ctx context.Context, az authorizer, d *decision) AttemptResult {
	a := AttemptResult{Layer: 1, Name: "policy-denies-over-limit",
		Expected: "gate policy.ErrAmountAboveMax, no Authorization, signed deny verdict archived",
		Why: fmt.Sprintf("The agent committed %d utia; the mandate allows %d per action. The commitment is valid, so only the policy refuses it. The signed deny verdict goes to the archive, no transfer is broadcast (only the decision's own PayForBlobs).",
			d.amount, perActionFactor*r.cfg.AmountUTIA)}
	auth, verdict, err := az.AuthorizeWithVerdict(ctx, d.res.Envelope, d.res.Action, d.res.ActionSalt)
	var apiErr *edictaapi.Error
	if errors.As(err, &apiErr) && verdict == nil {
		verdict = apiErr.PolicyVerdict
	}
	denied := errors.Is(err, policy.ErrAmountAboveMax)
	signed := false
	if sv, _, verr := policy.VerifyVerdict(verdict, r.gatePub); verr == nil {
		signed = sv.Verdict.Outcome == policy.OutcomeDeny && sv.Verdict.Reason == "ErrAmountAboveMax" &&
			string(sv.Verdict.CommitmentHash) == string(d.res.CommitmentHash[:])
	}
	a.AsExpected = denied && signed && auth == nil
	a.Got = fmt.Sprintf("gate %s; Authorization issued: %t; signed deny verdict: %t", errName(err, "policy.ErrAmountAboveMax"), auth != nil, signed)
	return a
}
