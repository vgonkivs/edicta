package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
)

// publishSigner signs the agent's publish requests and never prints its key.
type publishSigner struct {
	id  string
	key ed25519.PrivateKey
}

func (s *publishSigner) AgentID() string { return s.id }

func (s *publishSigner) SignPublish(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.key, msg), nil
}

func (*publishSigner) String() string       { return "[redacted]" }
func (*publishSigner) GoString() string     { return "[redacted]" }
func (*publishSigner) LogValue() slog.Value { return slog.StringValue("[redacted]") }

type wallClock struct{ now func() time.Time }

func (c wallClock) Now() time.Time                         { return c.now() }
func (c wallClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// decision is one agent decision and what came of it.
type decision struct {
	obs     pricefeed.Observation
	amount  uint64
	action  []byte
	payload *payload.Payload
	res     *sdk.Result

	authBytes   []byte
	authExpires uint64
	txHash      [32]byte
	txHeight    uint64
	receipt     []byte
}

func fmtPrice(p uint64) string { return fmt.Sprintf("%d.%08d", p/100_000_000, p%100_000_000) }

// buildAgent creates the SDK builder, the executor and the guarded rail. It
// runs after the start Enter: nothing here broadcasts, but the rail is created
// behind the Consent.
func (r *Runner) buildAgent(ctx context.Context) error {
	var err error
	if r.feed, err = r.deps.NewFeed(); err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: price feed: %w", err))
	}
	rd := r.gateDeps.Reader
	if rd == nil {
		return coded(ExitInconclusive, errors.New("demo: the gate has no chain reader"))
	}
	ver, err := inclusion.NewSelfCheck(inclusion.SelfCheckConfig{ChainID: r.preset.ChainID, Node: rd})
	if err != nil {
		return coded(ExitUsage, err)
	}
	scfg := sdk.DefaultConfig()
	// The gate runs a mandate, so it admits only commitments naming it.
	scfg.MandateHash = r.mandateHash
	scfg.AgentID = agentID
	scfg.Scope = commitment.Scope{GateID: r.gateID}
	scfg.Recipients = []blob.Recipient{r.keys.recipient}
	scfg.SkewS = skewS
	scfg.SubmitterTrust = sdk.SubmitterSameOperator
	scfg.ExpectNamespace = r.namespace
	scfg.ExpectSigners = [][]byte{r.recSigner}
	signer, err := sdk.NewEd25519Signer(r.keys.agent)
	if err != nil {
		return coded(ExitUsage, err)
	}
	r.signer = signer
	clock := wallClock{now: r.deps.now}
	if r.builder, err = sdk.New(scfg, sdk.Deps{Publisher: r.pubClient, Signer: signer, Clock: clock, Inclusion: ver}); err != nil {
		return coded(ExitUsage, err)
	}
	if r.rawRail, err = r.deps.NewRail(ctx, r.executorKey.source()); err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: executor rail: %w", err))
	}
	r.rail = GuardRail(r.rawRail, r.consent)
	if r.dom, err = r.rawRail.Domain(ctx); err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: executor domain: %w", err))
	}
	if r.dom.Sender != r.executorKey.addr || r.dom.ChainID != r.preset.ChainID {
		return coded(ExitWrong, errors.New("demo: the executor rail is not the executor account on the demo chain"))
	}
	r.store = transfer.NewMemStore()
	r.exec, err = transfer.NewExecutor(transfer.Config{
		GatePubKey: r.gatePub, GateID: r.gateID, SkewS: skewS, MaxAmount: r.cfg.AmountUTIA, MaxFee: r.preset.Funding.MaxFee,
		Destinations: []string{r.funder.addr}, SignKey: r.keys.exec,
	}, transfer.Domain(r.dom), r.rail, r.store, clock)
	if err != nil {
		return coded(ExitUsage, err)
	}
	return nil
}

// observe reads the price once, retrying a failing source.
func (r *Runner) observe(ctx context.Context) (pricefeed.Observation, error) {
	var last error
	for i := 0; i < 3; i++ {
		o, err := r.feed.Observe(ctx)
		if err == nil {
			return o, nil
		}
		last = err
		if ctx.Err() != nil {
			return o, ctx.Err()
		}
		if err := r.deps.sleep(ctx, 2*time.Second); err != nil {
			return o, err
		}
	}
	return pricefeed.Observation{}, coded(ExitInconclusive, fmt.Errorf("demo: price feed: %w", last))
}

// newDecision builds a decision to send amount from the executor to the
// funder, on the first observation.
func (r *Runner) newDecision(ctx context.Context, amount uint64) (*decision, error) {
	o, err := r.observe(ctx)
	if err != nil {
		return nil, err
	}
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: r.dom.Sender, To: r.funder.addr, Denom: r.dom.Denom, Amount: amount}, r.dom.HRP)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	action, err := bankaction.Encode(bankaction.Action{ChainID: r.dom.ChainID, Msg: msg})
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	note, err := json.Marshal(map[string]any{
		"strategy": "edicta-demo/first-observation",
		"observation": map[string]any{
			"asset": o.AssetID, "quote": o.Quote, "price": fmtPrice(o.Price), "source": o.Source, "observed_at": o.ObservedAt,
		},
		"rule":   "act on the first observation",
		"action": map[string]any{"type": "bank-send", "from": r.dom.Sender, "to": r.funder.addr, "denom": r.dom.Denom, "amount": amount},
	})
	if err != nil {
		return nil, err
	}
	p := &payload.Payload{
		Version: payload.Version,
		Model:   payload.Model{ID: "edicta-demo/first-observation-agent"},
		Policy:  payload.Policy{ID: "edicta-demo/first-observation-v0"},
		Context: payload.Data{MediaType: "application/json", Bytes: note},
		Action:  payload.Action{Type: bankaction.ActionType, Data: action},
	}
	return &decision{obs: o, amount: amount, action: action, payload: p}, nil
}

func (r *Runner) decide(ctx context.Context) (*decision, error) {
	if err := r.buildAgent(ctx); err != nil {
		return nil, err
	}
	d, err := r.newDecision(ctx, r.cfg.AmountUTIA)
	if err != nil {
		return nil, err
	}
	r.deps.Screen.OK(fmt.Sprintf("%s/%s %s from %s at %s; rule: act on the first observation; action: send %d %s to %s",
		d.obs.AssetID, d.obs.Quote, fmtPrice(d.obs.Price), d.obs.Source, time.Unix(int64(d.obs.ObservedAt), 0).UTC().Format("15:04:05Z"),
		d.amount, r.dom.Denom, r.funder.addr))
	return d, nil
}

// commit publishes, anchors and signs one decision.
func (r *Runner) commit(ctx context.Context, d *decision) error {
	if err := r.waitClockWindow(ctx); err != nil {
		return err
	}
	res, err := r.builder.Commit(ctx, d.payload)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: publish and commit: %w", err))
	}
	d.res = res
	return nil
}

func (r *Runner) publish(ctx context.Context, d *decision) error {
	if err := r.commit(ctx, d); err != nil {
		return err
	}
	ref := d.res.Published.Ref
	r.out.CommitmentHash, r.out.AnchorHeight = d.res.CommitmentHash, ref.Height
	r.deps.Screen.OK(fmt.Sprintf("anchored at %d (%s); commitment %s; %s", ref.Height,
		time.Unix(int64(d.res.Published.BlockTime), 0).UTC().Format("15:04:05Z"), hex.EncodeToString(d.res.CommitmentHash[:]), r.explore.Block(ref.Height)))
	return nil
}

// authorize asks the gate and checks the Authorization it returns.
func (r *Runner) authorize(ctx context.Context, d *decision) error {
	raw, err := r.authClient.Authorize(ctx, d.res.Envelope, d.res.Action, d.res.ActionSalt)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: gate authorize: %w", err))
	}
	sa, _, err := commitment.VerifyAuthorization(raw, commitment.AuthorizationCheck{
		GatePubKey: r.gatePub, GateID: r.gateID, ActionType: bankaction.ActionType, Action: d.res.Action,
		Now: uint64(r.deps.now().Unix()), SkewS: skewS,
	})
	if err != nil {
		return coded(ExitWrong, fmt.Errorf("demo: the Authorization does not verify: %w", err))
	}
	d.authBytes = raw
	d.authExpires = sa.Authorization.Expires
	return nil
}

func (r *Runner) authorizeAndExecute(ctx context.Context, d *decision) error {
	if err := r.authorize(ctx, d); err != nil {
		return err
	}
	res, err := r.exec.Execute(ctx, d.authBytes, d.res.Action, d.res.ActionSalt)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: executing: %w", err))
	}
	d.txHash, d.txHeight = res.TxHash, res.Height
	r.out.TxHash, r.out.TxHeight = hex.EncodeToString(res.TxHash[:]), res.Height
	r.saveEvidence()
	receipt, err := r.record(ctx, d, res.TxHash)
	if err != nil {
		return err
	}
	d.receipt = receipt
	if err := os.WriteFile(filepath.Join(r.runDir, "receipt.cbor"), receipt, 0o600); err != nil {
		return coded(ExitUsage, err)
	}
	r.deps.Screen.OK(fmt.Sprintf("authorized, expires %s; tx %s at %d; %s; receipt recorded",
		time.Unix(int64(d.authExpires), 0).UTC().Format("15:04:05Z"), r.out.TxHash, res.Height, r.explore.Tx(r.out.TxHash)))
	return nil
}

// record asks the gate for the receipt of the executor's claim and checks it.
func (r *Runner) record(ctx context.Context, d *decision, tx [32]byte) ([]byte, error) {
	ref := hex.EncodeToString(tx[:])
	pub, sig, err := r.exec.RecordRequest(d.res.CommitmentHash, ref)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	return r.recordWith(ctx, d, ref, pub, sig)
}

func (r *Runner) recordWith(ctx context.Context, d *decision, ref string, pub ed25519.PublicKey, sig []byte) ([]byte, error) {
	raw, err := r.recClient.Record(ctx, d.res.Envelope, ref, pub, sig)
	if err != nil {
		return nil, coded(ExitInconclusive, fmt.Errorf("demo: gate record: %w", err))
	}
	sr, _, err := commitment.VerifyReceipt(raw)
	if err != nil {
		return nil, coded(ExitWrong, fmt.Errorf("demo: the receipt does not verify: %w", err))
	}
	rc := sr.Receipt
	if !bytes.Equal(rc.GatePubKey, r.gatePub) || rc.GateID != r.gateID || !bytes.Equal(rc.CommitmentHash, d.res.CommitmentHash[:]) || rc.RailRef != ref {
		return nil, coded(ExitWrong, errors.New("demo: the receipt is not for this decision or gate"))
	}
	return raw, nil
}

// waitClockWindow holds back a decision until the clock is past the gate's
// registry epoch plus its skew. The registry is created while the gate
// starts, so its epoch is no later than the moment Start returned; the gate
// refuses an issued_at at or below epoch + skew.
func (r *Runner) waitClockWindow(ctx context.Context) error {
	if r.gateStarted.IsZero() {
		return nil
	}
	ready := r.gateStarted.Unix() + skewS + 2
	for r.deps.now().Unix() < ready {
		left := ready - r.deps.now().Unix()
		r.deps.Screen.Wait("waiting for the gate's clock window...", fmt.Sprintf("%ds", left))
		if err := r.deps.sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return nil
}
