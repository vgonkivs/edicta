package demo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/verifier"
)

const (
	// fastLiveDelay is the mandate's fast_mode_max_delay. It is below the
	// Recorder's tx timeout, so the anchor deadline is h0 + fastLiveDelay.
	fastLiveDelay = 30
	// fastLiveTimeoutBlocks must exceed the gate's max_h0_age_blocks plus
	// min_fast_slack_blocks.
	fastLiveTimeoutBlocks = 40
	// fastLivePFBs is what the Recorder account is funded for: the one
	// anchor tx of the run and spares.
	fastLivePFBs = 3
	// defaultRecorderFunding caps each funding send to the run's Recorder
	// account; it pays fees only.
	defaultRecorderFunding = 20_000
	// evidenceGrace is how many blocks past the deadline the scene waits
	// for the evidence before it gives up.
	evidenceGrace    = 10
	fastLiveRecorder = "recorder-fast"
)

// FastLiveConfig is the command line of `edicta demo fast-live`.
type FastLiveConfig struct {
	Config
	// Restart stops the in-process daemon right after the publish, before
	// the anchor lands, and starts it again on the same archive.
	Restart bool
	// MaxRecorderFunding caps each funding send to the run's Recorder account.
	MaxRecorderFunding uint64
}

// WithDefaults fills the zero fields that have defaults.
func (c FastLiveConfig) WithDefaults() FastLiveConfig {
	c.Config = c.Config.WithDefaults()
	if c.MaxRecorderFunding == 0 {
		c.MaxRecorderFunding = defaultRecorderFunding
	}
	return c
}

// ValidateBasic checks every field that needs no dependency.
func (c FastLiveConfig) ValidateBasic() error {
	return c.Config.ValidateBasic()
}

// ChecklistItem is one row of the step report, named by its section of the
// Mocha checklist.
type ChecklistItem struct {
	Section  string `json:"section"`
	Title    string `json:"title"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Status   string `json:"status"` // pass | fail | unchecked
}

// FastLiveOutcome is everything a fast-live run produced.
type FastLiveOutcome struct {
	Code            int             `json:"exit_code"`
	RunDir          string          `json:"run_dir"`
	CommitmentHash  string          `json:"commitment_hash,omitempty"`
	RecorderAccount string          `json:"recorder_account,omitempty"`
	H0              uint64          `json:"h0,omitempty"`
	AnchorHeight    uint64          `json:"anchor_height,omitempty"`
	Deadline        uint64          `json:"anchor_deadline,omitempty"`
	Restarted       bool            `json:"restarted"`
	Verdict         string          `json:"verdict,omitempty"`
	Items           []ChecklistItem `json:"checklist"`
	Funding         []FundingSend   `json:"funding,omitempty"`
}

// FastLive runs fast mode on the live network with the Runner's funding,
// trust-root and verify steps.
type FastLive struct {
	r   *Runner
	cfg FastLiveConfig
	out FastLiveOutcome

	store      *fsarchive.Store
	d          *decision
	recAddr    []byte
	seq0       uint64
	h0         uint64
	tPub       time.Time
	intentHash [32]byte
	intentTx   []byte
	evAtPub    bool
	landedKill bool
	step, of   int
}

// NewFastLive validates cfg and returns the scene. It does no I/O.
func NewFastLive(cfg FastLiveConfig, d Deps) (*FastLive, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, coded(ExitUsage, err)
	}
	r, err := newRunner(cfg.Config, d, func(p *Preset) {
		p.Funding.MaxAmount = min(p.Funding.MaxAmount, cfg.MaxRecorderFunding)
	})
	if err != nil {
		return nil, err
	}
	of := 7
	if cfg.Restart {
		of++
	}
	return &FastLive{r: r, cfg: cfg, of: of, out: FastLiveOutcome{Restarted: cfg.Restart}}, nil
}

// Run does the scene. Out.Code is always set; the error says why a run
// stopped early or which check failed.
func (f *FastLive) Run(ctx context.Context) (FastLiveOutcome, error) {
	r := f.r
	err := f.run(ctx)
	f.out.Code = r.exitCode(ctx, err)
	f.out.RunDir = r.runDir
	switch {
	case ctx.Err() != nil && f.out.Code == ExitInterrupted:
		r.reportInterrupt()
	case err != nil:
		r.deps.Screen.Fail("stopped", err)
	default:
		r.deps.Screen.Info(fmt.Sprintf("Done in %s. Report: %s", r.deps.now().Sub(r.start).Round(time.Second), filepath.Join(r.runDir, "fast-live.json")))
	}
	f.save()
	return f.out, err
}

func (f *FastLive) next(title string) {
	f.step++
	f.r.deps.Screen.Step(f.step, f.of, title)
}

func (f *FastLive) run(ctx context.Context) error {
	r := f.r
	r.start = r.deps.now()
	defer r.cleanup()

	f.next("Environment and a fresh Recorder account")
	if err := r.prepareWith(ctx, f.loadChainKeys, f.newRecorderKey); err != nil {
		return err
	}
	f.next("edictad in fast mode")
	if err := f.startGate(ctx); err != nil {
		return err
	}
	f.next("Fund the Recorder account (fees only)")
	if err := f.fund(ctx); err != nil {
		return err
	}
	f.next("Publish: pending reference")
	if err := f.publish(ctx); err != nil {
		return err
	}
	if f.cfg.Restart {
		f.next("Restart while pending")
		if err := f.restart(ctx); err != nil {
			return err
		}
	}
	f.next("Fast authorization")
	if err := f.authorize(ctx); err != nil {
		return err
	}
	f.next("Anchor and evidence at H")
	landed, err := f.waitAnchor(ctx)
	if err != nil {
		return err
	}
	f.next("Independent verification and checklist report")
	verr := error(nil)
	if landed {
		verr = f.verify(ctx)
	} else {
		f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", "skipped: no anchor", "unchecked")
	}
	f.report()
	if verr != nil {
		return verr
	}
	for _, it := range f.out.Items {
		if it.Status == "fail" {
			return coded(ExitWrong, fmt.Errorf("demo: checklist item %s failed: %s", it.Section, it.Observed))
		}
	}
	if !landed {
		return coded(ExitWrong, errors.New("demo: the anchor did not land with its evidence by the deadline"))
	}
	return nil
}

func (f *FastLive) add(section, title, expected, observed, status string) {
	f.out.Items = append(f.out.Items, ChecklistItem{Section: section, Title: title, Expected: expected, Observed: observed, Status: status})
}

func passIf(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

// newRecorderKey creates the run's Recorder account in the run directory: a
// new secp256k1 key no other tool holds, never the demo's own Recorder key.
// loadChainKeys loads the funder and the executor account; the executor never
// moves funds here (the Authorization is not executed), so it stays unfunded.
func (f *FastLive) loadChainKeys() error {
	r := f.r
	if err := r.loadFunderKey(); err != nil {
		return err
	}
	var err error
	if r.executorKey, err = loadOrCreateKey(filepath.Join(r.dirs.chain, executorName), executorName, r.preset.HRP); err != nil {
		return coded(ExitUsage, err)
	}
	if r.executorKey.addr == r.funder.addr {
		return coded(ExitUsage, ErrSameAccount)
	}
	return nil
}

func (f *FastLive) newRecorderKey() error {
	r := f.r
	dir := filepath.Join(r.runDir, fastLiveRecorder)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return coded(ExitUsage, fmt.Errorf("demo: recorder key directory: %w", err))
	}
	k, err := loadOrCreateKey(dir, recorderName, r.preset.HRP)
	if err != nil {
		return coded(ExitUsage, err)
	}
	r.recorderKey = k
	if k.addr == r.funder.addr || k.addr == r.executorKey.addr {
		return coded(ExitUsage, ErrSameAccount)
	}
	_, b, err := bech32.DecodeAndConvert(k.addr)
	if err != nil || len(b) != 20 {
		return coded(ExitUsage, fmt.Errorf("demo: recorder address %s", k.addr))
	}
	f.recAddr = b
	f.out.RecorderAccount = k.addr
	r.deps.Screen.OK(fmt.Sprintf("fresh Recorder account %s; its key stays in %s and signs nothing but this run's anchor txs", k.addr, dir))
	return nil
}

func (f *FastLive) startGate(ctx context.Context) error {
	r := f.r
	mm := func(m *policy.Mandate) { m.FastModeMaxDelay = fastLiveDelay }
	mc := func(c *edictad.Config) {
		c.Recorder.Fast = true
		c.Recorder.FastDedicatedAccount = true
		c.Recorder.FastTimeoutBlocks = fastLiveTimeoutBlocks
		c.Gate.Fast = edictad.FastConfig{Enabled: true, OwnNode: true, PendingNamespaces: []string{demoNamespace}}
	}
	if err := r.writeConfigsWith(mm, mc); err != nil {
		return coded(ExitUsage, err)
	}
	r.deps.Screen.Warn(fmt.Sprintf("gate.fast.own_node = true is a test-only attestation here: anchor txs go out through %s, a public endpoint, "+
		"not a node you run. Never set own_node for a node that is not yours.", r.preset.GRPC.Addr))
	if err := f.launch(ctx); err != nil {
		return err
	}
	r.deps.Screen.Mandate(r.mandateText)
	var err error
	if f.store, err = fsarchive.OpenReadOnly(r.edCfg.Archive.Dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()}); err != nil {
		return coded(ExitUsage, fmt.Errorf("demo: archive: %w", err))
	}
	return nil
}

// launch starts the gate and checks that its Recorder signs with the run's
// fresh account.
func (f *FastLive) launch(ctx context.Context) error {
	r := f.r
	if err := r.launchGate(ctx); err != nil {
		return err
	}
	if !bytes.Equal(r.recSigner, f.recAddr) {
		return coded(ExitWrong, fmt.Errorf("demo: the gate's Recorder signs as %x, not the run's account %s", r.recSigner, r.recorderKey.addr))
	}
	if r.gateDeps.Reader == nil || r.gateDeps.Consensus == nil {
		return coded(ExitInconclusive, errors.New("demo: the gate has no chain reader"))
	}
	r.deps.Screen.OK(fmt.Sprintf("[gate.fast] on, Recorder fast mode on (fast_timeout_blocks %d, mandate fast_mode_max_delay %d), account %s",
		fastLiveTimeoutBlocks, fastLiveDelay, r.recorderKey.addr))
	return nil
}

// stopGate is the in-process stand-in for killing the daemon.
func (f *FastLive) stopGate() {
	r := f.r
	if r.gate != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = r.gate.Shutdown(ctx)
		cancel()
		r.gate = nil
	}
}

// closeGateDeps drops every connection the stopped daemon used.
func (f *FastLive) closeGateDeps() {
	r := f.r
	if r.closeGateDeps != nil {
		r.closeGateDeps()
		r.closeGateDeps = nil
	}
}

// fund moves fees to the Recorder account through the demo's capped funding
// step, after the one Enter that starts the run.
func (f *FastLive) fund(ctx context.Context) error {
	r := f.r
	r.budget = f.budget
	if err := r.fundAndStart(ctx); err != nil {
		return err
	}
	f.out.Funding = r.out.Funding
	return nil
}

// budget is the Recorder account's shortfall for fastLivePFBs anchor tx
// fees. A shortfall above the per-send cap is refused before any prompt.
func (f *FastLive) budget(ctx context.Context) (Budget, error) {
	r := f.r
	fp := r.preset.Funding
	pfbFee, err := feeFor(r.minGas, fp.PFBGas)
	if err != nil {
		return Budget{}, coded(ExitUsage, err)
	}
	sendFee, err := feeFor(r.minGas, fp.GasLimit)
	if err != nil {
		return Budget{}, coded(ExitUsage, err)
	}
	have, err := r.balance(ctx, r.recorderKey.addr)
	if err != nil {
		return Budget{}, err
	}
	b := Budget{SendFee: sendFee, PFBFee: pfbFee, WantRecorder: fastLivePFBs * pfbFee}
	b.Recorder = shortfall(b.WantRecorder, have)
	if b.Recorder > fp.MaxAmount {
		return Budget{}, coded(ExitUsage, fmt.Errorf("%w: the Recorder account needs %d utia, the cap is %d per send; raise it with --max-recorder-funding",
			ErrShortfallAboveMax, b.Recorder, fp.MaxAmount))
	}
	b.FunderFees = b.Sends() * sendFee
	b.Total = b.Recorder + b.FunderFees
	return b, nil
}

// account reads the Recorder account, waiting while the node does not know
// it yet.
func (f *FastLive) account(ctx context.Context) (uint64, error) {
	r := f.r
	var last error
	for range maxReadFailures {
		acc, err := r.gateDeps.Consensus.Account(ctx, r.recorderKey.addr)
		if err == nil {
			return acc.Sequence, nil
		}
		last = err
		if err := r.deps.sleep(ctx, r.cfg.PollEvery); err != nil {
			return 0, err
		}
	}
	return 0, coded(ExitInconclusive, fmt.Errorf("demo: the Recorder account: %w", last))
}

// publish has the agent publish through the fast Recorder and sign the
// pending reference, then reads the archive before the anchor can land.
func (f *FastLive) publish(ctx context.Context) error {
	r := f.r
	sc := r.deps.Screen
	intents, err := gatechain.NewBlobIntents(r.gateDeps.Reader)
	if err != nil {
		return coded(ExitUsage, err)
	}
	pending, err := inclusion.NewPending(inclusion.PendingConfig{Intents: f.store, Verifier: intents})
	if err != nil {
		return coded(ExitUsage, err)
	}
	scfg := sdk.DefaultConfig()
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
	b, err := sdk.New(scfg, sdk.Deps{Publisher: r.pubClient, Signer: signer, Clock: wallClock{now: r.deps.now}, Pending: pending})
	if err != nil {
		return coded(ExitUsage, err)
	}
	amount := r.cfg.AmountUTIA
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: r.executorKey.addr, To: r.funder.addr, Denom: r.preset.Denom, Amount: amount}, r.preset.HRP)
	if err != nil {
		return coded(ExitUsage, err)
	}
	action, err := bankaction.Encode(bankaction.Action{ChainID: r.preset.ChainID, Msg: msg})
	if err != nil {
		return coded(ExitUsage, err)
	}
	note, err := json.Marshal(map[string]any{"strategy": "edicta-demo/fast-live", "rule": "act now, anchor within the window",
		"action": map[string]any{"type": "bank-send", "from": r.executorKey.addr, "to": r.funder.addr, "denom": r.preset.Denom, "amount": amount}})
	if err != nil {
		return err
	}
	d := &decision{amount: amount, action: action, payload: &payload.Payload{
		Version: payload.Version,
		Model:   payload.Model{ID: "edicta-demo/fast-live-agent"},
		Policy:  payload.Policy{ID: "edicta-demo/fast-live-v1"},
		Context: payload.Data{MediaType: "application/json", Bytes: note},
		Action:  payload.Action{Type: bankaction.ActionType, Data: action},
	}}
	if err := r.waitClockWindow(ctx); err != nil {
		return err
	}
	if f.seq0, err = f.account(ctx); err != nil {
		return err
	}
	res, err := b.Commit(ctx, d.payload)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: publish and commit: %w", err))
	}
	f.tPub = r.deps.now()
	d.res, f.d = res, d
	ref := res.Published.Ref
	f.out.CommitmentHash = hex.EncodeToString(res.CommitmentHash[:])
	r.out.CommitmentHash = res.CommitmentHash
	if !ref.Pending() {
		return coded(ExitWrong, errors.New("demo: the Recorder returned an anchored reference, not a pending one"))
	}
	f.h0, f.out.H0 = ref.Height, ref.Height

	rec, err := f.store.Intent(ctx, commitment.DACelestiaBlob, ref.Commitment, ref.Height)
	if err != nil {
		return coded(ExitWrong, fmt.Errorf("demo: no archived anchor intent for the pending reference: %w", err))
	}
	f.intentTx = bytes.Clone(rec.Tx)
	f.intentHash = sha256.Sum256(rec.Tx)
	_, everr := f.store.Evidence(ctx, commitment.DACelestiaBlob, ref.Commitment)
	f.evAtPub = everr == nil
	st, terr := r.gateDeps.Consensus.Tx(ctx, f.intentHash)
	inBlock := "not yet in a block"
	if terr == nil && st.Found {
		inBlock = fmt.Sprintf("already in block %d", st.Height)
	}
	sc.OK(fmt.Sprintf("pending reference at h0 %d, signer %s; anchor tx %s %s", ref.Height, r.recorderKey.addr, hex.EncodeToString(f.intentHash[:]), inBlock))
	sc.OK(fmt.Sprintf("agent signed commitment %s on the pending reference (inclusion.Pending)", f.out.CommitmentHash))

	f.add("4.1", "pending reference before the anchor", "anchor pending at h0, signed by the run's Recorder account",
		fmt.Sprintf("h0 %d, signer %x, T_pub %s, anchor tx %s", ref.Height, ref.Signer, f.tPub.UTC().Format(time.RFC3339), inBlock),
		passIf(bytes.Equal(ref.Signer, f.recAddr)))
	f.add("4.2", "intent archived before the evidence", "intent in the archive, no evidence yet",
		fmt.Sprintf("intent at h0 %d archived; evidence present: %t", rec.RefHeight, f.evAtPub), passIf(!f.evAtPub))
	return nil
}

// restart stops the daemon before the anchor lands and starts it again on
// the same archive and registry.
func (f *FastLive) restart(ctx context.Context) error {
	r := f.r
	sc := r.deps.Screen
	comm := f.d.res.Published.Ref.Commitment
	f.stopGate()
	st, terr := r.gateDeps.Consensus.Tx(ctx, f.intentHash)
	_, everr := f.store.Evidence(ctx, commitment.DACelestiaBlob, comm)
	f.landedKill = (terr == nil && st.Found) || everr == nil
	f.closeGateDeps()
	if f.landedKill {
		sc.Warn("the anchor landed before the daemon stopped; the restart does not show recovery while pending")
	} else {
		sc.OK("edictad stopped before H: the anchor is not in a block and no evidence is archived")
	}
	if err := f.launch(ctx); err != nil {
		return err
	}
	sc.OK("edictad restarted on the same archive and registry")
	status := "pass"
	if f.landedKill {
		status = "unchecked"
	}
	f.add("7.1", "daemon stopped before H and restarted", "stopped while the anchor is pending",
		fmt.Sprintf("anchor landed or evidence written before the stop: %t", f.landedKill), status)
	return nil
}

func (f *FastLive) authorize(ctx context.Context) error {
	r := f.r
	head, err := r.gateDeps.Consensus.LatestHeight(ctx)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: head: %w", err))
	}
	if err := r.authorizeWith(ctx, r.authClient, f.d); err != nil {
		return err
	}
	a := f.d.auth
	window := min(gate.DefaultConfig().FastWindowBlocks, fastLiveDelay)
	want := f.h0 + window
	if t := f.h0 + fastLiveTimeoutBlocks; t < want {
		want = t
	}
	f.out.Deadline = a.AnchorDeadline
	ok := a.Mode == commitment.ModeFast && a.AnchorDeadline == want
	r.deps.Screen.OK(fmt.Sprintf("authorized in mode %d at head about %d: anchor_deadline %d (expected %d), expires %s; the scene never executes it",
		a.Mode, head, a.AnchorDeadline, want, time.Unix(int64(a.Expires), 0).UTC().Format("15:04:05Z")))
	f.add("4.5", "fast Authorization", fmt.Sprintf("mode fast, anchor_deadline = h0 + min(fast_window_blocks, fast_timeout_blocks, mandate delay) = %d", want),
		fmt.Sprintf("mode %d, anchor_deadline %d", a.Mode, a.AnchorDeadline), passIf(ok))
	return nil
}

const (
	deadlineBlockTime = 6 * time.Second
	deadlineMargin    = 2 * time.Minute
)

// waitAnchor polls the own node and the archive until the anchor tx is in a
// block and its evidence is archived, or the deadline is well past.
func (f *FastLive) waitAnchor(ctx context.Context) (bool, error) {
	r := f.r
	sc, cons := r.deps.Screen, r.gateDeps.Consensus
	comm := f.d.res.Published.Ref.Commitment
	limit := f.out.Deadline + evidenceGrace
	var (
		st    node.TxStatus
		ev    *archive.EvidenceRecord
		fails int
	)
	for {
		head, err := cons.LatestHeight(ctx)
		if err == nil {
			var s node.TxStatus
			if s, err = cons.Tx(ctx, f.intentHash); err == nil {
				st = s
			}
		}
		if err != nil {
			if fails++; fails > maxReadFailures {
				return false, coded(ExitInconclusive, fmt.Errorf("demo: the node: %w", err))
			}
		} else {
			fails = 0
			if e, eerr := f.store.Evidence(ctx, commitment.DACelestiaBlob, comm); eerr == nil {
				ev = e
			}
			if st.Found && ev != nil {
				break
			}
			if head > limit {
				break
			}
			found := "not in a block"
			if st.Found {
				found = fmt.Sprintf("in block %d, evidence not archived yet", st.Height)
			}
			sc.Wait("waiting for the anchor...", fmt.Sprintf("head %d, h0 %d, deadline %d; anchor tx %s", head, f.h0, f.out.Deadline, found))
		}
		if err := r.deps.sleep(ctx, r.cfg.PollEvery); err != nil {
			return false, err
		}
	}
	if !st.Found || ev == nil {
		f.add("4.6", "evidence at H", "evidence record at H > h0", fmt.Sprintf("anchor found: %t, evidence: %t, past height %d", st.Found, ev != nil, limit), "fail")
		return false, nil
	}
	h := st.Height
	f.out.AnchorHeight = h
	r.out.AnchorHeight = h
	sc.OK(fmt.Sprintf("anchor tx in block %d (h0 %d, deadline %d), code %d; evidence archived at %d; %s", h, f.h0, f.out.Deadline, st.Code, ev.Height, r.explore.Block(h)))

	rd := r.gateDeps.Reader
	hdrH, errH := rd.HeaderAt(ctx, h)
	hdr0, err0 := rd.HeaderAt(ctx, f.h0)
	if errH != nil || err0 != nil {
		f.add("4.3", "anchor in a block after the pending reference", "H > h0, block time of H after h0", fmt.Sprintf("headers unreadable: %v", errors.Join(errH, err0)), "unchecked")
	} else {
		after := hdrH.Time.After(hdr0.Time)
		f.add("4.3", "anchor in a block after the pending reference", "H > h0, block time of H after the block time of h0 (and T_pub)",
			fmt.Sprintf("H %d, h0 %d, block time of H %s, of h0 %s, H minus T_pub %s", h, f.h0, hdrH.Time.UTC().Format(time.RFC3339),
				hdr0.Time.UTC().Format(time.RFC3339), hdrH.Time.Sub(f.tPub).Round(time.Second)),
			passIf(h > f.h0 && after && st.Code == 0))
	}

	seq, serr := f.account(ctx)
	seqTxs, qerr := cons.TxBySequence(ctx, r.recorderKey.addr, f.seq0)
	n, same := f.intents(ctx, comm)
	indexed := "the index lists no tx at that sequence"
	idxOK := true
	if qerr == nil && len(seqTxs) > 0 {
		idxOK = len(seqTxs) == 1 && seqTxs[0].Hash == f.intentHash
		indexed = fmt.Sprintf("the index lists %d tx(s) at that sequence, the anchor tx: %t", len(seqTxs), idxOK)
	}
	oneTx := serr == nil && seq == f.seq0+1 && idxOK && n == 1 && same
	f.add("4.4", "one anchor tx from the Recorder account", fmt.Sprintf("sequence %d -> %d, one archived intent", f.seq0, f.seq0+1),
		fmt.Sprintf("sequence now %d; %s; archived intents for this blob %d, tx bytes unchanged %t", seq, indexed, n, same), passIf(oneTx))
	evOK := ev.Height == h && h > f.h0 && h <= f.out.Deadline
	f.add("4.6", "evidence at H", fmt.Sprintf("evidence height = H, h0 < H <= %d", f.out.Deadline),
		fmt.Sprintf("evidence height %d, H %d", ev.Height, h), passIf(evOK))
	if f.cfg.Restart {
		status := passIf(oneTx && evOK && !f.evAtPub)
		if f.landedKill {
			status = "unchecked"
		}
		f.add("7.2", "evidence at H after the restart, no re-sign", "evidence at H from the archived intent, sequence +1 only",
			fmt.Sprintf("evidence height %d, sequence %d -> %d, archived tx unchanged %t", ev.Height, f.seq0, seq, same), status)
	}
	return true, nil
}

// intents counts the archived intents of the blob and reports whether the
// one at h0 still holds the bytes archived at publish.
func (f *FastLive) intents(ctx context.Context, comm []byte) (int, bool) {
	recs, err := f.store.Intents(ctx, commitment.DACelestiaBlob, 0)
	if err != nil {
		return 0, false
	}
	n, same := 0, false
	for _, rec := range recs {
		if !bytes.Equal(rec.Commitment, comm) {
			continue
		}
		n++
		if rec.RefHeight == f.h0 && bytes.Equal(rec.Tx, f.intentTx) {
			same = true
		}
	}
	return n, same
}

// waitDeadline blocks until the chain head is past the Authorization's
// anchor_deadline, bounded by the blocks left times the block time plus a
// margin.
func (f *FastLive) waitDeadline(ctx context.Context) error {
	r := f.r
	cons := r.gateDeps.Consensus
	want := f.out.Deadline + 1
	head, err := cons.LatestHeight(ctx)
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: the node: %w", err))
	}
	var left uint64
	if want > head {
		left = want - head
	}
	limit := time.Duration(left)*deadlineBlockTime + deadlineMargin
	r.deps.Screen.Info(fmt.Sprintf("verify needs the chain head past the anchor deadline %d: head %d, waiting up to %s", f.out.Deadline, head, limit.Round(time.Second)))
	end := r.deps.now().Add(limit)
	fails := 0
	for head < want {
		if !r.deps.now().Before(end) {
			return coded(ExitInconclusive, fmt.Errorf("demo: the chain head %d did not pass the anchor deadline %d within %s", head, f.out.Deadline, limit.Round(time.Second)))
		}
		if err := r.deps.sleep(ctx, r.cfg.PollEvery); err != nil {
			return err
		}
		h, err := cons.LatestHeight(ctx)
		if err != nil {
			if fails++; fails > maxReadFailures {
				return coded(ExitInconclusive, fmt.Errorf("demo: the node: %w", err))
			}
			continue
		}
		fails = 0
		head = h
		r.deps.Screen.Wait("waiting for the anchor deadline...", fmt.Sprintf("head %d, deadline %d, %d blocks to go", head, f.out.Deadline, max(int64(want)-int64(head), 0)))
	}
	return nil
}

func (f *FastLive) verify(ctx context.Context) error {
	r := f.r
	var err error
	if r.archive, err = openArchiveServer(filepath.Join(r.runDir, "archive")); err != nil {
		return coded(ExitUsage, err)
	}
	if err := f.waitDeadline(ctx); err != nil {
		return err
	}
	// The verifier's header trust must reach max(D, H); the root is taken
	// past D even when the anchor landed earlier.
	root, err := r.trustRoot(ctx, max(f.out.AnchorHeight, f.out.Deadline))
	if err != nil {
		if errors.Is(err, ErrTrustRootUnavailable) {
			f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", "no trust root", "unchecked")
			return coded(ExitInconclusive, err)
		}
		return err
	}
	res, err := r.verify(ctx, r.out.CommitmentHash, r.archive.url, "", root, f.out.AnchorHeight)
	if err != nil {
		return err
	}
	r.showVerify(res)
	r.writeVerifyFile("verify-fast-live.json", res)
	f.out.Verdict = string(res.Verdict)
	anchor := ""
	for _, c := range res.Checks {
		if c.Check == string(verifier.CheckAnchor) {
			anchor = c.Status
		}
	}
	r.deps.Screen.Info("$ edicta " + strings.Join(res.Command, " "))
	switch res.Verdict {
	case VerdictValid:
		f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", fmt.Sprintf("VALID, anchor check %s", anchor), passIf(anchor == "pass"))
		return nil
	case VerdictInconclusive:
		f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", "INCONCLUSIVE", "unchecked")
		return coded(ExitInconclusive, errors.New("demo: the verifier is INCONCLUSIVE"))
	case VerdictNotAuthorized:
		f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", "NOT AUTHORIZED", "fail")
		return coded(ExitNotAuth, errors.New("demo: the verifier says NOT AUTHORIZED"))
	}
	f.add("4.7", "edicta verify", "VALID, anchor at H inside its window", strings.ToUpper(string(res.Verdict)), "fail")
	return coded(ExitWrong, fmt.Errorf("demo: the verifier says %s", res.Verdict))
}

// report prints the checklist rows, named by their guide/mocha-checklist.md
// section, for the Results table.
func (f *FastLive) report() {
	sc := f.r.deps.Screen
	sc.Info("Checklist (guide/mocha-checklist.md, da = celestia_blob):")
	for _, it := range f.out.Items {
		sc.Check(CheckLine{Check: it.Section + " " + it.Title, Status: it.Status, Detail: it.Observed, Advice: "expected: " + it.Expected})
	}
}

func (f *FastLive) save() {
	if f.r.runDir == "" {
		return
	}
	b, err := json.MarshalIndent(f.out, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(f.r.runDir, "fast-live.json"), append(b, '\n'), 0o600)
	}
}
