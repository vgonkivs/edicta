package demo

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
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
	fastChainID = "edicta-offline-1"
	fastBase    = 1000
	// fastDelay is the mandate's fast_mode_max_delay and the Recorder's
	// anchor tx timeout, so the anchor deadline is h0 + fastDelay.
	fastDelay  = 20
	fastAmount = 1000
	fastSteps  = 6
)

// FastSceneConfig configures the offline fast-mode scene.
type FastSceneConfig struct {
	// Dir is where the run directory is created; it is kept.
	Dir string
}

// FastOutcome is what the scene produced.
type FastOutcome struct {
	Code           int
	RunDir         string
	CommitmentHash commitment.Hash
	H0             uint64
	Deadline       uint64
	// RecorderSigner is the account the gate's Recorder signs anchor txs with.
	RecorderSigner []byte
	// Window is the verdict inside the anchor window, Final the one after it.
	Window, Final FastVerdict
}

// FastVerdict is the part of one verifier report the scene judges.
type FastVerdict struct {
	Verdict      Verdict
	Code         int
	AnchorStatus string
	AnchorReason string
	Publication  string
	IntentSigner string
	Absence      string
	Heights      int
	Command      []string
}

// fastView is the part of the verifier's JSON report the scene reads.
type fastView struct {
	Verdict      string `json:"verdict"`
	Mode         string `json:"mode"`
	Publication  string `json:"publication"`
	IntentSigner string `json:"intent_signer"`
	Absence      *struct {
		Result  string `json:"result"`
		Heights int    `json:"heights"`
	} `json:"absence"`
	Checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason"`
		Error  string `json:"error"`
	} `json:"checks"`
	Error string `json:"error"`
}

type chainClock struct{ c *offlineChain }

func (k chainClock) Now() time.Time { return k.c.Now() }

// fastScene holds one run of the scene.
type fastScene struct {
	sc     Screen
	dir    string
	verify func(ctx context.Context, args []string, out io.Writer) int
	runDir string
	chain  *offlineChain
	store  *fsarchive.Store
	gate   *edictad.Server

	agent, gateKey, exec, principal ed25519.PrivateKey
	recipient                       blob.Recipient
	signer                          node.AnchorSigner
	sender, to                      string
	mandateHash                     commitment.Hash
	mandateText                     string
	gateID                          string
	gatePub                         ed25519.PublicKey
	ns, recSigner                   []byte
	pref                            commitment.PayloadRef

	out FastOutcome
}

// RunFastScene runs the fast-mode scene offline: an in-process chain stands
// in for the network; the gate, the Recorder's fast path, the absence proofs
// and the verifier are the real code. The gate authorizes a pending decision
// before its anchor lands, the anchor tx is killed, and after the deadline
// the verifier proves its absence: INVALID.
func RunFastScene(ctx context.Context, cfg FastSceneConfig, sc Screen, verify func(context.Context, []string, io.Writer) int) (FastOutcome, error) {
	s := &fastScene{sc: sc, verify: verify, dir: cfg.Dir}
	err := s.run(ctx)
	if s.gate != nil {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = s.gate.Shutdown(sctx)
		cancel()
	}
	if err != nil {
		s.out.Code = ExitCodeOf(err)
		sc.Fail("fast-mode scene", err)
		return s.out, err
	}
	return s.out, nil
}

func (s *fastScene) run(ctx context.Context) error {
	s.sc.Step(1, fastSteps, "Offline chain and fast-mode gate")
	if err := s.setup(ctx, s.dir); err != nil {
		return err
	}
	s.sc.Step(2, fastSteps, "Decision on a pending reference")
	res, err := s.decide(ctx)
	if err != nil {
		return err
	}
	s.sc.Step(3, fastSteps, "Fast authorization")
	if err := s.authorize(ctx, res); err != nil {
		return err
	}
	s.sc.Step(4, fastSteps, "Verify inside the anchor window")
	s.chain.Mine(3)
	if s.out.Window, err = s.check(ctx, s.chain.Height()); err != nil {
		return err
	}
	s.sc.Step(5, fastSteps, "Anchor killed")
	s.chain.Mine(s.out.Deadline + 1 - s.chain.Height())
	s.sc.OK(fmt.Sprintf("head %d, past the deadline %d; the network accepted %d broadcast(s) of the anchor tx and included none",
		s.chain.Height(), s.out.Deadline, s.chain.Swallowed()))
	s.sc.Step(6, fastSteps, "Verify after the deadline: absence proofs")
	if s.out.Final, err = s.check(ctx, s.out.Deadline); err != nil {
		return err
	}
	s.out.Code = ExitOK
	w, f := s.out.Window, s.out.Final
	if w.Verdict != VerdictInconclusive || w.AnchorReason != string(verifier.ReasonAnchorPending) ||
		f.Verdict != VerdictInvalid || f.AnchorReason != verifier.RuleAnchorAbsent || f.Publication != "failed" {
		s.out.Code = ExitWrong
		return coded(ExitWrong, errors.New("demo: the verifier did not end as the scene expects"))
	}
	s.sc.Info("The Authorization was genuine and issued in one block; the decision it rests on was never published. " +
		"The verifier proves that from chain data and names the account that signed the anchor intent.")
	return nil
}

func (s *fastScene) setup(ctx context.Context, parent string) error {
	if err := s.keys(parent); err != nil {
		return coded(ExitUsage, err)
	}
	// Twenty blocks, the last one now: the gate's start reads a header ten
	// blocks below the head.
	s.chain = newOfflineChain(fastChainID, fastBase, 20, time.Now().UTC().Truncate(time.Second).Add(-19*offlineBlockTime))
	cfg, err := s.writeConfig()
	if err != nil {
		return coded(ExitUsage, err)
	}
	if s.store, err = fsarchive.Open(cfg.Archive.Dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()}); err != nil {
		return coded(ExitUsage, fmt.Errorf("demo: archive: %w", err))
	}
	s.gate, err = edictad.Start(ctx, cfg, edictad.Deps{
		Reader: s.chain, Consensus: s.chain, Archive: s.store, Clock: chainClock{s.chain},
		RecorderFast: &edictad.RecorderFastDeps{Signer: s.signer},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return coded(ExitInconclusive, fmt.Errorf("demo: starting the gate: %w", err))
	}
	s.sc.Info(fmt.Sprintf("run directory %s (kept); no network, no funds: an in-process chain %s stands in for Celestia", s.runDir, fastChainID))
	s.sc.OK(fmt.Sprintf("gate %s started with [gate.fast] on, Recorder in fast mode; head %d", s.gateID, s.chain.Height()))
	s.sc.Mandate(s.mandateText)
	return nil
}

func (s *fastScene) keys(parent string) error {
	dir, err := os.MkdirTemp(parent, "edicta-fast-")
	if err != nil {
		return err
	}
	s.runDir = dir
	s.out.RunDir = dir
	s.gateID = "demo-" + filepath.Base(dir)
	gen := func() (ed25519.PrivateKey, error) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	for _, k := range []*ed25519.PrivateKey{&s.agent, &s.gateKey, &s.exec, &s.principal} {
		if *k, err = gen(); err != nil {
			return err
		}
	}
	s.gatePub = s.gateKey.Public().(ed25519.PublicKey)
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.recipient = blob.Recipient{KID: []byte("edicta-demo-fast"), PublicKey: rk.PublicKey()}
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	if _, _, err := kr.NewMnemonic(recorderName, keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1); err != nil {
		return err
	}
	if s.signer, err = node.NewAnchorSigner(kr, recorderName, fastChainID); err != nil {
		return err
	}
	addr := func() (string, error) {
		b, err := randBytes(20)
		if err != nil {
			return "", err
		}
		return bech32.ConvertAndEncode("celestia", b)
	}
	if s.sender, err = addr(); err != nil {
		return err
	}
	s.to, err = addr()
	return err
}

func (s *fastScene) writeConfig() (edictad.Config, error) {
	p := func(name string) string { return filepath.Join(s.runDir, name) }
	seed := s.gateKey.Seed()
	defer clear(seed)
	files := map[string][]byte{
		"gate.ed25519":  seed,
		"recorder.pass": []byte("offline-scene-passphrase\n"),
		"agents.toml":   []byte(fmt.Sprintf("[[agents]]\nagent_id = %q\npubkey = %q\n", agentID, hex.EncodeToString(s.agent.Public().(ed25519.PublicKey)))),
	}
	for name, b := range files {
		if err := writeNew(p(name), b); err != nil {
			return edictad.Config{}, err
		}
	}
	if err := os.Mkdir(p("archive"), 0o700); err != nil {
		return edictad.Config{}, err
	}
	m := s.mandate()
	signed, mh, err := policy.SignMandate(s.principal, m)
	if err != nil {
		return edictad.Config{}, fmt.Errorf("demo: mandate: %w", err)
	}
	if err := writeNew(p(mandateFile), signed); err != nil {
		return edictad.Config{}, err
	}
	s.mandateHash, s.mandateText = mh, policy.Render(m)
	cfg := edictad.Config{
		Network: edictad.NetworkConfig{
			ChainID: fastChainID, DA: edictad.DAConfigBlob,
			Bridge:        edictad.EndpointConfig{Addr: "bridge.offline.invalid:26658"},
			ConsensusGRPC: edictad.EndpointConfig{Addr: "consensus.offline.invalid:9090"},
		},
		Archive: edictad.ArchiveConfig{Dir: p("archive")},
		Policy:  edictad.PolicyConfig{MandateFile: p(mandateFile)},
		Recorder: edictad.RecorderConfig{
			Enabled: true, Namespace: demoNamespace,
			KeyringDir: p("keyring"), KeyringBackend: "file", KeyName: recorderName, PassphraseFile: p("recorder.pass"),
			Quota: edictad.QuotaConfig{BlobsPerHour: 60, BytesPerDay: 64 << 20},
			Fast:  true, FastTimeoutBlocks: fastDelay, FastDedicatedAccount: true,
		},
		Gate: edictad.GateConfig{
			GateID: s.gateID, KeyFile: p("gate.ed25519"), RegistryPath: p("registry.db"),
			ActionTypes: []string{bankaction.ActionType}, AllowlistFile: p("agents.toml"),
			ExecutorKeys:   []string{hex.EncodeToString(s.exec.Public().(ed25519.PublicKey))},
			AnchorVerifier: "self",
			Fast:           edictad.FastConfig{Enabled: true, OwnNode: true, PendingNamespaces: []string{demoNamespace}},
		},
		HTTP: edictad.HTTPConfig{Listen: "127.0.0.1:0"},
	}
	raw, err := toml.Marshal(cfg)
	if err != nil {
		return edictad.Config{}, err
	}
	if err := writeNew(p("edictad.toml"), raw); err != nil {
		return edictad.Config{}, err
	}
	return edictad.ParseConfig(raw)
}

// mandate consents to fast mode: an Authorization may come before the
// anchor, which must then land within fastDelay blocks.
func (s *fastScene) mandate() *policy.Mandate {
	now := s.chain.Now()
	return &policy.Mandate{
		Format: 1, Principal: s.principal.Public().(ed25519.PublicKey), GateID: s.gateID,
		Agents:    [][]byte{s.agent.Public().(ed25519.PublicKey)},
		NotBefore: uint64(now.Add(-mandateLead).Unix()), NotAfter: uint64(now.Add(mandateLife).Unix()),
		Kinds: []string{"transfer"},
		Assets: []policy.AssetRule{{
			Asset: "cosmos:" + fastChainID + "/utia", Scale: 6, PerActionMax: policy.AmountFromUint64(perActionFactor * fastAmount),
			Recipients: []string{"cosmos:" + fastChainID + ":" + s.to},
		}},
		MandateID: []byte("edicta-demo-fast"), Version: 1, FastModeMaxDelay: fastDelay,
	}
}

func (s *fastScene) client(signer edictaapi.PublishSigner) (*edictaapi.Client, error) {
	return edictaapi.NewClient("http://"+s.gate.Addr(), edictaapi.NewSecret(""), signer, nil,
		edictaapi.WithGateID(s.gateID), edictaapi.WithClock(chainClock{s.chain}))
}

// decide has the agent publish through the fast Recorder and sign the
// commitment on the pending reference it returns.
func (s *fastScene) decide(ctx context.Context) (*sdk.Result, error) {
	// The registry refuses decisions issued within the skew of its epoch.
	s.chain.Mine(skewS/uint64(offlineBlockTime/time.Second) + 1)
	hc, err := s.client(nil)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	hl, err := hc.Health(ctx)
	if err != nil {
		return nil, coded(ExitInconclusive, fmt.Errorf("demo: gate health: %w", err))
	}
	s.ns, s.recSigner = hl.Namespace, hl.RecorderSigner
	s.out.RecorderSigner = hl.RecorderSigner
	pub, err := s.client(&publishSigner{id: agentID, key: s.agent})
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	intents, err := gatechain.NewBlobIntents(s.chain)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	pending, err := inclusion.NewPending(inclusion.PendingConfig{Intents: s.store, Verifier: intents})
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	scfg := sdk.DefaultConfig()
	scfg.MandateHash = s.mandateHash
	scfg.AgentID = agentID
	scfg.Scope = commitment.Scope{GateID: s.gateID}
	scfg.Recipients = []blob.Recipient{s.recipient}
	scfg.SkewS = skewS
	scfg.SubmitterTrust = sdk.SubmitterSameOperator
	scfg.ExpectNamespace = s.ns
	scfg.ExpectSigners = [][]byte{s.recSigner}
	signer, err := sdk.NewEd25519Signer(s.agent)
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	b, err := sdk.New(scfg, sdk.Deps{Publisher: pub, Signer: signer, Clock: chainClock{s.chain}, Pending: pending})
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: s.sender, To: s.to, Denom: "utia", Amount: fastAmount}, "celestia")
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	action, err := bankaction.Encode(bankaction.Action{ChainID: fastChainID, Msg: msg})
	if err != nil {
		return nil, coded(ExitUsage, err)
	}
	note, err := json.Marshal(map[string]any{"strategy": "edicta-demo/fast-mode", "rule": "act now, anchor within the window",
		"action": map[string]any{"type": "bank-send", "to": s.to, "denom": "utia", "amount": fastAmount}})
	if err != nil {
		return nil, err
	}
	res, err := b.Commit(ctx, &payload.Payload{
		Version: payload.Version,
		Model:   payload.Model{ID: "edicta-demo/fast-mode-agent"},
		Policy:  payload.Policy{ID: "edicta-demo/fast-mode-v1"},
		Context: payload.Data{MediaType: "application/json", Bytes: note},
		Action:  payload.Action{Type: bankaction.ActionType, Data: action},
	})
	if err != nil {
		return nil, coded(ExitInconclusive, fmt.Errorf("demo: publish and commit: %w", err))
	}
	ref := res.Published.Ref
	if !ref.Pending() {
		return nil, coded(ExitWrong, errors.New("demo: the Recorder returned an anchored reference, not a pending one"))
	}
	s.out.CommitmentHash, s.out.H0, s.pref = res.CommitmentHash, ref.Height, ref
	s.sc.OK(fmt.Sprintf("pending reference at h0 %d: the anchor intent (a signed PayForBlobs, timeout height %d) is archived and broadcast, nothing is included yet",
		ref.Height, ref.Height+fastDelay))
	s.sc.OK(fmt.Sprintf("agent signed commitment %s (send %d utia to %s)", hex.EncodeToString(res.CommitmentHash[:]), fastAmount, s.to))
	return res, nil
}

func (s *fastScene) authorize(ctx context.Context, res *sdk.Result) error {
	h := s.chain.Height()
	az, err := edictaapi.NewClient("http://"+s.gate.Addr(), edictaapi.NewSecret(""), nil, nil, edictaapi.WithClock(chainClock{s.chain}))
	if err != nil {
		return coded(ExitUsage, err)
	}
	raw, err := az.Authorize(ctx, res.Envelope, res.Action, res.ActionSalt)
	if err != nil {
		return coded(ExitWrong, fmt.Errorf("demo: gate authorize: %w", err))
	}
	sa, _, err := commitment.VerifyAuthorization(raw, commitment.AuthorizationCheck{
		GatePubKey: s.gatePub, GateID: s.gateID, ActionType: bankaction.ActionType, Action: res.Action, ActionSalt: res.ActionSalt,
		Now: uint64(s.chain.Now().Unix()), SkewS: skewS,
	})
	if err != nil {
		return coded(ExitWrong, fmt.Errorf("demo: the Authorization does not verify: %w", err))
	}
	a := sa.Authorization
	if a.Mode != commitment.ModeFast || s.chain.Height() != h {
		return coded(ExitWrong, fmt.Errorf("demo: Authorization mode %d at head %d, expected fast mode at %d", a.Mode, s.chain.Height(), h))
	}
	s.out.Deadline = a.AnchorDeadline
	s.sc.OK(fmt.Sprintf("authorized in fast mode at head %d, in the block of h0, before any anchor: anchor_deadline %d, expires %s",
		h, a.AnchorDeadline, time.Unix(int64(a.Expires), 0).UTC().Format("15:04:05Z")))
	s.sc.Info("An executor may act on this Authorization now. The gate's promise: the decision lands on chain by the deadline, or the verifier proves it did not.")
	return nil
}

// check archives the absence proofs of [h0, upTo] from the bridge and runs
// the verifier with the header at upTo as its trust root.
func (s *fastScene) check(ctx context.Context, upTo uint64) (FastVerdict, error) {
	fetch, err := absence.NewFetcher(s.chain, nil, "bridge")
	if err != nil {
		return FastVerdict{}, coded(ExitUsage, err)
	}
	q := absence.Query{DA: commitment.DACelestiaBlob, Namespace: s.pref.Namespace, Commitment: s.pref.Commitment, Signer: s.pref.Signer}
	n := 0
	for h := s.out.H0; h <= upTo; h++ {
		r, err := fetch.Fetch(ctx, q, h)
		if err != nil {
			return FastVerdict{}, coded(ExitInconclusive, err)
		}
		if _, err := s.store.Put(ctx, r); err != nil {
			return FastVerdict{}, coded(ExitInconclusive, fmt.Errorf("demo: archive absence proof: %w", err))
		}
		n += absence.Size(r)
	}
	s.sc.OK(fmt.Sprintf("absence proofs for heights %d..%d fetched from the bridge (%d bytes) and archived", s.out.H0, upTo, n))
	trusted, err := s.trustedFile(upTo)
	if err != nil {
		return FastVerdict{}, coded(ExitUsage, err)
	}
	s.sc.TrustRoot(TrustRootInfo{Height: upTo, Hash: trusted.hash, Source: "the offline chain (demo mode)"})
	args := []string{"verify", hex.EncodeToString(s.out.CommitmentHash[:]), "--gate-key", hex.EncodeToString(s.gatePub),
		"--archive", filepath.Join(s.runDir, "archive"), "--trusted", trusted.path,
		"--principal-key", hex.EncodeToString(s.principal.Public().(ed25519.PublicKey)), "--json"}
	var buf bytes.Buffer
	code := s.verify(ctx, args, &buf)
	var v fastView
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil || v.Error != "" {
		return FastVerdict{}, coded(ExitUsage, fmt.Errorf("demo: the verifier gave no report (exit %d): %s", code, strings.TrimSpace(buf.String())))
	}
	out := FastVerdict{Code: code, Publication: v.Publication, IntentSigner: v.IntentSigner, Command: args}
	switch v.Verdict {
	case string(verifier.VerdictValid):
		out.Verdict = VerdictValid
	case string(verifier.VerdictInvalid):
		out.Verdict = VerdictInvalid
	case string(verifier.VerdictNotAuthorized):
		out.Verdict = VerdictNotAuthorized
	default:
		out.Verdict = VerdictInconclusive
	}
	if v.Absence != nil {
		out.Absence, out.Heights = v.Absence.Result, v.Absence.Heights
	}
	res := VerifyResult{Code: code, Verdict: out.Verdict}
	for _, c := range v.Checks {
		line := CheckLine{Check: c.Name, Status: c.Status, Reason: c.Reason, Detail: c.Error}
		if c.Name == string(verifier.CheckAnchor) {
			out.AnchorStatus, out.AnchorReason = c.Status, c.Reason
			// A failed check carries its rule in the error, not as a reason.
			if c.Status == "fail" && strings.Contains(c.Error, verifier.RuleAnchorAbsent) {
				out.AnchorReason = verifier.RuleAnchorAbsent
			}
		}
		res.Checks = append(res.Checks, line)
		s.sc.Check(line)
	}
	s.sc.Info(fmt.Sprintf("mode %s, publication: %s, intent signer: %s, absence: %s over %d height(s)",
		v.Mode, v.Publication, s.signerText(v.IntentSigner), orDash(out.Absence), out.Heights))
	s.sc.Verdict(res)
	s.sc.Info("$ edicta " + strings.Join(args[:len(args)-1], " "))
	return out, nil
}

// signerText names the intent signer the verifier attributed, from chain
// data, next to the account the Recorder reported.
func (s *fastScene) signerText(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 20 {
		return orDash(h)
	}
	addr, err := bech32.ConvertAndEncode("celestia", b)
	if err != nil {
		return h
	}
	if bytes.Equal(b, s.recSigner) {
		return addr + " (the Recorder's anchor account)"
	}
	return addr
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type trustedHeader struct {
	path string
	hash []byte
}

func (s *fastScene) trustedFile(h uint64) (trustedHeader, error) {
	raw, hash, err := s.chain.HeaderProto(h)
	if err != nil {
		return trustedHeader{}, err
	}
	b, err := json.Marshal(map[string]any{"height": h, "hash": hex.EncodeToString(hash), "header": hex.EncodeToString(raw)})
	if err != nil {
		return trustedHeader{}, err
	}
	path := filepath.Join(s.runDir, fmt.Sprintf("trusted-%d.json", h))
	if err := writeNew(path, b); err != nil {
		return trustedHeader{}, err
	}
	return trustedHeader{path: path, hash: hash}, nil
}
