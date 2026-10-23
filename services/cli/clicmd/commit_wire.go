// SPDX-License-Identifier: Apache-2.0

package clicmd

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/archive/httparchive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/dacommit/blobv1"
	"github.com/vgonkivs/edicta/engine/gate"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/internal/secret"
	"github.com/vgonkivs/edicta/plugins/celestia/chain/gatechain"
	"github.com/vgonkivs/edicta/plugins/celestia/chain/inclusion"
	"github.com/vgonkivs/edicta/plugins/celestia/node"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

// buildCommitService wires the Service from edicta.toml and the flags: the
// agent key from agent.key_file, the Recorder and the gate from
// agent.recorder_url and agent.gate_url.
func buildCommitService(ctx context.Context, o commonOpts) (*commitcmd.Service, func(), error) {
	noop := func() {}
	path := o.configPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, noop, usageErr("%v", err)
		}
		path = p
	}
	cfg, err := config.LoadValid(path, nil, config.Builtin{})
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	if cfg.Agent == nil {
		return nil, noop, usageErr("[agent] is required")
	}
	trust, err := submitterTrust(cfg.Agent.SubmitterTrust)
	if err != nil {
		return nil, noop, err
	}
	gateURL := cfg.Agent.GateURL
	recURL := cmpOr(cfg.Agent.RecorderURL, gateURL)
	if gateURL == "" {
		gateURL = recURL
	}
	if gateURL == "" {
		return nil, noop, usageErr("agent.gate_url (or agent.recorder_url) is required")
	}
	gateID := o.gateID
	if gateID == "" && cfg.Gate != nil {
		gateID = cfg.Gate.GateID
	}
	if gateID == "" {
		return nil, noop, usageErr("the gate id is unknown: pass --gate-id or set gate.gate_id")
	}
	gateKeys, err := gateKeysOf(o, cfg)
	if err != nil {
		return nil, noop, err
	}
	priv, err := keyfile.ReadSeed(cfg.Agent.KeyFile, "agent")
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	signer, err := sdk.NewEd25519Signer(priv)
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	mandate, recipients, err := mandateOfWarn(o, cfg.Agent.MandateFile, os.Stderr)
	if err != nil {
		return nil, noop, err
	}
	var token edictaapi.Secret
	if o.tokenFile != "" {
		s, err := secret.FromFile(o.tokenFile)
		if err != nil {
			return nil, noop, usageErr("%v", err)
		}
		token = edictaapi.NewSecret(strings.TrimSpace(s.RevealString()))
	}
	var ns []byte
	if cfg.Recorder != nil && cfg.Recorder.Namespace != "" {
		if ns, err = hex.DecodeString(cfg.Recorder.Namespace); err != nil {
			return nil, noop, usageErr("recorder.namespace: %v", err)
		}
	}

	apiOpts := []edictaapi.ClientOption{edictaapi.WithGateID(gateID), edictaapi.WithRetry(3, nil)}
	if !o.cbor {
		apiOpts = append(apiOpts, edictaapi.WithJSON())
	}
	hc := &http.Client{Timeout: 3 * time.Minute}
	pubClient, err := edictaapi.NewClient(recURL, token, publishSigner{id: cfg.Agent.ID, key: priv}, hc, apiOpts...)
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	gateClient, err := edictaapi.NewClient(gateURL, token, nil, hc, apiOpts...)
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}

	var signerClient commitcmd.Signer
	if o.signerURL != "" {
		if o.signerTokenFile == "" {
			return nil, noop, usageErr("--signer-url needs --signer-token-file")
		}
		tok, err := secret.FromFile(o.signerTokenFile)
		if err != nil {
			return nil, noop, usageErr("--signer-token-file: %v", err)
		}
		tok = secret.New([]byte(strings.TrimSpace(tok.RevealString())))
		c, err := commitcmd.NewSignerClient(o.signerURL, tok, hc)
		if err != nil {
			return nil, noop, usageErr("%v", err)
		}
		signerClient = c
	} else if o.signerTokenFile != "" {
		return nil, noop, usageErr("--signer-token-file needs --signer-url")
	}
	var state commitcmd.StateStore
	if o.stateDir != "" {
		st, err := commitcmd.NewFileStateStore(o.stateDir)
		if err != nil {
			return nil, noop, usageErr("%v", err)
		}
		state = st
	}

	fp := &fastPending{cfg: cfg}
	svc := &commitcmd.Service{
		Gate: gateClient, GateKeys: gateKeys, GateID: gateID, Signer: signerClient, State: state,
		Builders: func(mode string, validFor time.Duration) (*sdk.Builder, error) {
			sc := sdk.DefaultConfig()
			sc.AgentID = cfg.Agent.ID
			sc.Scope = commitment.Scope{GateID: gateID}
			sc.Recipients = recipients
			sc.MandateHash = mandate
			sc.SubmitterTrust = trust
			sc.ExpectNamespace = ns
			if validFor > 0 {
				sc.TTLS = uint64(validFor / time.Second)
			}
			d := sdk.Deps{Publisher: pubClient, Signer: signer, Clock: wallClock{}}
			if mode == commitcmd.ModeFast {
				pv, err := fp.get(ctx)
				if err != nil {
					return nil, err
				}
				d.Pending = pv
			}
			return sdk.New(sc, d)
		},
	}
	return svc, fp.close, nil
}

// submitterTrust maps agent.submitter_trust. There is no default: the claim
// "the evidence was checked" depends on whose Recorder published the blob.
// Untrusted needs an independent inclusion verifier, which is not wired yet.
func submitterTrust(v string) (sdk.SubmitterTrust, error) {
	switch v {
	case config.SubmitterSameOperator:
		return sdk.SubmitterSameOperator, nil
	case config.SubmitterUntrusted:
		return 0, usageErr("agent.submitter_trust = untrusted needs an independent inclusion verifier, which this build does not have")
	case "":
		return 0, usageErr(`agent.submitter_trust is required: "same_operator" (the Recorder is run by the agent's own operator)`)
	}
	return 0, usageErr("agent.submitter_trust %q is not known", v)
}

// gateKeysOf takes the gate keys from --gate-key, else agent.gate_keys, else
// signer.pinned_gate_keys. Without one the Authorization cannot be checked.
func gateKeysOf(o commonOpts, cfg config.Config) ([][]byte, error) {
	src := []string(o.gateKeys)
	if len(src) == 0 && cfg.Agent != nil {
		src = cfg.Agent.GateKeys
	}
	if len(src) == 0 && cfg.Signer != nil {
		src = cfg.Signer.PinnedGateKeys
	}
	if len(src) == 0 {
		return nil, usageErr("no gate key: pass --gate-key or set agent.gate_keys or signer.pinned_gate_keys")
	}
	out := make([][]byte, 0, len(src))
	for _, h := range src {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, usageErr("gate key %q must be 64 hex characters", h)
		}
		out = append(out, b)
	}
	return out, nil
}

// mandateOf returns the mandate_ref and the payload recipients. The mandate
// file gives both (the hash and its auditors); --mandate-ref overrides the
// hash and --recipient adds keys.
func mandateOf(o commonOpts, file string) (ref [32]byte, rec []blob.Recipient, err error) {
	return mandateOfWarn(o, file, io.Discard)
}

// mandateOfWarn is mandateOf, and writes a WARNING line to warn when a flag
// sets a value different from the mandate file's: the commitment then names
// a mandate or auditors the principal did not sign.
func mandateOfWarn(o commonOpts, file string, warn io.Writer) (ref [32]byte, rec []blob.Recipient, err error) {
	fromFile := file != ""
	if fromFile {
		if ref, rec, err = loadMandate(file); err != nil {
			return ref, nil, err
		}
	}
	return applyFlags(o, ref, rec, fromFile, warn)
}

func applyFlags(o commonOpts, ref [32]byte, rec []blob.Recipient, fromFile bool, warn io.Writer) ([32]byte, []blob.Recipient, error) {
	if o.mandateRef != "" {
		b, err := hex.DecodeString(o.mandateRef)
		if err != nil || len(b) != 32 {
			return ref, nil, usageErr("--mandate-ref must be 64 hex characters")
		}
		var flagRef [32]byte
		copy(flagRef[:], b)
		if fromFile && flagRef != ref {
			fmt.Fprintf(warn, "WARNING: --mandate-ref %s overrides the mandate file's mandate_ref %s\n",
				shortHex(flagRef[:]), shortHex(ref[:]))
		}
		ref = flagRef
	}
	extra, err := parseRecipients(o.recipients)
	if err != nil {
		return ref, nil, err
	}
	for _, r := range extra {
		dup := false
		for _, e := range rec {
			dup = dup || string(e.KID) == string(r.KID)
		}
		if !dup {
			if fromFile {
				fmt.Fprintf(warn, "WARNING: --recipient %s is not an auditor of the mandate file; the payload is also encrypted to it\n",
					shortHex(r.KID))
			}
			rec = append(rec, r)
		}
	}
	if len(rec) == 0 {
		return ref, nil, usageErr("no recipient: set agent.mandate_file with auditors or pass --recipient")
	}
	return ref, rec, nil
}

func shortHex(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}

func loadMandate(path string) (ref [32]byte, rec []blob.Recipient, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ref, nil, usageErr("agent.mandate_file: %v", err)
	}
	sm, h, err := policy.DecodeSignedMandate(b)
	if err != nil {
		return ref, nil, usageErr("agent.mandate_file: %v", err)
	}
	copy(ref[:], h[:])
	for i, a := range sm.Mandate.Auditors {
		pk, err := ecdh.X25519().NewPublicKey(a.Pubkey)
		if err != nil {
			return ref, nil, usageErr("agent.mandate_file: auditor %d: %v", i, err)
		}
		rec = append(rec, blob.Recipient{KID: a.Kid, PublicKey: pk})
	}
	return ref, rec, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// publishSigner signs publish requests with the agent key.
type publishSigner struct {
	id  string
	key ed25519.PrivateKey
}

func (p publishSigner) AgentID() string { return p.id }
func (p publishSigner) SignPublish(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(p.key, msg), nil
}

func parseRecipients(in []string) ([]blob.Recipient, error) {
	out := make([]blob.Recipient, 0, len(in))
	for _, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, usageErr("--recipient %q is not hex", h)
		}
		pk, err := ecdh.X25519().NewPublicKey(b)
		if err != nil {
			return nil, usageErr("--recipient %q: %v", h, err)
		}
		out = append(out, blob.Recipient{KID: policy.AuditorKid(b), PublicKey: pk})
	}
	return out, nil
}

// fastPending opens the chain reader and the archive the anchor intent check
// needs, on the first fast-mode request, so strict mode never dials them. Only
// a successful open is kept: a transient failure does not disable fast mode.
type fastPending struct {
	cfg config.Config
	mu  sync.Mutex
	pv  sdk.PendingVerifier
	rc  io.Closer
}

func (f *fastPending) get(ctx context.Context) (sdk.PendingVerifier, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pv != nil {
		return f.pv, nil
	}
	pv, err := f.open(ctx)
	if err != nil {
		return nil, err
	}
	f.pv = pv
	return pv, nil
}

func (f *fastPending) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rc != nil {
		_ = f.rc.Close()
	}
}

// open returns a usage failure for a missing setting and a plain error for an
// endpoint that does not answer.
func (f *fastPending) open(ctx context.Context) (sdk.PendingVerifier, error) {
	c := f.cfg
	if c.Network.Bridge.Addr == "" {
		return nil, usageErr("fast mode needs network.bridge to check the anchor intent")
	}
	var intents archive.IntentReader
	switch {
	case c.Archive.URL != "":
		cl, err := httparchive.NewClient(c.Archive.URL, &http.Client{Timeout: 30 * time.Second})
		if err != nil {
			return nil, usageErr("archive.url: %v", err)
		}
		intents = cl
	case c.Archive.Dir != "":
		st, err := fsarchive.OpenReadOnly(c.Archive.Dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
		if err != nil {
			return nil, fmt.Errorf("open archive: %w", err)
		}
		intents = st
	default:
		return nil, usageErr("fast mode needs archive.url or archive.dir to read the anchor intent")
	}
	bc := node.BridgeConfig{Addr: c.Network.Bridge.Addr, TLS: c.Network.Bridge.TLS}
	if tf := c.Network.Bridge.TokenFile; tf != "" {
		s, err := secret.FromFile(tf)
		if err != nil {
			return nil, usageErr("network.bridge.token_file: %v", err)
		}
		bc.Token = strings.TrimSpace(s.RevealString())
	}
	rc, reader, err := node.NewReadOnly(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("bridge: %w", err)
	}
	bi, err := gatechain.NewBlobIntents(reader)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	pv, err := inclusion.NewPending(inclusion.PendingConfig{Intents: intents, Verifier: bi})
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	f.rc = rc
	return pv, nil
}
