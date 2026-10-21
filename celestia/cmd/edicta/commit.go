// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
)

const commitFlags = "[--config PATH] [--gate-id ID] [--gate-key HEX] [--recipient X25519_HEX]... [--mandate-ref HEX] [--token-file FILE] [--cbor]"

const commitUsage = "usage: edicta commit " + commitFlags +
	" [--request FILE|-] [--action-file FILE] [--action-type TYPE] [--context FILE] [--model ID] [--policy ID] [--mode fast|strict] [--valid-for 10m]"

const serveUsage = "usage: edicta agent serve " + commitFlags + " [--listen 127.0.0.1:8500] [--allow-remote]"

// commonOpts are the flags `commit` and `agent serve` share.
type commonOpts struct {
	configPath string
	gateID     string
	gateKey    string
	recipients stringList
	mandateRef string
	tokenFile  string
	cbor       bool
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func (o *commonOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&o.configPath, "config", "", "path to edicta.toml (default: the Edicta home)")
	fs.StringVar(&o.gateID, "gate-id", "", "the gate's id (default: gate.gate_id of the config)")
	fs.StringVar(&o.gateKey, "gate-key", "", "hex Ed25519 public key of the gate; the Authorization is verified against it")
	fs.Var(&o.recipients, "recipient", "hex X25519 public key the payload is encrypted to (repeatable, at least one)")
	fs.StringVar(&o.mandateRef, "mandate-ref", "", "hex SHA-256 of the mandate in force, set as mandate_ref")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the bearer token of the API")
	fs.BoolVar(&o.cbor, "cbor", false, "speak application/cbor to the API instead of application/json")
}

// serviceFactory builds the Service; tests replace it so that no request
// touches a network.
var newCommitService = buildCommitService

func runCommit(ctx context.Context, args []string, out io.Writer, stdin io.Reader) int {
	fs := flag.NewFlagSet("commit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o commonOpts
	o.register(fs)
	requestFile := fs.String("request", "", "JSON request file, or - for stdin")
	actionFile := fs.String("action-file", "", "file holding the exact action bytes")
	actionType := fs.String("action-type", "", "action type (media type)")
	contextFile := fs.String("context", "", "JSON file with the decision context")
	model := fs.String("model", "", "model id")
	pol := fs.String("policy", "", "policy id")
	mode := fs.String("mode", "", "fast or strict (default: strict)")
	validFor := fs.String("valid-for", "", "validity of the commitment, a duration such as 10m")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return fail(out, &commitcmd.Failure{Exit: commitcmd.ExitUsage, Code: "usage", Message: err.Error() + "\n" + commitUsage})
	}

	var req commitcmd.Request
	if *requestFile != "" {
		r := stdin
		if *requestFile != "-" {
			f, err := os.Open(*requestFile)
			if err != nil {
				return fail(out, usageErr("%v", err))
			}
			defer f.Close()
			r = f
		}
		var err error
		if req, err = commitcmd.DecodeRequest(r); err != nil {
			return failErr(out, err)
		}
	}
	if *actionFile != "" {
		b, err := os.ReadFile(*actionFile)
		if err != nil {
			return fail(out, usageErr("%v", err))
		}
		req.Action = b
	}
	if *contextFile != "" {
		b, err := os.ReadFile(*contextFile)
		if err != nil {
			return fail(out, usageErr("%v", err))
		}
		req.Context = b
	}
	for _, s := range []struct {
		v   string
		dst *string
	}{{*actionType, &req.ActionType}, {*model, &req.Model.ID}, {*pol, &req.Policy.ID}, {*mode, &req.Mode}, {*validFor, &req.ValidFor}} {
		if s.v != "" {
			*s.dst = s.v
		}
	}

	svc, closeFn, err := newCommitService(ctx, o)
	if err != nil {
		return failErr(out, err)
	}
	defer closeFn()
	resp, err := svc.Commit(ctx, req)
	if err != nil {
		return failErr(out, err)
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fail(out, &commitcmd.Failure{Exit: commitcmd.ExitUsage, Code: "internal", Message: err.Error()})
	}
	fmt.Fprintln(out, string(b))
	return commitcmd.ExitOK
}

func runAgent(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintf(out, "edicta agent: want the subcommand serve\n%s\n", serveUsage)
		return commitcmd.ExitUsage
	}
	fs := flag.NewFlagSet("agent serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o commonOpts
	o.register(fs)
	listen := fs.String("listen", "127.0.0.1:8500", "listen address; loopback only unless --allow-remote")
	allowRemote := fs.Bool("allow-remote", false, "allow a listen address that is not loopback (the service has no authentication)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		fmt.Fprintf(out, "edicta agent serve: %v\n%s\n", err, serveUsage)
		return commitcmd.ExitUsage
	}
	if err := commitcmd.CheckBind(*listen, *allowRemote); err != nil {
		fmt.Fprintf(out, "edicta agent serve: %v\n", err)
		return commitcmd.ExitUsage
	}
	svc, closeFn, err := newCommitService(ctx, o)
	if err != nil {
		return failErr(out, err)
	}
	defer closeFn()
	err = commitcmd.Serve(ctx, *listen, svc, *allowRemote, func(a net.Addr) {
		fmt.Fprintf(out, "edicta agent serve: listening on %s (POST /v1/commit)\n", a)
	})
	if err != nil {
		fmt.Fprintf(out, "edicta agent serve: %v\n", err)
		return commitcmd.ExitUnavailable
	}
	return commitcmd.ExitOK
}

func usageErr(format string, a ...any) *commitcmd.Failure {
	return &commitcmd.Failure{Exit: commitcmd.ExitUsage, Code: "usage", Message: fmt.Sprintf(format, a...)}
}

func failErr(out io.Writer, err error) int {
	var f *commitcmd.Failure
	if !errors.As(err, &f) {
		f = usageErr("%v", err)
	}
	return fail(out, f)
}

func fail(out io.Writer, f *commitcmd.Failure) int {
	b, err := commitcmd.ErrorJSON(f)
	if err != nil {
		fmt.Fprintf(out, "edicta commit: %v\n", f)
		return f.Exit
	}
	fmt.Fprintln(out, string(b))
	return f.Exit
}

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
	priv, err := keyfile.ReadSeed(cfg.Agent.KeyFile, "agent")
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	signer, err := sdk.NewEd25519Signer(priv)
	if err != nil {
		return nil, noop, usageErr("%v", err)
	}
	recipients, err := parseRecipients(o.recipients)
	if err != nil {
		return nil, noop, err
	}
	var mandate [32]byte
	if o.mandateRef != "" {
		b, err := hex.DecodeString(o.mandateRef)
		if err != nil || len(b) != 32 {
			return nil, noop, usageErr("--mandate-ref must be 64 hex characters")
		}
		copy(mandate[:], b)
	}
	var gatePub []byte
	if o.gateKey != "" {
		gatePub, err = hex.DecodeString(o.gateKey)
		if err != nil || len(gatePub) != ed25519.PublicKeySize {
			return nil, noop, usageErr("--gate-key must be 64 hex characters")
		}
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

	fp := &fastPending{cfg: cfg}
	svc := &commitcmd.Service{
		Gate: gateClient, GatePub: gatePub, GateID: gateID,
		Builders: func(mode string, validFor time.Duration) (*sdk.Builder, error) {
			sc := sdk.DefaultConfig()
			sc.AgentID = cfg.Agent.ID
			sc.Scope = commitment.Scope{GateID: gateID}
			sc.Recipients = recipients
			sc.MandateHash = mandate
			sc.SubmitterTrust = sdk.SubmitterSameOperator
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
	if len(in) == 0 {
		return nil, usageErr("at least one --recipient is required")
	}
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
// needs, on the first fast-mode request, so strict mode never dials them.
type fastPending struct {
	cfg  config.Config
	once sync.Once
	pv   sdk.PendingVerifier
	err  error
	rc   io.Closer
}

func (f *fastPending) get(ctx context.Context) (sdk.PendingVerifier, error) {
	f.once.Do(func() { f.pv, f.err = f.open(ctx) })
	return f.pv, f.err
}

func (f *fastPending) close() {
	if f.rc != nil {
		_ = f.rc.Close()
	}
}

func (f *fastPending) open(ctx context.Context) (sdk.PendingVerifier, error) {
	c := f.cfg
	if c.Network.Bridge.Addr == "" {
		return nil, errors.New("fast mode needs network.bridge to check the anchor intent")
	}
	var intents archive.IntentReader
	switch {
	case c.Archive.URL != "":
		cl, err := httparchive.NewClient(c.Archive.URL, &http.Client{Timeout: 30 * time.Second})
		if err != nil {
			return nil, err
		}
		intents = cl
	case c.Archive.Dir != "":
		st, err := fsarchive.OpenReadOnly(c.Archive.Dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
		if err != nil {
			return nil, fmt.Errorf("open archive: %w", err)
		}
		intents = st
	default:
		return nil, errors.New("fast mode needs archive.url or archive.dir to read the anchor intent")
	}
	bc := node.BridgeConfig{Addr: c.Network.Bridge.Addr, TLS: c.Network.Bridge.TLS}
	if tf := c.Network.Bridge.TokenFile; tf != "" {
		s, err := secret.FromFile(tf)
		if err != nil {
			return nil, err
		}
		bc.Token = strings.TrimSpace(s.RevealString())
	}
	rc, reader, err := node.NewReadOnly(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("bridge: %w", err)
	}
	f.rc = rc
	bi, err := gatechain.NewBlobIntents(reader)
	if err != nil {
		return nil, err
	}
	return inclusion.NewPending(inclusion.PendingConfig{Intents: intents, Verifier: bi})
}

