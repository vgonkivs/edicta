// SPDX-License-Identifier: Apache-2.0

package clicmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/vgonkivs/edicta/internal/secret"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

const commitFlags = "[--config PATH] [--gate-id ID] [--gate-key HEX]... [--recipient X25519_HEX]... [--mandate-ref HEX] [--token-file FILE] [--cbor]" +
	" [--state-dir DIR] [--signer-url URL --signer-token-file FILE]"

const commitUsage = "usage: edicta commit " + commitFlags +
	" [--request FILE|-] [--action-file FILE] [--action-type TYPE] [--context FILE] [--model ID] [--policy ID] [--mode fast|strict] [--valid-for 10m]" +
	"\n  eden: --eden-build FILE|- --payment-required HEADER_B64|@FILE [--resource https://URL] [--sign --broadcast] [--record] [--payment-signature] [--wait 5m]" +
	"\n  resume: --resume-hash HEX (needs --state-dir)"

const serveUsage = "usage: edicta agent serve " + commitFlags + " [--listen 127.0.0.1:8500] [--allow-remote --serve-token-file FILE --allowed-host HOST:PORT... [--allowed-origin URL]...]"

// commonOpts are the flags `commit` and `agent serve` share.
type commonOpts struct {
	configPath string
	gateID     string
	gateKeys   stringList
	recipients stringList
	mandateRef string
	tokenFile  string
	cbor       bool
	// stateDir keeps each run by commitment hash for resume.
	stateDir string
	// signerURL and signerTokenFile reach edicta-signer; the token is the
	// agent's own credential there.
	signerURL       string
	signerTokenFile string

	// serve only
	serveTokenFile string
	allowedHosts   stringList
	allowedOrigins stringList
	allowRemote    bool
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func (o *commonOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&o.configPath, "config", "", "path to edicta.toml (default: the Edicta home)")
	fs.StringVar(&o.gateID, "gate-id", "", "the gate's id (default: gate.gate_id of the config)")
	fs.Var(&o.gateKeys, "gate-key", "hex Ed25519 public key of the gate (repeatable; default: agent.gate_keys, then signer.pinned_gate_keys)")
	fs.Var(&o.recipients, "recipient", "hex X25519 public key the payload is encrypted to (repeatable, at least one)")
	fs.StringVar(&o.mandateRef, "mandate-ref", "", "hex SHA-256 of the mandate in force, set as mandate_ref")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the bearer token of the API")
	fs.BoolVar(&o.cbor, "cbor", false, "speak application/cbor to the API instead of application/json")
	fs.StringVar(&o.stateDir, "state-dir", "", "directory that keeps each run by commitment hash, for resume")
	fs.StringVar(&o.signerURL, "signer-url", "", "base URL of the signer, edicta signer serve or edicta-signer (eden sign, record and payment-signature)")
	fs.StringVar(&o.signerTokenFile, "signer-token-file", "", "file holding the agent's API token at the signer")
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
	edenBuild := fs.String("eden-build", "", "the /deposit/build JSON, a file or - for stdin (eden input)")
	paymentRequired := fs.String("payment-required", "", "the PAYMENT-REQUIRED header value (base64), or @FILE holding it")
	resource := fs.String("resource", "", "the https URL the client calls (default: the quote's own when it is https)")
	doSign := fs.Bool("sign", false, "ask the signer for the deposit")
	doBroadcast := fs.Bool("broadcast", false, "the signer sends the signed deposit (required with --sign: it sends when it signs)")
	doRecord := fs.Bool("record", false, "wait until the signer reports the deposit executed")
	doPaySig := fs.Bool("payment-signature", false, "print the Payment-Signature once the signer releases it")
	wait := fs.String("wait", "", "bound of --record and --payment-signature, a duration such as 5m")
	resumeHash := fs.String("resume-hash", "", "continue the run stored under this commitment hash")
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

	if *edenBuild != "" || *paymentRequired != "" || *resource != "" {
		if req.Eden == nil {
			req.Eden = &commitcmd.EdenInput{}
		}
		if *edenBuild != "" {
			if *edenBuild == "-" && *requestFile == "-" {
				return fail(out, usageErr("--request - and --eden-build - both read stdin"))
			}
			b, err := readInput(*edenBuild, stdin, edenescrow.MaxBuildBodySize)
			if err != nil {
				return fail(out, usageErr("--eden-build: %v", err))
			}
			req.Eden.Build = b
		}
		if *paymentRequired != "" {
			v := *paymentRequired
			if name, ok := strings.CutPrefix(v, "@"); ok {
				if name == "-" && (*edenBuild == "-" || *requestFile == "-") {
					return fail(out, usageErr("--payment-required @- and another input both read stdin"))
				}
				b, err := readInput(name, stdin, edenescrow.MaxRequirementsSize*2)
				if err != nil {
					return fail(out, usageErr("--payment-required: %v", err))
				}
				v = strings.TrimSpace(string(b))
			}
			req.Eden.PaymentRequired = v
		}
		if *resource != "" {
			req.Eden.Resource = *resource
		}
	}
	req.Sign, req.Broadcast = req.Sign || *doSign, req.Broadcast || *doBroadcast
	req.Record, req.PaymentSignature = req.Record || *doRecord, req.PaymentSignature || *doPaySig
	if *wait != "" {
		req.Wait = *wait
	}
	if *resumeHash != "" {
		req.ResumeHash = *resumeHash
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

// readInput reads a file, or stdin for "-", at most limit bytes.
func readInput(name string, stdin io.Reader, limit int) ([]byte, error) {
	r := stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("more than %d bytes", limit)
	}
	return b, nil
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
	fs.BoolVar(&o.allowRemote, "allow-remote", false, "allow a listen address that is not loopback; needs --serve-token-file and --allowed-host")
	fs.StringVar(&o.serveTokenFile, "serve-token-file", "", "file holding the bearer token callers must present (remote mode)")
	fs.Var(&o.allowedHosts, "allowed-host", "accepted Host header value, host:port (remote mode, repeatable)")
	fs.Var(&o.allowedOrigins, "allowed-origin", "accepted Origin value (remote mode, repeatable)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		fmt.Fprintf(out, "edicta agent serve: %v\n%s\n", err, serveUsage)
		return commitcmd.ExitUsage
	}
	sopts := commitcmd.Options{AllowRemote: o.allowRemote, AllowedHosts: o.allowedHosts, AllowedOrigins: o.allowedOrigins}
	if o.serveTokenFile != "" {
		tok, err := secret.FromFile(o.serveTokenFile)
		if err != nil {
			fmt.Fprintf(out, "edicta agent serve: %v\n", err)
			return commitcmd.ExitUsage
		}
		sopts.Token = []byte(strings.TrimSpace(tok.RevealString()))
	}
	if err := commitcmd.CheckBind(*listen, o.allowRemote); err != nil {
		fmt.Fprintf(out, "edicta agent serve: %v\n", err)
		return commitcmd.ExitUsage
	}
	if err := sopts.ValidateBasic(); err != nil {
		fmt.Fprintf(out, "edicta agent serve: %v\n", err)
		return commitcmd.ExitUsage
	}
	svc, closeFn, err := newCommitService(ctx, o)
	if err != nil {
		return failErr(out, err)
	}
	defer closeFn()
	err = commitcmd.Serve(ctx, *listen, svc, sopts, func(a net.Addr) {
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
