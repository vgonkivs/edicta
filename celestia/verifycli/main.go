// Package verifycli is the verify and replay command line, shared by the
// edicta and edicta-verify commands.
//
//	verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL)
//	    [--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)]
//	    [--checkpoint-quorum N] [--cross-check URL]...
//	    [--receipt FILE [--tx-rpc URL... --check-execution]]
//	    [--skew SECONDS] [--blob-retention SECONDS] [--json]
//
// The archive is only read, never created, locked or cleaned.
//
// Exit codes: 0 valid, 1 invalid, 2 unchecked (inconclusive: a source or an
// input did not let a check run to a result, and the report names the reason
// and the source), 3 not authorized (pending or rejected), 4 usage,
// configuration or I/O errors, which give no verdict, 5 unchecked with the
// gate's integrity violated (signed verdicts of the gate contradict each
// other). The precedence is 4, 1, 5, 3, 2, 0. With --json an error is printed
// as {"error": "..."}.
package verifycli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/verifier"
)

const (
	codeValid         = 0
	codeInvalid       = 1
	codeUnchecked     = 2
	codeNotAuthorized = 3
	codeUsage         = 4
	codeGateIntegrity = 5
)

// maxEvidenceFile bounds one policy evidence file; a signed verdict is at
// most 16384 bytes.
const maxEvidenceFile = 16384

const (
	// maxReceiptFile bounds the receipt file; a signed receipt is a few hundred bytes.
	maxReceiptFile = 1 << 20
	// archiveTimeout bounds one archive read over HTTP.
	archiveTimeout = 5 * time.Minute
	// defaultTimeout bounds a whole run, so a stuck source cannot hang it.
	defaultTimeout = 5 * time.Minute
)

// newAnchors is a variable so tests can replace the chain-facing verifiers.
var newAnchors = func() map[commitment.DA]verifier.AnchorVerifier {
	return map[commitment.DA]verifier.AnchorVerifier{
		commitment.DACelestiaBlob: anchorverify.Blob(),
		commitment.DAFibre:        anchorverify.Fibre(),
	}
}

type usageError struct{ error }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

// Run executes verify or replay; args start with the subcommand. It prints
// the report, or the error, to out and returns the exit code.
func Run(ctx context.Context, args []string, out io.Writer) int {
	code, err := execute(ctx, args, out)
	if err != nil {
		if wantsJSON(args) {
			b, merr := json.Marshal(struct {
				Error string `json:"error"`
			}{err.Error()})
			if merr == nil {
				fmt.Fprintf(out, "%s\n", b)
				return code
			}
		}
		fmt.Fprintf(out, "edicta: %v\n", err)
	}
	return code
}

// wantsJSON looks for the flag before flag parsing, so that a usage error is
// also printed as JSON.
func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if name != "json" || !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "---") {
			continue
		}
		if !hasVal {
			return true
		}
		if b, err := strconv.ParseBool(val); err == nil && b {
			return true
		}
	}
	return false
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// flags is the parsed command line.
type flags struct {
	cmd           string
	hash          commitment.Hash
	gateKeys      []ed25519.PublicKey
	archiveDir    string
	archiveURL    string
	trustedPath   string
	checkpoint    string
	quorum        int
	quorumSet     bool
	excludeHosts  []string
	timeout       time.Duration
	headersRPC    string
	checkpointRPC []string
	crossRPC      []string
	receiptPath   string
	txRPC         []string
	checkExec     bool
	params        commitment.Params
	asJSON        bool
	principalKeys []ed25519.PublicKey
	requirePolicy bool
	policyFull    bool
	policyDepth   int
	evidencePaths []string
}

func parseFlags(args []string, out io.Writer) (flags, error) {
	const usage = "usage: verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) " +
		"[--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)] [--cross-check URL]... [--exclude-host HOST]... " +
		"[--timeout DURATION] [--receipt FILE --tx-rpc URL... --check-execution] " +
		"[--principal-key HEX]... [--require-policy] [--policy-full] [--policy-depth N] [--policy-evidence FILE]... [--json]"
	var f flags
	if len(args) == 0 || (args[0] != "verify" && args[0] != "replay") {
		return f, usagef("%s", usage)
	}
	f.cmd = args[0]
	fs := flag.NewFlagSet(f.cmd, flag.ContinueOnError)
	if wantsJSON(args) {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(out)
	}
	def := commitment.DefaultParams()
	gateKeys := fs.String("gate-key", "", "gate public key, hex; several separated by commas")
	quorum := fs.String("checkpoint-quorum", "1", "operators that must agree on the checkpoint")
	skew := fs.Uint64("skew", def.SkewS, "clock skew the gate allowed, seconds")
	blobRetention := fs.Uint64("blob-retention", def.BlobRetentionS, "blob retention the gate assumed, seconds")
	fs.StringVar(&f.archiveDir, "archive", "", "archive directory")
	fs.StringVar(&f.archiveURL, "archive-url", "", "read-only archive over HTTP")
	fs.StringVar(&f.trustedPath, "trusted", "", "trusted header file")
	fs.StringVar(&f.checkpoint, "checkpoint", "", "explicit checkpoint HEIGHT:HASH, taken out of band")
	fs.StringVar(&f.headersRPC, "headers-rpc", "", "CometBFT RPC that serves the headers between the checkpoint and the anchor")
	fs.StringVar(&f.receiptPath, "receipt", "", "signed receipt file")
	fs.BoolVar(&f.checkExec, "check-execution", false, "check the transaction the receipt names")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "overall time limit of the run")
	fs.BoolVar(&f.asJSON, "json", false, "print one JSON document")
	fs.BoolVar(&f.requirePolicy, "require-policy", false, "the gate had a mandate: a missing policy record is unchecked, not skipped")
	fs.BoolVar(&f.policyFull, "policy-full", false, "walk the verdict chain and search for forks")
	fs.IntVar(&f.policyDepth, "policy-depth", 0, "most hops the policy walk follows (0: the default)")
	var principals multiFlag
	fs.Var(&principals, "principal-key", "trusted mandate principal public key, hex (repeatable; commas also separate keys)")
	var evidence multiFlag
	fs.Var(&evidence, "policy-evidence", "file with a signed policy verdict held by the auditor, for fork detection (repeatable)")
	var ckpt, cross, exclude, txRPC multiFlag
	fs.Var(&txRPC, "tx-rpc", "CometBFT RPC that serves the transaction the receipt names; the first is the primary, more are alternates tried in order")
	fs.Var(&ckpt, "checkpoint-rpc", "CometBFT RPC of an independent checkpoint operator (repeatable)")
	fs.Var(&cross, "cross-check", "CometBFT RPC to cross-check headers and the transaction (repeatable)")
	fs.Var(&exclude, "exclude-host", "host that must not serve as a checkpoint or cross-check source, such as the gate's own endpoint (repeatable)")

	// The hash may stand before, between or after the flags.
	var positional []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			return f, usagef("%v", err)
		}
		consumed := len(rest) - fs.NArg()
		if consumed > 0 && rest[consumed-1] == "--" {
			positional = append(positional, fs.Args()...)
			break
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 {
		return f, usagef("expected one commitment hash")
	}
	var err error
	if f.hash, err = parseHash(positional[0]); err != nil {
		return f, usageError{err}
	}
	if f.gateKeys, err = parseKeys(*gateKeys); err != nil {
		return f, usageError{err}
	}
	if len(principals) > 0 {
		if f.principalKeys, err = parseKeyList(strings.Join(principals, ","), "--principal-key"); err != nil {
			return f, usageError{err}
		}
	}
	f.evidencePaths = evidence
	if f.quorum, err = strconv.Atoi(*quorum); err != nil || f.quorum < 1 {
		return f, usagef("--checkpoint-quorum must be a positive number")
	}
	fs.Visit(func(fl *flag.Flag) { f.quorumSet = f.quorumSet || fl.Name == "checkpoint-quorum" })
	f.checkpointRPC, f.crossRPC, f.excludeHosts, f.txRPC = ckpt, cross, exclude, txRPC
	f.params = def
	f.params.SkewS, f.params.BlobRetentionS = *skew, *blobRetention
	return f, f.validate()
}

// validate refuses the combinations that would leave a flag with no effect,
// so that nobody reads a report as covering something it did not check.
func (f flags) validate() error {
	if (f.archiveDir == "") == (f.archiveURL == "") {
		return usagef("exactly one of --archive and --archive-url is required")
	}
	if f.timeout <= 0 {
		return usagef("--timeout must be positive")
	}
	if f.policyDepth < 0 {
		return usagef("--policy-depth must not be negative")
	}
	online := f.checkpoint != "" || len(f.checkpointRPC) > 0
	switch {
	case f.trustedPath != "" && online:
		return usagef("--trusted cannot be combined with --checkpoint or --checkpoint-rpc")
	case f.checkpoint != "" && len(f.checkpointRPC) > 0:
		return usagef("--checkpoint and --checkpoint-rpc are two ways to name the checkpoint; use one")
	case online && f.headersRPC == "":
		return usagef("--headers-rpc is required with a checkpoint")
	case f.checkpointRPC != nil && f.quorum > len(f.checkpointRPC):
		return usagef("--checkpoint-quorum %d needs at least %d --checkpoint-rpc sources", f.quorum, f.quorum)
	case f.quorumSet && len(f.checkpointRPC) == 0:
		return usagef("--checkpoint-quorum applies only to --checkpoint-rpc sources")
	case f.cmd == "replay" && (f.receiptPath != "" || len(f.txRPC) > 0 || f.checkExec):
		return usagef("replay takes no receipt and no execution check")
	case len(f.txRPC) > 0 && !f.checkExec:
		return usagef("--tx-rpc is used only with --check-execution")
	case f.checkExec && (len(f.txRPC) == 0 || f.receiptPath == ""):
		return usagef("--check-execution needs --receipt and --tx-rpc, or the execution is never checked")
	case f.headersRPC != "" && !online && !f.checkExec:
		return usagef("--headers-rpc is used only with a checkpoint or --check-execution")
	case len(f.crossRPC) > 0 && !online && !f.checkExec:
		return usagef("--cross-check is used only with a checkpoint or --check-execution")
	}
	if f.checkpoint != "" {
		if _, _, err := parseCheckpoint(f.checkpoint); err != nil {
			return usageError{err}
		}
	}
	return f.checkExcluded()
}

// checkExcluded refuses a checkpoint or cross-check source on a host the
// auditor named as not independent, such as the gate's own endpoint.
func (f flags) checkExcluded() error {
	excluded := map[string]bool{}
	for _, h := range f.excludeHosts {
		raw := h
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		name, err := inclusion.SourceHost(raw)
		if err != nil {
			return usagef("--exclude-host %q: %v", h, err)
		}
		excluded[name] = true
	}
	if len(excluded) == 0 {
		return nil
	}
	for _, g := range []struct {
		flag string
		urls []string
	}{{"--checkpoint-rpc", f.checkpointRPC}, {"--cross-check", f.crossRPC}} {
		for _, u := range g.urls {
			name, err := inclusion.SourceHost(u)
			if err != nil {
				continue
			}
			if excluded[name] {
				return usagef("%s %s is on an excluded host", g.flag, u)
			}
		}
	}
	return nil
}

func execute(ctx context.Context, args []string, out io.Writer) (int, error) {
	f, err := parseFlags(args, out)
	if err != nil {
		return codeUsage, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	reader, err := openArchive(f.archiveDir, f.archiveURL)
	if err != nil {
		return codeUsage, usageError{err}
	}
	online := f.checkpoint != "" || len(f.checkpointRPC) > 0
	var rec *recordingReader
	if online {
		rec = newRecordingReader(reader)
		reader = rec
	}
	deps, err := buildDeps(reader, f.gateKeys, f.params)
	if err != nil {
		return codeUsage, usageError{err}
	}
	deps.Config.PrincipalKeys = f.principalKeys
	deps.Config.RequirePolicy = f.requirePolicy
	deps.Config.PolicyFull = f.policyFull
	deps.Config.PolicyDepth = f.policyDepth
	for _, path := range f.evidencePaths {
		b, err := readFileCapped(path, maxEvidenceFile)
		if err != nil {
			return codeUsage, usageError{fmt.Errorf("policy evidence: %w", err)}
		}
		deps.Config.Evidence = append(deps.Config.Evidence, b)
	}
	if deps.Extractors, err = newExtractors(); err != nil {
		return codeUsage, usageError{err}
	}

	info := &trustInfo{}
	var opts []verifier.Option
	switch {
	case f.trustedPath != "":
		trust, err := loadTrusted(f.trustedPath)
		if err != nil {
			return codeUsage, usageError{err}
		}
		deps.Trust = trust
		info.mode = "file"
	case online:
		lt, err := newLazyTrust(rec, f, info)
		if err != nil {
			return codeUsage, usageError{err}
		}
		deps.Trust = lt
	}

	if f.receiptPath != "" {
		b, err := readFileCapped(f.receiptPath, maxReceiptFile)
		if err != nil {
			return codeUsage, usageError{fmt.Errorf("receipt: %w", err)}
		}
		opts = append(opts, verifier.WithReceipt(b))
	}
	if f.checkExec {
		opts = append(opts, verifier.WithExecutionCheck())
		if len(f.txRPC) > 0 {
			chk, err := newBankChecker(f.txRPC, f.headersRPC, f.crossRPC, deps.Trust, info)
			if err != nil {
				return codeUsage, usageError{err}
			}
			deps.Executions = map[string]verifier.ExecutionChecker{bankaction.ActionType: chk}
		}
	}
	v, err := verifier.New(deps)
	if err != nil {
		return codeUsage, usageError{err}
	}

	var view reportView
	var code int
	if f.cmd == "verify" {
		rep, err := v.Verify(ctx, f.hash, opts...)
		if err != nil {
			return codeUsage, err
		}
		view = viewOf(rep)
		code = codeFor(rep)
	} else {
		rr, err := v.Replay(ctx, f.hash)
		if err != nil {
			return codeUsage, err
		}
		view = viewOf(rr.Report)
		k := viewOfK2(rr.K2)
		view.K2 = &k
		code = codeFor(rr.Report)
	}
	info.apply(&view)

	if f.asJSON {
		if err := writeJSON(out, view); err != nil {
			return codeUsage, err
		}
		return code, nil
	}
	writeText(out, view, isTerminal(out))
	return code, nil
}

func readFileCapped(path string, limit int64) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file is too large")
	}
	return b, nil
}

func codeFor(r verifier.Report) int {
	switch r.Verdict {
	case verifier.VerdictValid:
		return codeValid
	case verifier.VerdictUnchecked:
		if r.GateIntegrity.Status == verifier.IntegrityViolated {
			return codeGateIntegrity
		}
		return codeUnchecked
	case verifier.VerdictNotAuthorized:
		return codeNotAuthorized
	}
	return codeInvalid
}

func parseHash(s string) (commitment.Hash, error) {
	var h commitment.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, errors.New("commitment hash must be 64 hex characters")
	}
	copy(h[:], b)
	return h, nil
}

func parseKeys(s string) ([]ed25519.PublicKey, error) {
	if s == "" {
		return nil, errors.New("--gate-key is required")
	}
	return parseKeyList(s, "--gate-key")
}

func parseKeyList(s, flag string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, part := range strings.Split(s, ",") {
		b, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s must be 64 hex characters per key", flag)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	return keys, nil
}

// newExtractors is a variable so that tests can replace it. Only tia-transfer
// is registered: an action type without an extractor makes its policy check
// unchecked (policy_no_extractor).
var newExtractors = func() (*policy.Extractors, error) { return policy.NewExtractors(tiatransfer.New()) }

func committers() (map[commitment.DA]gate.DACommitter, error) {
	fibreCommitter, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	if err != nil {
		return nil, err
	}
	return map[commitment.DA]gate.DACommitter{
		commitment.DACelestiaBlob: blobv1.New(),
		commitment.DAFibre:        fibreCommitter,
	}, nil
}

func openArchive(dir, url string) (verifier.Reader, error) {
	if url != "" {
		return httparchive.NewClient(url, &http.Client{Timeout: archiveTimeout})
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("archive %q is not a directory", dir)
	}
	cm, err := committers()
	if err != nil {
		return nil, err
	}
	store, err := fsarchive.OpenReadOnly(dir, cm)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	return store, nil
}

func buildDeps(r verifier.Reader, keys []ed25519.PublicKey, params commitment.Params) (verifier.Deps, error) {
	cm, err := committers()
	if err != nil {
		return verifier.Deps{}, err
	}
	return verifier.Deps{
		Config:     verifier.Config{Params: params, GateKeys: keys},
		Archive:    r,
		Committers: cm,
		Anchors:    newAnchors(),
	}, nil
}
