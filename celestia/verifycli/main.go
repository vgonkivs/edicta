// Package verifycli is the verify and replay command line, shared by the
// edicta and edicta-verify commands.
//
//	verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL)
//	    [--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)]
//	    [--checkpoint-quorum N] [--cross-check URL]...
//	    [--receipt FILE [--tx-rpc URL... --check-execution [--result-archive DIR|URL]...]]
//	    [--absence-source URL] [--skew SECONDS] [--blob-retention SECONDS] [--json]
//	    [--settlement --receipt FILE (--settlement-rpc URL | --settlement-own-rpc URL)...
//	     [--settlement-da URL] [--settlement-level L0|L1|L2] [--settlement-min-sources N]
//	     [--settlement-confirm-depth N]]
//	absence <commitment_hash> --gate-key HEX --archive DIR --absence-source URL
//	    (--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)) [--json]
//
// absence fetches the absence proofs of a pending reference's window from a
// bridge node, verifies each against the trusted chain and writes those that
// verify to the archive as kind 14 records. It exits 0 when every height is
// proven, 2 otherwise.
//
// The archive is only read, never created, locked or cleaned. So are the
// further copies of --result-archive, which the execution check reads for
// archived execution results after the archive, in the order given.
//
// Exit codes: 0 valid, 1 invalid, 2 unchecked (inconclusive: a source or an
// input did not let a check run to a result, and the report names the reason
// and the source), 3 not authorized (pending or rejected), 4 usage,
// configuration or I/O errors, which give no verdict, 5 unchecked with the
// gate's integrity violated (signed verdicts of the gate contradict each
// other). The precedence is 4, 1, 5, 3, 2, 0. With --json an error is printed
// as {"error": "..."}.
//
// --settlement adds the Eden profile's settlement report (rail_settlement):
// whether the transaction the receipt names is the authorized deposit and
// landed. It is printed beside the core report and never changes the verdict
// or the exit code.
package verifycli

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
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/policyext/tiatransfer"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk/blob"
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
	return RunWith(ctx, args, out, nil)
}

// RunWith is Run with a loader of defaults. A non-nil load adds --config PATH;
// load is called with the path (empty when the flag is absent) and returns the
// defaults of the flags the user did not pass.
func RunWith(ctx context.Context, args []string, out io.Writer, load DefaultsLoader) int {
	code, err := execute(ctx, args, out, load)
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
	principalKeys []policy.PrincipalID
	requirePolicy bool
	policyFull    bool
	maxWalkSteps  int
	evidencePaths []string
	auditorKeys   []string
	absenceSource string
	execChainID   string
	// resultArchives are further archive copies, directories or URLs,
	// read for archived execution results only.
	resultArchives []string
	settle         settlementFlags
}

func parseFlags(args []string, out io.Writer) (flags, error) { return parseFlagsWith(args, out, nil) }

func parseFlagsWith(args []string, out io.Writer, load DefaultsLoader) (flags, error) {
	const usage = "usage: verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) " +
		"[--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)] [--cross-check URL]... [--exclude-host HOST]... " +
		"[--timeout DURATION] [--receipt FILE --tx-rpc URL... --check-execution [--exec-chain-id ID] [--result-archive DIR|URL]...] " +
		"[--principal-key HEX]... [--principal ed25519:HEX|cosmos:BECH32|eth:0xHEX]... [--require-policy] [--policy-full] [--max-walk-steps N] [--policy-evidence FILE]... [--auditor-key FILE]... [--absence-source URL] [--json] " +
		"[--settlement (--settlement-rpc URL | --settlement-own-rpc URL)... [--settlement-da URL] [--settlement-level L0|L1|L2] [--settlement-min-sources N] [--settlement-confirm-depth N]]\n" +
		"       absence <commitment_hash> --gate-key HEX --archive DIR --absence-source URL (--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)) [--json]"
	var f flags
	if len(args) == 0 || (args[0] != "verify" && args[0] != "replay" && args[0] != "absence") {
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
	fs.StringVar(&f.absenceSource, "absence-source", "", "bridge node JSON-RPC URL that serves absence proofs of a pending reference; block results come from --headers-rpc")
	fs.BoolVar(&f.checkExec, "check-execution", false, "check the transaction the receipt names")
	fs.StringVar(&f.execChainID, "exec-chain-id", "", "chain id the bank-send profile rebuilds a revealed private action for; default the chain id of the trusted header at the reference height")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "overall time limit of the run")
	fs.BoolVar(&f.asJSON, "json", false, "print one JSON document")
	fs.BoolVar(&f.requirePolicy, "require-policy", false, "the gate had a mandate: a missing policy record is unchecked, not skipped")
	fs.BoolVar(&f.policyFull, "policy-full", false, "walk the verdict chain and search for forks")
	fs.IntVar(&f.maxWalkSteps, "max-walk-steps", verifier.DefaultMaxWalkSteps, "most steps the policy walk takes toward genesis (at least 1)")
	fs.IntVar(&f.maxWalkSteps, "policy-depth", verifier.DefaultMaxWalkSteps, "alias of --max-walk-steps")
	var principals multiFlag
	fs.Var(&principals, "principal-key", "trusted Ed25519 mandate principal public key, hex (repeatable; commas also separate keys)")
	var typedPrincipals multiFlag
	fs.Var(&typedPrincipals, "principal", "trusted mandate principal by scheme: ed25519:HEX, cosmos:BECH32 or eth:0xHEX (repeatable; commas also separate)")
	var evidence multiFlag
	fs.Var(&evidence, "policy-evidence", "file with a signed policy verdict held by the auditor, for fork detection (repeatable)")
	var auditorKeys multiFlag
	fs.Var(&auditorKeys, "auditor-key", "file with an X25519 auditor private key, hex, mode 0600, that opens private mandates (repeatable)")
	var cfgPath *string
	if load != nil {
		cfgPath = fs.String("config", "", "path of edicta.toml; its values stand in for the flags not given (default: the Edicta home, skipped when absent)")
	}
	fs.BoolVar(&f.settle.on, "settlement", false, "add the Eden settlement report of the transaction the receipt names; it never changes the verdict")
	var settleRPC, settleOwn multiFlag
	fs.Var(&settleRPC, "settlement-rpc", "Eden JSON-RPC of a public operator for --settlement (repeatable, one per host)")
	fs.Var(&settleOwn, "settlement-own-rpc", "Eden JSON-RPC of the operator's own node for --settlement, asked first (repeatable)")
	fs.StringVar(&f.settle.da, "settlement-da", "", "the operator's own ev-node RPC, for whether the block's data is in Celestia (report only)")
	fs.StringVar(&f.settle.level, "settlement-level", "", "level a settlement pass needs: L0, L1 or L2 (default L1: two operators agree)")
	fs.IntVar(&f.settle.sources, "settlement-min-sources", 0, "agreeing operators that make L1 (default 2)")
	fs.Uint64Var(&f.settle.depth, "settlement-confirm-depth", 0, "Eden blocks that must follow the transaction's (default 20)")
	var ckpt, cross, exclude, txRPC, resultArchives multiFlag
	fs.Var(&resultArchives, "result-archive", "further archive copy, a directory or an http(s) URL, that the execution check reads for archived execution results after the archive (repeatable)")
	fs.Var(&txRPC, "tx-rpc", "CometBFT RPC that serves the transaction the receipt names; the first is the primary, more are alternates tried in order")
	fs.Var(&ckpt, "checkpoint-rpc", "CometBFT RPC of an independent checkpoint operator (repeatable)")
	fs.Var(&cross, "cross-check", "CometBFT RPC to cross-check headers and the transaction (repeatable)")
	fs.Var(&exclude, "exclude-host", "host that must not serve as a checkpoint, cross-check or settlement source, such as the gate's own endpoint (repeatable)")

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
	given := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
	var d Defaults
	if load != nil {
		if d, err = load(*cfgPath); err != nil {
			return f, usageError{err}
		}
		if !given["gate-key"] {
			*gateKeys = d.GateKeys
		}
	}
	if f.gateKeys, err = parseKeys(*gateKeys); err != nil {
		return f, usageError{err}
	}
	if len(principals) > 0 {
		keys, err := parseKeyList(strings.Join(principals, ","), "--principal-key")
		if err != nil {
			return f, usageError{err}
		}
		for _, k := range keys {
			f.principalKeys = append(f.principalKeys, policy.PrincipalID{Principal: k})
		}
	}
	for _, s := range typedPrincipals {
		for _, part := range strings.Split(s, ",") {
			id, err := policy.ParsePrincipal(strings.TrimSpace(part))
			if err != nil {
				return f, usagef("--principal: %v", err)
			}
			f.principalKeys = append(f.principalKeys, id)
		}
	}
	f.evidencePaths = evidence
	f.auditorKeys = auditorKeys
	if f.quorum, err = strconv.Atoi(*quorum); err != nil || f.quorum < 1 {
		return f, usagef("--checkpoint-quorum must be a positive number")
	}
	fs.Visit(func(fl *flag.Flag) { f.quorumSet = f.quorumSet || fl.Name == "checkpoint-quorum" })
	f.checkpointRPC, f.crossRPC, f.excludeHosts, f.txRPC = ckpt, cross, exclude, txRPC
	f.resultArchives = resultArchives
	f.settle.rpc, f.settle.ownRPC = settleRPC, settleOwn
	f.params = def
	f.params.SkewS, f.params.BlobRetentionS = *skew, *blobRetention
	f.applyDefaults(d, given)
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
	if f.maxWalkSteps < 1 {
		return usagef("--max-walk-steps must be at least 1")
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
	case f.execChainID != "" && !f.checkExec:
		return usagef("--exec-chain-id is used only with --check-execution")
	case len(f.resultArchives) > 0 && !f.checkExec:
		return usagef("--result-archive is used only with --check-execution")
	case f.checkExec && (len(f.txRPC) == 0 || f.receiptPath == ""):
		return usagef("--check-execution needs --receipt and --tx-rpc, or the execution is never checked")
	case f.cmd == "absence" && (f.archiveDir == "" || f.absenceSource == ""):
		return usagef("absence needs --archive DIR, which it writes, and --absence-source")
	case f.cmd == "absence" && f.trustedPath == "" && !online:
		return usagef("absence needs --trusted or a checkpoint: every proof is checked against the trusted chain")
	case f.cmd == "absence" && (f.receiptPath != "" || len(f.txRPC) > 0 || f.checkExec):
		return usagef("absence takes no receipt and no execution check")
	case f.headersRPC != "" && !online && !f.checkExec && f.absenceSource == "":
		return usagef("--headers-rpc is used only with a checkpoint, --check-execution or --absence-source")
	case len(f.crossRPC) > 0 && !online && !f.checkExec:
		return usagef("--cross-check is used only with a checkpoint or --check-execution")
	}
	if f.checkpoint != "" {
		if _, _, err := parseCheckpoint(f.checkpoint); err != nil {
			return usageError{err}
		}
	}
	if err := f.settle.validate(f.cmd, f.receiptPath); err != nil {
		return err
	}
	return f.checkExcluded()
}

// checkExcluded refuses a checkpoint, cross-check or settlement source on a
// host the auditor named as not independent, such as the gate's own
// endpoint.
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
	}{
		{"--checkpoint-rpc", f.checkpointRPC}, {"--cross-check", f.crossRPC},
		{"--settlement-rpc", f.settle.rpc}, {"--settlement-own-rpc", f.settle.ownRPC}, {"--settlement-da", nonEmpty(f.settle.da)},
	} {
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

func execute(ctx context.Context, args []string, out io.Writer, load DefaultsLoader) (int, error) {
	f, err := parseFlagsWith(args, out, load)
	if err != nil {
		return codeUsage, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	if f.cmd == "absence" {
		return runAbsence(ctx, f, out)
	}
	reader, err := openArchive(f.archiveDir, f.archiveURL)
	if err != nil {
		return codeUsage, usageError{err}
	}
	fetch, closeFetch, err := absenceFetcher(ctx, f)
	if err != nil {
		return codeUsage, usageError{err}
	}
	defer closeFetch()
	base := reader
	window := &windowHeaders{fetch: fetch}
	if ar, ok := base.(archive.AbsenceReader); ok {
		window.r = ar
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
	if deps.ResultCopies, err = openResultCopies(f.resultArchives); err != nil {
		return codeUsage, usageError{err}
	}
	deps.Config.PrincipalKeys = f.principalKeys
	deps.Config.RequirePolicy = f.requirePolicy
	deps.Config.PolicyFull = f.policyFull
	deps.Config.MaxWalkSteps = f.maxWalkSteps
	for _, path := range f.evidencePaths {
		b, err := readFileCapped(path, maxEvidenceFile)
		if err != nil {
			return codeUsage, usageError{fmt.Errorf("policy evidence: %w", err)}
		}
		deps.Config.Evidence = append(deps.Config.Evidence, b)
	}
	for _, path := range f.auditorKeys {
		k, err := loadAuditorKey(path)
		if err != nil {
			return codeUsage, usageError{err}
		}
		deps.Config.AuditorKeys = append(deps.Config.AuditorKeys, k)
	}
	if deps.Extractors, err = newExtractors(); err != nil {
		return codeUsage, usageError{err}
	}

	info := &trustInfo{}
	var opts []verifier.Option
	switch {
	case f.trustedPath != "":
		trust, err := loadTrusted(f.trustedPath, window)
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
		lt.window = window
		deps.Trust = lt
	}
	var headers absence.HeaderSource
	if f.headersRPC != "" {
		src, err := cometrpc.New(f.headersRPC, nil)
		if err != nil {
			return codeUsage, usageError{err}
		}
		headers = src
	}
	deps.Pending = newPendingChain(base, headers, fetch, window)

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
			chk, err := newBankChecker(f.txRPC, f.headersRPC, f.crossRPC, deps.Trust, info, f.execChainID)
			if err != nil {
				return codeUsage, usageError{err}
			}
			deps.Executions = map[string]verifier.ExecutionChecker{bankaction.ActionType: chk}
		}
	}
	if f.settle.on {
		if deps.Settlements, err = newSettlements(f.settle); err != nil {
			return codeUsage, usageError{err}
		}
		opts = append(opts, verifier.WithSettlement())
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

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
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

// newExtractors is a variable so that tests can replace it. It registers the
// same extractors as the gate of the same build: tia-transfer and the Eden
// escrow deposit. An action type without an extractor makes its policy check
// unchecked (policy_no_extractor); so does a dev decision in a production
// build, whose extractor ID only an edictadev build registers.
var newExtractors = func() (*policy.Extractors, error) {
	return policy.NewExtractors(tiatransfer.New(), edenescrow.New())
}

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

// openResultCopies opens each --result-archive value as the main archive
// flags would: a value with a scheme is a URL, any other a directory. The
// value names the copy in the report.
func openResultCopies(values []string) ([]verifier.ResultCopy, error) {
	var out []verifier.ResultCopy
	for i, v := range values {
		if slices.Contains(values[:i], v) {
			return nil, fmt.Errorf("--result-archive %q is given twice", v)
		}
		dir, url := v, ""
		if strings.Contains(v, "://") {
			dir, url = "", v
		}
		r, err := openArchive(dir, url)
		if err != nil {
			return nil, fmt.Errorf("--result-archive: %w", err)
		}
		er, ok := r.(archive.ExecResultReader)
		if !ok {
			return nil, fmt.Errorf("--result-archive %q cannot hold execution results", v)
		}
		out = append(out, verifier.ResultCopy{Name: v, Reader: er})
	}
	return out, nil
}

// loadAuditorKey reads an X25519 private key in hex from a file that only
// its owner can read. The key bytes never appear in an error.
func loadAuditorKey(path string) (blob.RecipientKey, error) {
	s, err := secret.FromFile(path)
	if err != nil {
		return blob.RecipientKey{}, fmt.Errorf("--auditor-key: %w", err)
	}
	defer s.Zero()
	text := strings.TrimSpace(s.RevealString())
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return blob.RecipientKey{}, fmt.Errorf("--auditor-key %q: not 32 bytes of hex", path)
	}
	defer clear(raw)
	sk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return blob.RecipientKey{}, fmt.Errorf("--auditor-key %q: not an X25519 private key", path)
	}
	return blob.NewRecipientKey(sk)
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
