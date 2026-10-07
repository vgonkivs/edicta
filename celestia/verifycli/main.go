// Package verifycli is the verify and replay command line, shared by the
// edicta and edicta-verify commands.
//
//	verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL)
//	    [--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)]
//	    [--checkpoint-quorum N] [--cross-check URL]...
//	    [--receipt FILE [--tx-rpc URL --check-execution]]
//	    [--skew SECONDS] [--blob-retention SECONDS] [--json]
//
// The archive is only read, never created, locked or cleaned.
//
// Exit codes: 0 valid, 1 invalid, 2 unchecked (something could not be
// checked, such as no trusted header), 3 not authorized (pending or
// rejected), 4 usage, configuration or I/O errors, which give no verdict.
// With --json an error is printed as {"error": "..."}.
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
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/verifier"
)

const (
	codeValid         = 0
	codeInvalid       = 1
	codeUnchecked     = 2
	codeNotAuthorized = 3
	codeUsage         = 4
)

const (
	// maxReceiptFile bounds the receipt file; a signed receipt is a few hundred bytes.
	maxReceiptFile = 1 << 20
	// archiveTimeout bounds one archive read over HTTP.
	archiveTimeout = 5 * time.Minute
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
	headersRPC    string
	checkpointRPC []string
	crossRPC      []string
	receiptPath   string
	txRPC         string
	checkExec     bool
	params        commitment.Params
	asJSON        bool
}

func parseFlags(args []string, out io.Writer) (flags, error) {
	const usage = "usage: verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) " +
		"[--trusted FILE | --headers-rpc URL (--checkpoint H:HASH | --checkpoint-rpc URL...)] [--cross-check URL]... " +
		"[--receipt FILE --tx-rpc URL --check-execution] [--json]"
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
	fs.StringVar(&f.txRPC, "tx-rpc", "", "CometBFT RPC that serves the transaction the receipt names")
	fs.BoolVar(&f.checkExec, "check-execution", false, "check the transaction the receipt names")
	fs.BoolVar(&f.asJSON, "json", false, "print one JSON document")
	var ckpt, cross multiFlag
	fs.Var(&ckpt, "checkpoint-rpc", "CometBFT RPC of an independent checkpoint operator (repeatable)")
	fs.Var(&cross, "cross-check", "CometBFT RPC to cross-check headers and the transaction (repeatable)")

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
	if f.quorum, err = strconv.Atoi(*quorum); err != nil || f.quorum < 1 {
		return f, usagef("--checkpoint-quorum must be a positive number")
	}
	f.checkpointRPC, f.crossRPC = ckpt, cross
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
	case f.cmd == "replay" && (f.receiptPath != "" || f.txRPC != "" || f.checkExec):
		return usagef("replay takes no receipt and no execution check")
	case f.txRPC != "" && !f.checkExec:
		return usagef("--tx-rpc is used only with --check-execution")
	}
	if f.checkpoint != "" {
		if _, _, err := parseCheckpoint(f.checkpoint); err != nil {
			return usageError{err}
		}
	}
	return nil
}

func execute(ctx context.Context, args []string, out io.Writer) (int, error) {
	f, err := parseFlags(args, out)
	if err != nil {
		return codeUsage, err
	}
	reader, err := openArchive(f.archiveDir, f.archiveURL)
	if err != nil {
		return codeUsage, usageError{err}
	}
	deps, err := buildDeps(reader, f.gateKeys, f.params)
	if err != nil {
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
	case f.checkpoint != "" || len(f.checkpointRPC) > 0:
		lt, err := newLazyTrust(reader, f, info)
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
		if f.txRPC != "" {
			chk, err := newBankChecker(f.txRPC, f.headersRPC, f.crossRPC)
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
		code = codeFor(rep.Verdict)
	} else {
		rr, err := v.Replay(ctx, f.hash)
		if err != nil {
			return codeUsage, err
		}
		view = viewOf(rr.Report)
		k := viewOfK2(rr.K2)
		view.K2 = &k
		code = codeFor(rr.Report.Verdict)
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

func codeFor(v verifier.Verdict) int {
	switch v {
	case verifier.VerdictValid:
		return codeValid
	case verifier.VerdictUnchecked:
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
	var keys []ed25519.PublicKey
	for _, part := range strings.Split(s, ",") {
		b, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("--gate-key must be 64 hex characters per key")
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	return keys, nil
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
