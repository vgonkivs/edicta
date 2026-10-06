// Command edicta-verify re-checks an archived decision offline.
//
//	edicta-verify verify|replay --archive DIR --gate-key HEX [--trusted FILE]
//	    [--skew SECONDS] [--blob-retention SECONDS] [--json] <commitment_hash>
//
// The archive is only read, never created, locked or cleaned.
//
// Exit codes: 0 valid, 1 invalid, 2 unchecked (something could not be
// checked, such as no trusted header), 3 not authorized (pending or
// rejected), 4 usage or unreadable input. With --json an error is printed as
// {"error": "..."}.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/commitment"
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

// newAnchors is a variable so tests can replace the chain-facing verifiers.
var newAnchors = func() map[commitment.DA]verifier.AnchorVerifier {
	return map[commitment.DA]verifier.AnchorVerifier{
		commitment.DACelestiaBlob: anchorverify.Blob(),
		commitment.DAFibre:        anchorverify.Fibre(),
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

type usageError struct{ error }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

func run(args []string, out io.Writer) int {
	code, err := execute(args, out)
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
		fmt.Fprintf(out, "edicta-verify: %v\n", err)
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

func execute(args []string, out io.Writer) (int, error) {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "replay") {
		return codeUsage, usagef("usage: edicta-verify verify|replay --archive DIR --gate-key HEX [--trusted FILE] [--skew SECONDS] [--blob-retention SECONDS] [--json] <commitment_hash>")
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	if wantsJSON(args) {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(out)
	}
	def := commitment.DefaultParams()
	archiveDir := fs.String("archive", "", "archive directory")
	gateKeys := fs.String("gate-key", "", "gate public key, hex; several separated by commas")
	trustedPath := fs.String("trusted", "", "trusted header file")
	skew := fs.Uint64("skew", def.SkewS, "clock skew the gate allowed, seconds")
	blobRetention := fs.Uint64("blob-retention", def.BlobRetentionS, "blob retention the gate assumed, seconds")
	asJSON := fs.Bool("json", false, "print one JSON document")
	if err := fs.Parse(args[1:]); err != nil {
		return codeUsage, usagef("%v", err)
	}
	if fs.NArg() != 1 {
		return codeUsage, usagef("expected one commitment hash")
	}
	h, err := parseHash(fs.Arg(0))
	if err != nil {
		return codeUsage, usageError{err}
	}
	keys, err := parseKeys(*gateKeys)
	if err != nil {
		return codeUsage, usageError{err}
	}
	if *archiveDir == "" {
		return codeUsage, usagef("--archive is required")
	}
	if st, err := os.Stat(*archiveDir); err != nil || !st.IsDir() {
		return codeUsage, usagef("archive %q is not a directory", *archiveDir)
	}

	params := def
	params.SkewS, params.BlobRetentionS = *skew, *blobRetention
	deps, err := buildDeps(*archiveDir, keys, *trustedPath, params)
	if err != nil {
		return codeUsage, usageError{err}
	}
	v, err := verifier.New(deps)
	if err != nil {
		return codeUsage, usageError{err}
	}

	ctx := context.Background()
	var view reportView
	var code int
	if cmd == "verify" {
		rep, err := v.Verify(ctx, h)
		if err != nil {
			return codeUsage, err
		}
		view = viewOf(rep)
		code = codeFor(rep.Verdict)
	} else {
		rr, err := v.Replay(ctx, h)
		if err != nil {
			return codeUsage, err
		}
		view = viewOf(rr.Report)
		k := viewOfK2(rr.K2)
		view.K2 = &k
		code = codeFor(rr.Report.Verdict)
	}

	if *asJSON {
		if err := writeJSON(out, view); err != nil {
			return codeUsage, err
		}
		return code, nil
	}
	writeText(out, view, isTerminal(out))
	return code, nil
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

func buildDeps(dir string, keys []ed25519.PublicKey, trustedPath string, params commitment.Params) (verifier.Deps, error) {
	fibreCommitter, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	if err != nil {
		return verifier.Deps{}, err
	}
	committers := map[commitment.DA]gate.DACommitter{
		commitment.DACelestiaBlob: blobv1.New(),
		commitment.DAFibre:        fibreCommitter,
	}
	store, err := fsarchive.OpenReadOnly(dir, committers)
	if err != nil {
		return verifier.Deps{}, fmt.Errorf("open archive: %w", err)
	}
	deps := verifier.Deps{
		Config:     verifier.Config{Params: params, GateKeys: keys},
		Archive:    store,
		Committers: committers,
		Anchors:    newAnchors(),
	}
	if trustedPath != "" {
		trust, err := loadTrusted(trustedPath)
		if err != nil {
			return verifier.Deps{}, err
		}
		deps.Trust = trust
	}
	return deps, nil
}
