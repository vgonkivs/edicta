package demo

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/verifier"
)

// verifyView is the part of the verifier's JSON report the demo reads.
type verifyView struct {
	Verdict string `json:"verdict"`
	Checks  []struct {
		Name    string   `json:"name"`
		Status  string   `json:"status"`
		Reason  string   `json:"reason"`
		Sources []string `json:"sources"`
		Advice  string   `json:"advice"`
		Error   string   `json:"error"`
	} `json:"checks"`
	HeaderTrust struct {
		Mode       string `json:"mode"`
		CrossCheck string `json:"cross_check"`
	} `json:"header_trust"`
	Execution *struct {
		Inclusion string `json:"inclusion"`
		Result    string `json:"result"`
		Height    uint64 `json:"height"`
	} `json:"execution"`
	Error string `json:"error"`
}

var timingReasons = []string{
	string(verifier.ReasonHeaderAboveCheckpoint), string(verifier.ReasonResultHeaderUnreachable),
	string(verifier.ReasonTxNotFound), string(verifier.ReasonTxSourceUnavailable),
}

// openArchiveServer serves dir read-only on a loopback port.
func openArchiveServer(dir string) (*archiveServer, error) {
	st, err := fsarchive.OpenReadOnly(dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	if err != nil {
		return nil, fmt.Errorf("demo: open archive: %w", err)
	}
	return serveArchive(httparchive.NewHandler(st))
}

func (r *Runner) verifyArgs(hash commitment.Hash, archiveURL, receipt string, root TrustRootInfo) []string {
	v := r.preset.Verify
	args := []string{
		"verify", hex.EncodeToString(hash[:]),
		"--gate-key", hex.EncodeToString(r.gatePub),
		"--archive-url", archiveURL,
		"--headers-rpc", v.HeadersRPC,
		"--checkpoint", fmt.Sprintf("%d:%s", root.Height, hex.EncodeToString(root.Hash)),
		"--receipt", receipt,
		"--tx-rpc", v.TxRPC,
		"--check-execution",
	}
	for _, c := range v.CrossCheckRPC {
		args = append(args, "--cross-check", c)
	}
	for _, h := range r.preset.ExcludeHosts() {
		args = append(args, "--exclude-host", h)
	}
	return append(args, "--timeout", v.Timeout().String(), "--json")
}

// runVerify runs the verifier once and turns its report into a result.
func (r *Runner) runVerify(ctx context.Context, args []string, root TrustRootInfo) (VerifyResult, error) {
	var buf bytes.Buffer
	code := r.deps.Verify(ctx, args, &buf)
	res := VerifyResult{Code: code, TrustRoot: root, Command: args}
	var v verifyView
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		return res, coded(ExitUsage, fmt.Errorf("demo: the verifier gave no report (exit %d): %s", code, strings.TrimSpace(buf.String())))
	}
	if code == 4 || v.Error != "" {
		return res, coded(ExitUsage, fmt.Errorf("demo: the verifier could not run: %s", v.Error))
	}
	switch v.Verdict {
	case string(verifier.VerdictValid):
		res.Verdict = VerdictValid
	case string(verifier.VerdictInvalid):
		res.Verdict = VerdictInvalid
	case string(verifier.VerdictUnchecked):
		res.Verdict = VerdictInconclusive
	case string(verifier.VerdictNotAuthorized):
		res.Verdict = VerdictNotAuthorized
	default:
		return res, coded(ExitUsage, fmt.Errorf("demo: unknown verdict %q", v.Verdict))
	}
	for _, c := range v.Checks {
		line := CheckLine{Check: c.Name, Status: c.Status, Reason: c.Reason, Advice: c.Advice, Detail: c.Error}
		if len(c.Sources) > 0 {
			line.Source = strings.Join(c.Sources, ",")
		}
		res.Checks = append(res.Checks, line)
	}
	if res.Verdict == VerdictValid {
		res.Assumptions = r.assumptions(v, root)
	}
	return res, nil
}

// assumptions lists what a VALID result still rests on, built from the
// report and the trust-root source.
func (r *Runner) assumptions(v verifyView, root TrustRootInfo) []string {
	hosts := []string{}
	for _, u := range []string{r.preset.Verify.HeadersRPC, r.preset.Verify.TxRPC} {
		if h, err := inclusion.SourceHost(u); err == nil {
			hosts = append(hosts, h)
		}
	}
	who := root.Source
	if root.Source == "--trusted-header" || root.Source == "manual input" {
		who = "your source"
	}
	out := []string{fmt.Sprintf("%s and the data RPCs (%s) do not collude", who, strings.Join(hosts, ", "))}
	cross := v.HeaderTrust.CrossCheck
	if cross == "" || cross == "off" {
		out = append(out, "header cross-check: off")
	} else {
		out = append(out, "header cross-check: "+cross)
	}
	if e := v.Execution; e != nil && e.Inclusion == "proven" && e.Result == "proven" {
		out = append(out, "inclusion proven (share proof) and execution code proven (LastResultsHash)")
	}
	return out
}

func timingOnly(res VerifyResult) (timing, above bool) {
	if res.Verdict != VerdictInconclusive {
		return false, false
	}
	n := 0
	for _, c := range res.Checks {
		if c.Status != "unchecked" {
			continue
		}
		n++
		if !slices.Contains(timingReasons, c.Reason) {
			return false, false
		}
		if c.Reason == string(verifier.ReasonHeaderAboveCheckpoint) {
			above = true
		}
	}
	return n > 0, above
}

const maxVerifyRetries = 3

// verify runs the verifier and retries only timing reasons: two blocks apart,
// at most three times within a minute. A header above the trust root asks for
// a new trust root once.
func (r *Runner) verify(ctx context.Context, hash commitment.Hash, archiveURL, receipt string, root TrustRootInfo, txHeight uint64) (VerifyResult, error) {
	start := r.deps.now()
	newRoot := false
	for retries := 0; ; retries++ {
		res, err := r.runVerify(ctx, r.verifyArgs(hash, archiveURL, receipt, root), root)
		res.Retries = retries
		if err != nil {
			return res, err
		}
		timing, above := timingOnly(res)
		if !timing || retries >= maxVerifyRetries || r.deps.now().Sub(start) > time.Minute {
			return res, nil
		}
		r.deps.Screen.Info(fmt.Sprintf("a source lags (retry %d of %d); waiting two blocks", retries+1, maxVerifyRetries))
		if err := r.deps.sleep(ctx, 6*time.Second); err != nil {
			return res, err
		}
		if above && !newRoot {
			newRoot = true
			if root, err = r.trustRoot(ctx, txHeight+2); err != nil {
				return res, err
			}
		}
	}
}

func (r *Runner) showVerify(res VerifyResult) {
	for _, c := range res.Checks {
		r.deps.Screen.Check(c)
	}
	r.deps.Screen.Verdict(res)
}

func (r *Runner) verifyStep(ctx context.Context, d *decision) error {
	var err error
	if r.archive, err = openArchiveServer(filepath.Join(r.runDir, "archive")); err != nil {
		return coded(ExitUsage, err)
	}
	root, err := r.trustRoot(ctx, d.txHeight)
	if err != nil {
		if !errors.Is(err, ErrTrustRootUnavailable) {
			return err
		}
		res := VerifyResult{Code: ExitInconclusive, Verdict: VerdictInconclusive, Checks: []CheckLine{{
			Check: "header_trust", Status: "unchecked", Reason: string(verifier.ReasonNoTrustedHeader),
			Advice: verifier.ReasonNoTrustedHeader.Advice(),
		}}}
		r.out.Verify = res
		r.showVerify(res)
		r.step5Inconclusive = true
		return nil
	}
	r.root, r.haveRoot = root, true
	res, err := r.verify(ctx, d.res.CommitmentHash, r.archive.url, filepath.Join(r.runDir, "receipt.cbor"), root, d.txHeight)
	r.out.Verify = res
	if err != nil {
		return err
	}
	r.showVerify(res)
	r.writeVerifyFile("verify-step5.json", res)
	switch res.Verdict {
	case VerdictValid:
		return nil
	case VerdictInvalid:
		return coded(ExitWrong, fmt.Errorf("demo: step 5 is INVALID"))
	case VerdictNotAuthorized:
		return coded(ExitNotAuth, fmt.Errorf("demo: step 5 is NOT AUTHORIZED"))
	}
	r.step5Inconclusive = true
	return nil
}
