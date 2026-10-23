// Package doctor checks a configured Edicta stack and says, for every check,
// what is wrong and how to fix it. Each check reads the network and the disk
// only through the interfaces of Env, so unit tests use fakes.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/internal/clearerr"
)

// Status is the outcome of one check.
type Status string

// The three outcomes. Only Fail makes a run fail.
const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Result is what a check found. Cause says what was seen (or what is wrong),
// Fix what to do about it; Fix is empty for ok.
type Result struct {
	Status Status `json:"status"`
	Cause  string `json:"cause,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// Check is one named check of the stack.
type Check interface {
	Name() string
	Run(ctx context.Context, c config.Config) Result
}

func ok(format string, a ...any) Result {
	return Result{Status: OK, Cause: fmt.Sprintf(format, a...)}
}

func warn(cause, fix string) Result { return Result{Status: Warn, Cause: cause, Fix: fix} }

func fail(cause, fix string) Result { return Result{Status: Fail, Cause: cause, Fix: fix} }

// Item is one check's name and result.
type Item struct {
	Name string `json:"name"`
	Result
}

// Report is the result of a run, in check order.
type Report struct {
	Items []Item `json:"checks"`
}

// Failed reports whether any check failed.
func (r Report) Failed() bool {
	for _, it := range r.Items {
		if it.Status == Fail {
			return true
		}
	}
	return false
}

// Count returns how many items have the given status.
func (r Report) Count(s Status) int {
	n := 0
	for _, it := range r.Items {
		if it.Status == s {
			n++
		}
	}
	return n
}

// CheckTimeout bounds one check; a check that outlasts it fails.
const CheckTimeout = 30 * time.Second

// Run runs every check in order. A check that panics or outlasts its time
// limit is a failure, not a crash of the run.
func Run(ctx context.Context, c config.Config, checks []Check) Report {
	var rep Report
	for _, ch := range checks {
		rep.Items = append(rep.Items, Item{Name: ch.Name(), Result: redactResult(runOne(ctx, c, ch), c)})
	}
	return rep
}

// redactResult keeps API keys that providers put in endpoint URLs out of the
// report, also when a probe or a remote answer echoes the URL back. The fix
// keeps the URLs doctor itself suggests, such as a faucet page.
func redactResult(r Result, c config.Config) Result {
	eps := endpointStrings(c)
	r.Cause = clearerr.RedactText(clearerr.RedactEndpoints(r.Cause, eps...))
	r.Fix = clearerr.RedactEndpoints(r.Fix, eps...)
	return r
}

func endpointStrings(c config.Config) []string {
	n := c.Network
	out := []string{n.Bridge.Addr, n.ConsensusGRPC.Addr, n.EVM.FacilitatorURL, c.Archive.URL}
	out = append(out, n.CometRPC...)
	out = append(out, n.EVM.RPC...)
	out = append(out, c.Archive.MirrorURLs...)
	if c.Agent != nil {
		out = append(out, c.Agent.RecorderURL, c.Agent.GateURL)
	}
	if c.Capture != nil {
		out = append(out, c.Capture.CometRPC)
	}
	if v := c.Verify; v != nil {
		out = append(out, v.HeadersRPC, v.TxRPC)
		out = append(out, v.CheckpointRPC...)
		out = append(out, v.CrossCheckRPC...)
	}
	return out
}

func runOne(ctx context.Context, c config.Config, ch Check) (res Result) {
	cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			res = fail(fmt.Sprintf("check %s stopped unexpectedly: %v", ch.Name(), p), "report this as a bug")
		}
	}()
	res = ch.Run(cctx, c)
	if res.Status != OK && res.Status != Warn && res.Status != Fail {
		return fail(fmt.Sprintf("check %s returned no status", ch.Name()), "report this as a bug")
	}
	return res
}

// WriteText prints one line per check, with the fix on the next line.
func (r Report) WriteText(w io.Writer) error {
	for _, it := range r.Items {
		if _, err := fmt.Fprintf(w, "%-4s  %-11s %s\n", it.Status, it.Name, it.Cause); err != nil {
			return err
		}
		if it.Fix != "" {
			if _, err := fmt.Fprintf(w, "      %-11s fix: %s\n", "", it.Fix); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "%d ok, %d warn, %d fail\n", r.Count(OK), r.Count(Warn), r.Count(Fail))
	return err
}

// WriteJSON prints the report as one JSON document.
func (r Report) WriteJSON(w io.Writer) error {
	doc := struct {
		OK     bool   `json:"ok"`
		Checks []Item `json:"checks"`
	}{OK: !r.Failed(), Checks: r.Items}
	if doc.Checks == nil {
		doc.Checks = []Item{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
