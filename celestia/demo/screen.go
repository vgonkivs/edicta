package demo

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	cReset  = "\x1b[0m"
	cGreen  = "\x1b[32m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
)

// NewScreen prints to w: text, with colour on a terminal, or one JSON event
// per line.
func NewScreen(w io.Writer, color, jsonOut bool) Screen {
	return &textScreen{w: w, color: color && !jsonOut, json: jsonOut}
}

type textScreen struct {
	mu      sync.Mutex
	w       io.Writer
	color   bool
	json    bool
	step    int
	rewrite bool
}

func (s *textScreen) paint(c, text string) string {
	if !s.color {
		return text
	}
	return c + text + cReset
}

func (s *textScreen) event(kind string, v map[string]any) {
	v["step"], v["kind"] = s.step, kind
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(s.w, "%s\n", b)
}

func (s *textScreen) line(format string, a ...any) {
	if s.rewrite {
		fmt.Fprint(s.w, "\r\x1b[K")
		s.rewrite = false
	}
	fmt.Fprintf(s.w, format+"\n", a...)
}

func (s *textScreen) Step(n, of int, title string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.step = n
	if s.json {
		s.event("step", map[string]any{"of": of, "title": title})
		return
	}
	s.line("[%d/%d] %s", n, of, title)
}

func (s *textScreen) say(kind, tag, colour, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event(kind, map[string]any{"text": text})
		return
	}
	if tag != "" {
		tag = s.paint(colour, "["+tag+"]") + " "
	}
	s.line("  %s%s", tag, text)
}

func (s *textScreen) OK(line string, kv ...any)   { s.say("ok", "ok", cGreen, line) }
func (s *textScreen) Info(line string, kv ...any) { s.say("info", "", "", line) }
func (s *textScreen) Warn(line string, kv ...any) { s.say("warn", "!", cYellow, line) }

func (s *textScreen) Fail(line string, err error) {
	if err != nil {
		line = fmt.Sprintf("%s: %v", line, err)
	}
	s.say("fail", "FAIL", cRed, line)
}

func (s *textScreen) Wait(line, progress string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("wait", map[string]any{"text": line, "progress": progress})
		return
	}
	if !s.color {
		fmt.Fprintf(s.w, "  %s %s\n", line, progress)
		return
	}
	fmt.Fprintf(s.w, "\r\x1b[K  %s %s", line, progress)
	s.rewrite = true
}

func (s *textScreen) Layer(n int, title string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("layer", map[string]any{"layer": n, "title": title})
		return
	}
	s.line("  Layer %d - %s", n, title)
}

func (s *textScreen) Mandate(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("mandate", map[string]any{"text": text})
		return
	}
	s.line("  %s", s.paint(cGreen, "[mandate]")+" signed by this run's principal key; the gate enforces:")
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		s.line("    %s", l)
	}
}

func (s *textScreen) TrustRoot(t TrustRootInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := hex.EncodeToString(t.Hash)
	if s.json {
		s.event("trust_root", map[string]any{"height": t.Height, "hash": hash, "source": t.Source, "link": t.Link})
		return
	}
	text := fmt.Sprintf("[trust root] header %d = %s from %s", t.Height, hash, t.Source)
	if t.Link != "" {
		text += "; check " + t.Link
	}
	s.line("  %s", text)
}

func (s *textScreen) Check(c CheckLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("check", map[string]any{"check": c.Check, "status": c.Status, "reason": c.Reason, "source": c.Source, "detail": c.Detail})
		return
	}
	switch c.Status {
	case "pass":
		text := c.Check
		if c.Detail != "" {
			text += ": " + c.Detail
		}
		s.line("  %s %s", s.paint(cGreen, "[pass]"), text)
	case "unchecked":
		text := fmt.Sprintf("%s: reason=%s", c.Check, c.Reason)
		if c.Source != "" {
			text += " source=" + c.Source
		}
		if c.Advice != "" {
			text += "; try: " + c.Advice
		}
		s.line("  %s", s.paint(cYellow, "[unchecked] "+text))
	default:
		text := c.Check
		if c.Detail != "" {
			text += ": " + c.Detail
		}
		s.line("  %s", s.paint(cRed, "[FAIL] "+text))
	}
}

func (s *textScreen) Verdict(v VerifyResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("verdict", map[string]any{"verdict": string(v.Verdict), "exit": v.Code, "retries": v.Retries, "assumptions": v.Assumptions, "command": strings.Join(v.Command, " ")})
		return
	}
	name, colour := "", cGreen
	switch v.Verdict {
	case VerdictValid:
		name = "VALID"
	case VerdictInvalid:
		name, colour = "INVALID", cRed
	case VerdictNotAuthorized:
		name, colour = "NOT AUTHORIZED", cRed
	default:
		name, colour = "INCONCLUSIVE", cYellow
		var reasons []string
		for _, c := range v.Checks {
			if c.Status == "unchecked" && c.Reason != "" {
				reasons = append(reasons, c.Reason)
			}
		}
		if len(reasons) > 0 {
			name += " (" + strings.Join(reasons, ", ") + ")"
		}
	}
	s.line("  VERDICT: %s (verify exit %d)", s.paint(colour, name), v.Code)
	if v.Verdict != VerdictValid {
		return
	}
	s.line("  Trust root: header %d, hash from %s", v.TrustRoot.Height, v.TrustRoot.Source)
	s.line("  Assumptions:")
	for _, a := range v.Assumptions {
		s.line("    - %s", a)
	}
	s.line("  Demo mode: production takes the trust root from its own node or validator signatures.")
	if len(v.Command) > 0 {
		s.line("  $ edicta %s", strings.Join(v.Command, " "))
	}
}

func (s *textScreen) Attempt(a AttemptResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.json {
		s.event("attempt", map[string]any{"layer": a.Layer, "name": a.Name, "expected": a.Expected, "got": a.Got, "as_expected": a.AsExpected, "skipped": a.Skipped, "why": a.Why})
		return
	}
	tag, colour := "REFUSED", cRed
	switch {
	case a.Skipped:
		tag, colour = "SKIPPED", cYellow
	case !a.AsExpected:
		tag, colour = "UNEXPECTED", cRed
	case a.Layer == 2 || a.Layer == 3:
		tag = "CAUGHT"
	}
	s.line("  %s %s: %s", s.paint(colour, "["+tag+"]"), a.Name, a.Got)
	if a.Why != "" {
		s.line("            %s", a.Why)
	}
}
