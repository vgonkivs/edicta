package verifycli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// checkView is one check. An unchecked check carries its machine-readable
// reason, the sources or checks it blames and what to try next.
type checkView struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Sources []string `json:"sources,omitempty"`
	Advice  string   `json:"advice,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type trustView struct {
	Status         string            `json:"status"`
	Mode           string            `json:"mode,omitempty"`
	CheckpointH    uint64            `json:"checkpoint_height"`
	CheckpointHash string            `json:"checkpoint_hash"`
	Sources        []string          `json:"sources,omitempty"`
	Agreed         int               `json:"agreed,omitempty"`
	Quorum         int               `json:"quorum,omitempty"`
	CrossCheck     string            `json:"cross_check"`
	Hashes         map[uint64]string `json:"hashes,omitempty"`
	HeadersSource  string            `json:"headers_source,omitempty"`
	HeaderSources  map[uint64]string `json:"header_sources,omitempty"`
	CrossSources   []string          `json:"cross_check_sources,omitempty"`
}

type txSourceView struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type executionView struct {
	RailRef    string         `json:"rail_ref"`
	Height     uint64         `json:"height,omitempty"`
	HeaderHash string         `json:"header_hash,omitempty"`
	BlockTime  uint64         `json:"block_time,omitempty"`
	Inclusion  string         `json:"inclusion,omitempty"`
	Outcome    string         `json:"outcome,omitempty"`
	Result     string         `json:"result,omitempty"`
	CrossCheck string         `json:"cross_check,omitempty"`
	Sources    []txSourceView `json:"sources"`
}

type integrityView struct {
	Status         string   `json:"status"`
	Reason         string   `json:"reason,omitempty"`
	Evidence       []string `json:"evidence"`
	EvidenceHashes []string `json:"evidence_verdict_hashes"`
}

type policyView struct {
	MandateHash   string   `json:"mandate_hash"`
	MandateID     string   `json:"mandate_id"`
	Version       uint64   `json:"version"`
	Principal     string   `json:"principal"`
	Seq           uint64   `json:"seq"`
	AnchorTime    uint64   `json:"anchor_time"`
	EvalTime      uint64   `json:"eval_time"`
	Extractor     string   `json:"extractor"`
	Kind          string   `json:"kind"`
	Asset         string   `json:"asset"`
	Amount        string   `json:"amount"`
	Scale         uint64   `json:"scale"`
	Recipient     string   `json:"recipient,omitempty"`
	PrevStateHash string   `json:"prev_state_hash"`
	NewStateHash  string   `json:"new_state_hash"`
	Denials       []string `json:"denials,omitempty"`
}

type authView struct {
	Path         string `json:"path"`
	Expires      uint64 `json:"expires"`
	AuthorizedAt uint64 `json:"authorized_at"`
}

type certView struct {
	SignedPower    int64   `json:"cert_signed_power"`
	TotalPower     int64   `json:"cert_total_power"`
	SignedShare    float64 `json:"cert_signed_share"`
	QuorumWarning  bool    `json:"cert_quorum_warning"`
	TokenPrecision string  `json:"cert_token_precision,omitempty"`
	ValsetHeader   string  `json:"cert_valset_header,omitempty"`
}

type receiptView struct {
	RailRef         string `json:"rail_ref"`
	RecordedAt      uint64 `json:"recorded_at"`
	GateAttested    bool   `json:"gate_attested"`
	ProvenExecution bool   `json:"proven_execution"`
}

type paramsView struct {
	SkewS           uint64 `json:"skew_s"`
	BlobRetentionS  uint64 `json:"blob_retention_s"`
	FibreRetentionS uint64 `json:"fibre_retention_s"`
}

type k2View struct {
	Replayable     bool   `json:"replayable"`
	Reason         string `json:"reason,omitempty"`
	R              uint64 `json:"r,omitempty"`
	Start          uint64 `json:"start,omitempty"`
	Margin         uint64 `json:"margin,omitempty"`
	Within         bool   `json:"within"`
	Route          string `json:"route,omitempty"`
	AuthorizedPath string `json:"authorized_path,omitempty"`
	Consistent     bool   `json:"consistent"`
	Error          string `json:"error,omitempty"`
}

// reportView is the printed form of a report; the JSON keys are the contract.
type reportView struct {
	Verdict           string         `json:"verdict"`
	CommitmentHash    string         `json:"commitment_hash"`
	State             string         `json:"state"`
	AuthVerified      bool           `json:"authorization_verified"`
	Params            paramsView     `json:"params"`
	Rejections        []string       `json:"rejections,omitempty"`
	DA                uint64         `json:"da,omitempty"`
	Height            uint64         `json:"height,omitempty"`
	BlockTime         uint64         `json:"block_time,omitempty"`
	RetentionStart    uint64         `json:"retention_start,omitempty"`
	GateID            string         `json:"gate_id,omitempty"`
	ActionType        string         `json:"action_type,omitempty"`
	Settlement        string         `json:"settlement,omitempty"`
	Authorization     *authView      `json:"authorization,omitempty"`
	Cert              *certView      `json:"cert,omitempty"`
	ProofForm         *int           `json:"anchor_proof_form,omitempty"`
	CandidatesEarlier *int           `json:"anchor_candidates_earlier,omitempty"`
	Receipt           *receiptView   `json:"receipt,omitempty"`
	Execution         *executionView `json:"execution,omitempty"`
	Policy            *policyView    `json:"policy,omitempty"`
	GateIntegrity     integrityView  `json:"gate_integrity"`
	HeaderTrust       trustView      `json:"header_trust"`
	TrustModel        string         `json:"trust_model,omitempty"`
	Checks            []checkView    `json:"checks"`
	Warnings          []string       `json:"warnings,omitempty"`
	K2                *k2View        `json:"retention_replay,omitempty"`
}

func pathName(p commitment.PayloadPath) string {
	switch p {
	case commitment.PathDA:
		return "da"
	case commitment.PathArchive:
		return "archive"
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func viewOf(r verifier.Report) reportView {
	v := reportView{
		Verdict:        string(r.Verdict),
		CommitmentHash: hex.EncodeToString(r.CommitmentHash[:]),
		State:          stateName(r.State),
		AuthVerified:   r.AuthorizationVerified,
		Params: paramsView{
			SkewS: r.Params.SkewS, BlobRetentionS: r.Params.BlobRetentionS, FibreRetentionS: r.Params.FibreRetentionS,
		},
		Rejections:     r.Rejections,
		DA:             uint64(r.DA),
		Height:         r.Height,
		BlockTime:      r.BlockTime,
		RetentionStart: r.RetentionStart,
		GateID:         r.GateID,
		ActionType:     r.ActionType,
		Settlement:     r.Settlement,
		Warnings:       r.Warnings,
		Checks:         []checkView{},
		HeaderTrust: trustView{
			Status:         string(r.HeaderTrust.Status),
			CheckpointH:    r.HeaderTrust.CheckpointH,
			CheckpointHash: hex.EncodeToString(r.HeaderTrust.CheckpointHash),
			CrossCheck:     r.HeaderTrust.CrossCheck,
		},
	}
	if v.HeaderTrust.Status == "" {
		v.HeaderTrust.Status = string(verifier.TrustUnchecked)
	}
	if len(r.HeaderTrust.Hashes) > 0 {
		v.HeaderTrust.Hashes = map[uint64]string{}
		for h, b := range r.HeaderTrust.Hashes {
			v.HeaderTrust.Hashes[h] = hex.EncodeToString(b)
		}
	}
	v.GateIntegrity = integrityView{
		Status: string(r.GateIntegrity.Status), Reason: string(r.GateIntegrity.Reason),
		Evidence: []string{}, EvidenceHashes: []string{},
	}
	if v.GateIntegrity.Status == "" {
		v.GateIntegrity.Status = string(verifier.IntegrityNotChecked)
	}
	for _, e := range r.GateIntegrity.Evidence {
		v.GateIntegrity.Evidence = append(v.GateIntegrity.Evidence, hex.EncodeToString(e))
	}
	for _, h := range r.GateIntegrity.EvidenceHashes {
		v.GateIntegrity.EvidenceHashes = append(v.GateIntegrity.EvidenceHashes, hex.EncodeToString(h[:]))
	}
	if p := r.Policy; p != nil {
		v.Policy = &policyView{
			MandateHash: hex.EncodeToString(p.MandateHash[:]), MandateID: hex.EncodeToString(p.MandateID),
			Version: p.Version, Principal: hex.EncodeToString(p.Principal), Seq: p.Seq,
			AnchorTime: p.AnchorTime, EvalTime: p.EvalTime, Extractor: p.ExtractorID,
			Kind: p.Facts.Kind, Asset: p.Facts.Asset, Amount: hex.EncodeToString(p.Facts.Amount),
			Scale: p.Facts.Scale, Recipient: p.Facts.Recipient,
			PrevStateHash: hex.EncodeToString(p.PrevStateHash[:]), NewStateHash: hex.EncodeToString(p.NewStateHash[:]),
			Denials: p.Denials,
		}
	}
	for _, c := range r.Checks {
		v.Checks = append(v.Checks, checkView{
			Name: string(c.Name), Status: string(c.Status), Reason: string(c.Reason), Sources: c.Sources,
			Advice: c.Reason.Advice(), Error: errText(c.Err),
		})
	}
	if a := r.Authorization; a != nil {
		v.Authorization = &authView{Path: pathName(a.Path), Expires: a.Expires, AuthorizedAt: a.AuthorizedAt}
	}
	if r.Cert != nil {
		form, earlier := r.AnchorProofForm, r.AnchorCandidatesEarlier
		v.ProofForm, v.CandidatesEarlier = &form, &earlier
	}
	if c := r.Cert; c != nil {
		v.Cert = &certView{
			SignedPower: c.SignedPower, TotalPower: c.TotalPower, SignedShare: c.SignedShare,
			QuorumWarning: c.QuorumWarning, TokenPrecision: c.TokenPrecision, ValsetHeader: c.ValsetHeader,
		}
	}
	if rc := r.Receipt; rc != nil {
		v.Receipt = &receiptView{RailRef: rc.RailRef, RecordedAt: rc.RecordedAt, GateAttested: rc.GateAttested, ProvenExecution: rc.ProvenExecution}
	}
	if ex := r.Execution; ex != nil {
		v.Execution = &executionView{
			RailRef: ex.RailRef, Height: ex.Height, BlockTime: ex.BlockTime, Inclusion: ex.Inclusion,
			Outcome: ex.Outcome, Result: ex.Result, CrossCheck: ex.CrossCheck, Sources: []txSourceView{},
		}
		if len(ex.HeaderHash) > 0 {
			v.Execution.HeaderHash = hex.EncodeToString(ex.HeaderHash)
		}
		for _, s := range ex.Sources {
			v.Execution.Sources = append(v.Execution.Sources, txSourceView{
				Name: s.Name, Role: s.Role, Result: s.Result, Reason: string(s.Reason), Detail: s.Detail,
			})
		}
	}
	return v
}

// stateName prints a missing decision as unknown: with no record there is no
// state to report.
func stateName(s archive.State) string {
	if s == archive.StateAbsent {
		return "unknown"
	}
	return s.String()
}

func viewOfK2(k verifier.K2Replay) k2View {
	return k2View{
		Replayable: k.Replayable, Reason: k.Reason, R: k.R, Start: k.Start, Margin: k.Margin,
		Within: k.Within, Route: pathName(k.Route), AuthorizedPath: pathName(k.AuthorizedPath),
		Consistent: k.Consistent, Error: errText(k.Err),
	}
}

func writeJSON(out io.Writer, v reportView) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", b)
	return err
}

// isTerminal reports whether out is a character device; colour is for people
// only.
func isTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func writeText(out io.Writer, v reportView, colour bool) {
	paint := func(code, s string) string {
		if !colour {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	tag := func(status string) string {
		switch status {
		case string(verifier.StatusPass):
			return paint("32", "[ok]")
		case string(verifier.StatusFail):
			return paint("31", "[FAIL]")
		}
		return paint("33", "[unchecked]")
	}
	p := func(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }

	if v.GateIntegrity.Status == string(verifier.IntegrityViolated) {
		p("%s", paint("1;31", "GATE INTEGRITY VIOLATED ("+v.GateIntegrity.Reason+")"))
	}
	p("commitment: %s", v.CommitmentHash)
	p("state: %s", v.State)
	for _, r := range v.Rejections {
		p("  refused: %s", r)
	}
	p("parameters: skew %ds, blob retention %ds, fibre retention %ds", v.Params.SkewS, v.Params.BlobRetentionS, v.Params.FibreRetentionS)
	if v.GateID != "" {
		p("gate: %s  action type: %s  da: %d  height: %d", v.GateID, v.ActionType, v.DA, v.Height)
	}
	replayFailed := v.K2 != nil && v.K2.Replayable && !v.K2.Consistent
	for _, c := range v.Checks {
		if replayFailed && c.Name == string(verifier.CheckRetention) {
			continue
		}
		if c.Error != "" {
			p("%s %s: %s", tag(c.Status), c.Name, c.Error)
		} else {
			p("%s %s", tag(c.Status), c.Name)
		}
		if c.Reason != "" {
			p("    reason: %s: %s", c.Reason, verifier.Reason(c.Reason).Meaning())
			if len(c.Sources) > 0 {
				p("    source: %s", strings.Join(c.Sources, ", "))
			}
			if c.Advice != "" {
				p("    advice: %s", c.Advice)
			}
		}
	}
	if v.K2 != nil {
		k := v.K2
		switch {
		case !k.Replayable:
			p("%s retention replay: not replayable: %s", tag(string(verifier.StatusUnchecked)), k.Reason)
		case k.Consistent:
			p("%s retention replay consistent: retention %ds, start %d, margin %ds, window holds: %t, route %s, authorized path %s",
				tag(string(verifier.StatusPass)), k.R, k.Start, k.Margin, k.Within, k.Route, k.AuthorizedPath)
		default:
			p("%s retention replay: %s", tag(string(verifier.StatusUnchecked)), k.Error)
			r := verifier.ReasonReplayInconsistent
			p("    reason: %s: %s", r, r.Meaning())
			p("    advice: %s", r.Advice())
		}
	}
	if pv := v.Policy; pv != nil {
		p("policy: mandate %s version %d, counter position %d, %s %s (scale %d), anchor time %d, evaluated at %d",
			pv.MandateHash, pv.Version, pv.Seq, pv.Asset, pv.Amount, pv.Scale, pv.AnchorTime, pv.EvalTime)
	}
	switch v.GateIntegrity.Status {
	case string(verifier.IntegrityViolated):
		for i, h := range v.GateIntegrity.EvidenceHashes {
			p("gate integrity: contradicting verdict %d: %s", i+1, h)
		}
	case string(verifier.IntegrityOK), string(verifier.IntegrityUnchecked):
		line := "gate integrity: " + v.GateIntegrity.Status
		if v.GateIntegrity.Reason != "" {
			line += " (" + v.GateIntegrity.Reason + ")"
		}
		p("%s", line)
	}
	if v.Authorization != nil {
		a := v.Authorization
		p("authorization: path %s, expires %d, issued at %d", a.Path, a.Expires, a.AuthorizedAt)
	}
	if v.BlockTime != 0 {
		p("anchor block time: %d", v.BlockTime)
	}
	if v.Settlement != "" {
		p("settlement: %s", v.Settlement)
	}
	if c := v.Cert; c != nil {
		p("certificate: signed %d of %d (%.4f), token precision %q", c.SignedPower, c.TotalPower, c.SignedShare, c.TokenPrecision)
	}
	if v.ProofForm != nil {
		p("anchor proof form: %d, earlier candidates: %d", *v.ProofForm, *v.CandidatesEarlier)
	}
	ht := v.HeaderTrust
	mode := ""
	if ht.Mode != "" {
		mode = ", mode " + ht.Mode
	}
	if ht.CheckpointH != 0 {
		p("header trust: %s%s, checkpoint %d %s, cross-check %s", ht.Status, mode, ht.CheckpointH, ht.CheckpointHash, ht.CrossCheck)
	} else {
		p("header trust: %s%s", ht.Status, mode)
	}
	if ht.Quorum > 0 {
		p("checkpoint operators: %d agree, %d required: %s", ht.Agreed, ht.Quorum, strings.Join(ht.Sources, ", "))
	}
	if ht.HeadersSource != "" {
		p("headers served by: %s", ht.HeadersSource)
	}
	if len(ht.HeaderSources) > 0 {
		hs := make([]uint64, 0, len(ht.HeaderSources))
		for h := range ht.HeaderSources {
			hs = append(hs, h)
		}
		sort.Slice(hs, func(i, j int) bool { return hs[i] < hs[j] })
		parts := make([]string, len(hs))
		for i, h := range hs {
			parts[i] = fmt.Sprintf("%d from %s", h, ht.HeaderSources[h])
		}
		p("needed headers: %s", strings.Join(parts, ", "))
	}
	if len(ht.CrossSources) > 0 {
		p("cross-check sources: %s", strings.Join(ht.CrossSources, ", "))
	}
	if v.TrustModel != "" {
		p("trust model: %s", v.TrustModel)
	}
	if rc := v.Receipt; rc != nil {
		if rc.ProvenExecution {
			p("receipt: rail ref %s recorded at %d, attested by the gate; the transaction is in a block of the trusted chain", rc.RailRef, rc.RecordedAt)
		} else {
			p("receipt: rail ref %s recorded at %d, attested by the gate, execution not proven", rc.RailRef, rc.RecordedAt)
		}
	}
	if ex := v.Execution; ex != nil {
		if ex.Height != 0 {
			p("execution: transaction in block %d (hash %s), inclusion %s, outcome %s, result %s, cross-check %s",
				ex.Height, ex.HeaderHash, ex.Inclusion, ex.Outcome, ex.Result, ex.CrossCheck)
			if ex.Inclusion != "proven" {
				p("execution height: node-attested, so the order of the anchor before the transaction rests on the transaction source")
			}
		}
		for _, s := range ex.Sources {
			line := fmt.Sprintf("tx source %s (%s): %s", s.Name, s.Role, s.Result)
			if s.Reason != "" {
				line += ", " + s.Reason
			}
			p("%s", line)
		}
	}
	for _, w := range v.Warnings {
		p("warning: %s", w)
	}
	for _, c := range v.Checks {
		if c.Reason == string(verifier.ReasonHeaderDisagreement) {
			p("%s", paint("1;31", "!!! "+verifier.DisagreementText))
			break
		}
	}
	p("verdict: %s", v.Verdict)
}
