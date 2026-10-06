package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

type checkView struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type trustView struct {
	Status         string            `json:"status"`
	CheckpointH    uint64            `json:"checkpoint_height"`
	CheckpointHash string            `json:"checkpoint_hash"`
	CrossCheck     string            `json:"cross_check"`
	Hashes         map[uint64]string `json:"hashes,omitempty"`
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
	Verdict           string       `json:"verdict"`
	CommitmentHash    string       `json:"commitment_hash"`
	State             string       `json:"state"`
	AuthVerified      bool         `json:"authorization_verified"`
	Params            paramsView   `json:"params"`
	Rejections        []string     `json:"rejections,omitempty"`
	DA                uint64       `json:"da,omitempty"`
	Height            uint64       `json:"height,omitempty"`
	BlockTime         uint64       `json:"block_time,omitempty"`
	RetentionStart    uint64       `json:"retention_start,omitempty"`
	GateID            string       `json:"gate_id,omitempty"`
	ActionType        string       `json:"action_type,omitempty"`
	Settlement        string       `json:"settlement,omitempty"`
	Authorization     *authView    `json:"authorization,omitempty"`
	Cert              *certView    `json:"cert,omitempty"`
	ProofForm         *int         `json:"anchor_proof_form,omitempty"`
	CandidatesEarlier *int         `json:"anchor_candidates_earlier,omitempty"`
	Receipt           *receiptView `json:"receipt,omitempty"`
	HeaderTrust       trustView    `json:"header_trust"`
	Checks            []checkView  `json:"checks"`
	Warnings          []string     `json:"warnings,omitempty"`
	K2                *k2View      `json:"k2,omitempty"`
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
		State:          r.State.String(),
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
	for _, c := range r.Checks {
		v.Checks = append(v.Checks, checkView{Name: string(c.Name), Status: string(c.Status), Error: errText(c.Err)})
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
	return v
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

	p("commitment: %s", v.CommitmentHash)
	p("state: %s", v.State)
	for _, r := range v.Rejections {
		p("  refused: %s", r)
	}
	p("parameters: skew %ds, blob retention %ds, fibre retention %ds", v.Params.SkewS, v.Params.BlobRetentionS, v.Params.FibreRetentionS)
	if v.GateID != "" {
		p("gate: %s  action type: %s  da: %d  height: %d", v.GateID, v.ActionType, v.DA, v.Height)
	}
	for _, c := range v.Checks {
		if c.Error != "" {
			p("%s %s: %s", tag(c.Status), c.Name, c.Error)
		} else {
			p("%s %s", tag(c.Status), c.Name)
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
			p("%s retention replay: %s", tag(string(verifier.StatusFail)), k.Error)
		}
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
	if ht.CheckpointH != 0 {
		p("header trust: %s, checkpoint %d %s, cross-check %s", ht.Status, ht.CheckpointH, ht.CheckpointHash, ht.CrossCheck)
	} else {
		p("header trust: %s", ht.Status)
	}
	if rc := v.Receipt; rc != nil {
		p("receipt: rail ref %s recorded at %d, attested by the gate, execution not proven", rc.RailRef, rc.RecordedAt)
	}
	for _, w := range v.Warnings {
		p("warning: %s", w)
	}
	p("verdict: %s", v.Verdict)
}
