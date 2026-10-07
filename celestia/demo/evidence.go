package demo

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

type evidenceDoc struct {
	Code           int             `json:"exit_code"`
	RunDir         string          `json:"run_dir"`
	CommitmentHash string          `json:"commitment_hash,omitempty"`
	AnchorHeight   uint64          `json:"anchor_height,omitempty"`
	TxHash         string          `json:"tx_hash,omitempty"`
	TxHeight       uint64          `json:"tx_height,omitempty"`
	Verdict        string          `json:"verdict,omitempty"`
	TrustRoot      *trustRootDoc   `json:"trust_root,omitempty"`
	Attempts       []AttemptResult `json:"attempts,omitempty"`
	Funding        []FundingSend   `json:"funding,omitempty"`
}

type trustRootDoc struct {
	Height uint64 `json:"height"`
	Hash   string `json:"hash"`
	Source string `json:"source"`
	Link   string `json:"link,omitempty"`
}

func writeEvidence(path string, o Outcome) error {
	doc := evidenceDoc{Code: o.Code, RunDir: o.RunDir, AnchorHeight: o.AnchorHeight, TxHash: o.TxHash, TxHeight: o.TxHeight,
		Verdict: string(o.Verify.Verdict), Attempts: o.Attempts, Funding: o.Funding}
	if o.CommitmentHash != ([32]byte{}) {
		doc.CommitmentHash = hex.EncodeToString(o.CommitmentHash[:])
	}
	if t := o.Verify.TrustRoot; t.Height != 0 {
		doc.TrustRoot = &trustRootDoc{Height: t.Height, Hash: hex.EncodeToString(t.Hash), Source: t.Source, Link: t.Link}
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (r *Runner) writeVerifyFile(name string, res VerifyResult) {
	if r.runDir == "" {
		return
	}
	b, err := json.MarshalIndent(struct {
		Verdict string      `json:"verdict"`
		Exit    int         `json:"exit"`
		Command []string    `json:"command"`
		Checks  []CheckLine `json:"checks"`
	}{string(res.Verdict), res.Code, res.Command, res.Checks}, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(r.runDir, name), append(b, '\n'), 0o600)
	}
}
