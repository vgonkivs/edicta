// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"encoding/hex"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

// ReportJSON is the settlement report with the profile's JSON names.
type ReportJSON struct {
	Profile          string                  `json:"profile"`
	Status           string                  `json:"status"`
	Reason           string                  `json:"reason,omitempty"`
	Error            string                  `json:"error,omitempty"`
	Level            string                  `json:"level,omitempty"`
	Outcome          string                  `json:"outcome,omitempty"`
	RailRef          string                  `json:"rail_ref"`
	ChainID          uint64                  `json:"chain_id,omitempty"`
	BlockNumber      *uint64                 `json:"block_number,omitempty"`
	BlockHash        string                  `json:"block_hash,omitempty"`
	TransactionIndex *uint64                 `json:"transaction_index,omitempty"`
	BlockTime        *uint64                 `json:"block_time,omitempty"`
	Payer            string                  `json:"payer,omitempty"`
	Warnings         []string                `json:"warnings,omitempty"`
	DAIncluded       *DAIncludedJSON         `json:"da_included,omitempty"`
	Deposit          *edenescrow.DepositView `json:"deposit,omitempty"`
	Sources          []SourceJSON            `json:"sources"`
}

// Origins of an operator label in the report.
const (
	LabelExplicit = "explicit"
	LabelDefault  = "default"
)

// DAIncludedJSON is the own ev-node's word that the block's data is in
// Celestia at Height.
type DAIncludedJSON struct {
	Height uint64 `json:"height"`
	Source string `json:"source"`
}

// SourceJSON is one source asked. Result is used or agree for a passing
// source, else what its answer amounts to: not_found, unconfirmed,
// unavailable or set_aside.
type SourceJSON struct {
	Name     string `json:"name"`
	Class    string `json:"class"`
	Operator string `json:"operator"`
	// OperatorLabel is explicit for a configured label, default when the
	// host stands in.
	OperatorLabel string `json:"operator_label"`
	Result        string `json:"result"`
	Reason        string `json:"reason,omitempty"`
	Error         string `json:"error,omitempty"`
}

// JSON returns the report with the profile's field names.
func (r Report) JSON() ReportJSON {
	v := ReportJSON{
		Profile: Profile, Status: string(r.Status), Reason: string(r.Reason),
		RailRef: r.RailRef, ChainID: r.ChainID, Warnings: r.Warnings, Deposit: r.Deposit, Sources: []SourceJSON{},
	}
	if r.Err != nil {
		v.Error = r.Err.Error()
	}
	if r.Status == StatusPass {
		v.Level, v.Outcome = r.Level.String(), string(r.Outcome)
	}
	if r.HasBlock {
		n, i, t := r.Block, r.Index, r.BlockTime
		v.BlockNumber, v.TransactionIndex, v.BlockTime = &n, &i, &t
		v.BlockHash = "0x" + hex.EncodeToString(r.BlockHash[:])
	}
	if r.HasPayer {
		v.Payer = "0x" + hex.EncodeToString(r.Payer[:])
	}
	if d := r.DA; d != nil && d.Err == nil && d.Included {
		v.DAIncluded = &DAIncludedJSON{Height: d.Height, Source: d.Source}
	}
	for _, s := range r.Sources {
		sj := SourceJSON{Name: s.Name, Class: s.Class.String(), Operator: s.Operator, OperatorLabel: LabelDefault,
			Result: s.Result, Reason: string(s.Reason)}
		if s.OperatorExplicit {
			sj.OperatorLabel = LabelExplicit
		}
		if s.Result == SourceSetAside && s.State != "" {
			sj.Result = string(s.State)
		}
		if s.Err != nil {
			sj.Error = s.Err.Error()
		}
		v.Sources = append(v.Sources, sj)
	}
	return v
}
