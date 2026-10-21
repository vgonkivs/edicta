// SPDX-License-Identifier: Apache-2.0

package verifycli

import (
	"context"
	"fmt"
	"io"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/edenexec"
	"github.com/vgonkivs/edicta/edenexec/edenrpc"
	"github.com/vgonkivs/edicta/verifier"
)

// settlementFlags select the Eden settlement report. Own nodes are asked
// before public RPCs, each group in the order given. Without
// --settlement-level the report needs L1, so one source alone reports at
// most that the level was not reached, or a wrong transaction; asking for
// a level that the given sources can never reach is a usage error.
type settlementFlags struct {
	on      bool
	rpc     []string
	ownRPC  []string
	da      string
	level   string
	sources int
	depth   uint64
}

func (s settlementFlags) validate(cmd, receiptPath string) error {
	given := len(s.rpc) > 0 || len(s.ownRPC) > 0 || s.da != "" || s.level != "" || s.sources != 0 || s.depth != 0
	switch {
	case !s.on && given:
		return usagef("--settlement-rpc, --settlement-own-rpc, --settlement-da, --settlement-level, --settlement-min-sources and --settlement-confirm-depth are used only with --settlement")
	case !s.on:
		return nil
	case cmd != "verify":
		return usagef("only verify takes --settlement")
	case receiptPath == "":
		return usagef("--settlement needs --receipt: the report checks the transaction the receipt names")
	case len(s.rpc)+len(s.ownRPC) == 0:
		return usagef("--settlement needs at least one --settlement-rpc or --settlement-own-rpc")
	}
	_, err := s.checker()
	return err
}

// checker builds the Eden settlement checker of the flags.
func (s settlementFlags) checker() (*edenexec.Checker, error) {
	cfg := edenexec.Config{MinSources: s.sources, ConfirmDepth: s.depth}
	if s.level != "" {
		l, err := edenexec.ParseLevel(s.level)
		if err != nil {
			return nil, usagef("--settlement-level: %v", err)
		}
		cfg.MinLevel = l
	}
	cfg.ApplyDefaults()
	var srcs []edenexec.Source
	add := func(urls []string, class edenexec.SourceClass, flag string) error {
		for _, u := range urls {
			c := edenrpc.Config{URL: u, Class: class}
			c.ApplyDefaults()
			src, err := edenrpc.New(c, nil)
			if err != nil {
				return usagef("%s %q: %v", flag, u, err)
			}
			srcs = append(srcs, src)
		}
		return nil
	}
	if err := add(s.ownRPC, edenexec.ClassOwnNode, "--settlement-own-rpc"); err != nil {
		return nil, err
	}
	if err := add(s.rpc, edenexec.ClassPublicRPC, "--settlement-rpc"); err != nil {
		return nil, err
	}
	var da edenexec.DAStatus
	if s.da != "" {
		c := edenrpc.StoreConfig{URL: s.da}
		c.ApplyDefaults()
		st, err := edenrpc.NewStore(c, nil)
		if err != nil {
			return nil, usagef("--settlement-da %q: %v", s.da, err)
		}
		da = st
	}
	if s.level != "" && cfg.MinLevel >= edenexec.LevelMultiSource && edenexec.Operators(srcs) < cfg.MinSources {
		return nil, usagef("--settlement-level %s needs %d sources of distinct operators, %d given",
			cfg.MinLevel, cfg.MinSources, edenexec.Operators(srcs))
	}
	chk, err := edenexec.NewChecker(cfg, srcs, da)
	if err != nil {
		return nil, usagef("settlement: %v", err)
	}
	return chk, nil
}

// newSettlements is a variable so tests can serve the sources without a
// network.
var newSettlements = func(s settlementFlags) (map[string]verifier.SettlementChecker, error) {
	chk, err := s.checker()
	if err != nil {
		return nil, err
	}
	return map[string]verifier.SettlementChecker{edenescrow.ActionType: edenSettlement{chk}}, nil
}

// edenSettlement adapts the Eden checker to the verifier's report hook.
type edenSettlement struct{ chk *edenexec.Checker }

func (e edenSettlement) CheckSettlement(ctx context.Context, in verifier.SettlementInput) (any, error) {
	return e.chk.SettlementOfAction(ctx, in.Action, in.RailRef, in.Expires, in.TRef)
}

// settlementView is the printed settlement report. It is a separate field
// from the core's anchor "settlement" level, and no exit code reads it.
type settlementView struct {
	Status    string `json:"status"`
	BlockedOn string `json:"blocked_on,omitempty"`
	Error     string `json:"error,omitempty"`
}

func viewOfSettlement(info *verifier.SettlementInfo) any {
	if info == nil {
		return nil
	}
	if info.Blocked != "" {
		return settlementView{Status: "not_run", BlockedOn: info.Blocked}
	}
	if rep, ok := info.Result.(edenexec.Report); ok {
		v := rep.JSON()
		if info.Err != nil && v.Error == "" {
			v.Error = info.Err.Error()
		}
		return v
	}
	return settlementView{Status: string(edenexec.StatusUnchecked), Error: errText(info.Err)}
}

// writeSettlementText prints the report beside the core report. Text that
// sources supplied is quoted, so it cannot drive the terminal.
func writeSettlementText(out io.Writer, v any) {
	p := func(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }
	switch s := v.(type) {
	case settlementView:
		if s.BlockedOn != "" {
			p("rail settlement: not run, blocked on %s", s.BlockedOn)
		} else {
			p("rail settlement: %s, error %q", s.Status, s.Error)
		}
	case edenexec.ReportJSON:
		line := fmt.Sprintf("rail settlement (%s, does not change the verdict): %s", s.Profile, s.Status)
		if s.Level != "" {
			line += fmt.Sprintf(" at %s, outcome %s", s.Level, s.Outcome)
		}
		if s.Reason != "" {
			line += ", " + s.Reason
		}
		p("%s", line)
		if s.BlockNumber != nil {
			p("rail settlement block: %d (hash %s), index %d, block time %d", *s.BlockNumber, s.BlockHash, *s.TransactionIndex, *s.BlockTime)
		}
		if s.Payer != "" {
			p("rail settlement payer: %s", s.Payer)
		}
		if s.DAIncluded != nil {
			p("rail settlement data in Celestia at height %d, by %s (node-attested)", s.DAIncluded.Height, s.DAIncluded.Source)
		}
		for _, w := range s.Warnings {
			p("rail settlement warning: %s", w)
		}
		for _, src := range s.Sources {
			line := fmt.Sprintf("rail settlement source %s (%s): %s", src.Name, src.Class, src.Result)
			if src.Reason != "" {
				line += ", " + src.Reason
			}
			p("%s", line)
		}
		if s.Error != "" {
			p("rail settlement detail: %q", s.Error)
		}
	}
}
