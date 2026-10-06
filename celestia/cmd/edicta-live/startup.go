package main

import (
	"context"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

// startupCheck runs the compatibility check of the data availability mode and
// returns the head it validated.
func startupCheck(ctx context.Context, cfg Config, rd node.Reader, cons node.Consensus) (node.Header, error) {
	e := node.Expect{ChainID: cfg.ChainID, MinAppVersion: cfg.MinAppVersion, MaxAppVersion: cfg.MaxAppVersion}
	if cfg.DA == "fibre" {
		st, err := node.CheckFibre(ctx, rd, cons, node.FibreExpect{Expect: e})
		return st.Head, err
	}
	return node.Check(ctx, rd, cons, e)
}

// decisionBytes is the payload size the escrow line counts decisions in.
const decisionBytes = 1024

// logEscrow reports the Recorder's Fibre escrow. It only reads: it never
// refuses the run, since the Recorder refuses a short escrow itself, and
// never deposits.
func logEscrow(ctx context.Context, logf func(string, ...any), cons *node.ConsensusClient, recorderSigner []byte) {
	addr, err := bech32.ConvertAndEncode("celestia", recorderSigner)
	if err != nil {
		logf("recorder escrow: not read: %v", err)
		return
	}
	esc, err := cons.EscrowAccount(ctx, addr)
	if err != nil {
		logf("recorder escrow: not read: %v", err)
		return
	}
	us, err := fibrecommit.UploadSize(decisionBytes)
	if err != nil {
		logf("recorder escrow: not read: %v", err)
		return
	}
	per := recorder.FibreCostUtia(us)
	k := esc.AvailableUtia / per
	logf("recorder escrow %d utia (~%d decisions of 1 KiB)", esc.AvailableUtia, k)
	if k < 1 {
		logf("WARNING: recorder escrow is below the cost of one decision (%d utia); fund it before publishing", per)
	}
}
