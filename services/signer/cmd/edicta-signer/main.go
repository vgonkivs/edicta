// SPDX-License-Identifier: Apache-2.0

// Command edicta-signer is the executor after the gate: it holds the payer
// key and signs an Eden escrow deposit only for a decision that carries both
// the agent's signed envelope and the gate's Authorization for exactly those
// action bytes. It links no Celestia node or chain stack, which keeps the
// process that holds a spendable key small; edicta signer serve runs the same
// code.
package main

import (
	"os"

	"github.com/vgonkivs/edicta/services/signer/signercmd"
)

func main() { os.Exit(signercmd.Main(os.Args, os.Stdout, os.Stderr)) }
