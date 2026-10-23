// SPDX-License-Identifier: Apache-2.0

// Command edicta is the Edicta command line: the agent's tools, the verifier,
// the gate and signer daemons and the principal's mandate tool, as
// subcommands. Run edicta --help for the list.
package main

import (
	"os"

	"github.com/vgonkivs/edicta/services/cli/edictacli"
)

func main() { os.Exit(edictacli.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
