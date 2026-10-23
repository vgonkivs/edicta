// SPDX-License-Identifier: Apache-2.0

// Command edicta-principal is the principal's tool for mandates. It links only
// the root module, so the process that holds the principal key carries no
// Celestia node or chain stack; edicta principal runs the same code.
package main

import (
	"os"

	"github.com/vgonkivs/edicta/internal/principalcli"
)

func main() { os.Exit(principalcli.Main(os.Args, os.Stdout, os.Stderr)) }
