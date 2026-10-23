// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package edictacli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/vgonkivs/edicta/services/cli/devinitcmd"
)

// addDev registers edicta dev init and reports that it did.
func addDev(root *cobra.Command, stdout, stderr io.Writer, code *int) bool {
	root.AddCommand(group("dev", "DEV ONLY: the local compose stack", stdout, code,
		leaf("init", "Create the DEV keys, configuration and Eden genesis", code, func(a []string) int {
			return devinitcmd.Main(append([]string{argv0() + " dev init"}, a...), stdout, stderr)
		})))
	return true
}
