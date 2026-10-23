// SPDX-License-Identifier: Apache-2.0

//go:build !edictadev

package edictacli

import (
	"io"

	"github.com/spf13/cobra"
)

// addDev adds nothing: edicta dev exists only in builds with the edictadev tag.
func addDev(*cobra.Command, io.Writer, io.Writer, *int) bool { return false }
