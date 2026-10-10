// Command edicta-verify re-checks an archived decision. It is the verify and
// replay of the edicta command, kept under its old name:
//
//	edicta-verify verify|replay --archive DIR --gate-key HEX [--trusted FILE]
//	    [--absence-source URL] [--skew SECONDS] [--blob-retention SECONDS] [--json] <commitment_hash>
//	edicta-verify absence --archive DIR --gate-key HEX --absence-source URL
//	    (--trusted FILE | --headers-rpc URL --checkpoint H:HASH) <commitment_hash>
//
// The flags, the output and the exit codes are those of the verifycli
// package.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"

	"github.com/vgonkivs/edicta/celestia/verifycli"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return verifycli.Run(ctx, args, out)
}
