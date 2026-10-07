// Command edicta is the Edicta command line.
//
//	edicta verify|replay <commitment_hash> --gate-key HEX ...
//	edicta demo [flags]
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/vgonkivs/edicta/celestia/verifycli"
)

const usage = "usage: edicta demo | verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) [flags]"

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, usage)
		return 4
	}
	switch args[0] {
	case "demo":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runDemo(ctx, args[1:], out, os.Stdin)
	case "verify", "replay":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return verifycli.Run(ctx, args, out)
	}
	fmt.Fprintf(out, "edicta: unknown subcommand %q\n%s\n", args[0], usage)
	return 4
}
