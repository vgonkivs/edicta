// Command edicta is the Edicta command line.
//
//	edicta verify|replay <commitment_hash> --gate-key HEX ...
//	edicta init [--home DIR] [--preset CELESTIA+SETTLEMENT] [--set network.key=value]... [--max-per-payment USDC] [--max-per-hour USDC]
//	edicta doctor [--config PATH] [--set key=value]... [--json]
//	edicta commit [flags]
//	edicta agent serve [flags]
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgonkivs/edicta/celestia/verifycli"
)

const usage = "usage: edicta init [--home DIR] [--preset CELESTIA+SETTLEMENT] [--set network.key=value]... [--max-per-payment USDC] [--max-per-hour USDC] | doctor [--config PATH] [--set key=value]... [--json] | commit [--request FILE|-] [flags] | agent serve [--listen ADDR] [flags] | verify|replay <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) [--config PATH] [flags]"

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, usage)
		return 4
	}
	switch args[0] {
	case "init":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runInit(ctx, args[1:], out)
	case "doctor":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runDoctor(ctx, args[1:], out)
	case "commit":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runCommit(ctx, args[1:], out, os.Stdin)
	case "agent":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAgent(ctx, args[1:], out)
	case "verify", "replay":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return verifycli.RunWith(ctx, args, out, verifyDefaults)
	}
	fmt.Fprintf(out, "edicta: unknown subcommand %q\n%s\n", args[0], usage)
	return 4
}
