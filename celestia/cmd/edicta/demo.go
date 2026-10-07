package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/vgonkivs/edicta/celestia/demo"
)

const demoUsage = "usage: edicta demo [--network mocha] [--home DIR] [--amount UTIA] [--json] " +
	"[--funder-keyring-dir DIR --funder-key NAME [--funder-passphrase-file FILE] [--address ADDR]] " +
	"[--max-total-funding UTIA [--yes]] [--trusted-header H:HASH]"

func defaultHome() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".edicta-demo")
}

func parseDemo(args []string, out io.Writer) (demo.Config, error) {
	var c demo.Config
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&c.Network, "network", "mocha", "network preset")
	fs.StringVar(&c.Home, "home", defaultHome(), "demo home directory; chain keys and run directories live here")
	fs.Uint64Var(&c.AmountUTIA, "amount", 1000, "utia the agent decides to send")
	fs.BoolVar(&c.JSON, "json", false, "print one JSON event per line")
	fs.StringVar(&c.Funder.KeyringDir, "funder-keyring-dir", "", "file keyring of an account you already have")
	fs.StringVar(&c.Funder.KeyName, "funder-key", "", "key name in that keyring")
	fs.StringVar(&c.Funder.PassphraseFile, "funder-passphrase-file", "", "file (mode 0600) with the keyring passphrase; otherwise prompted without echo")
	fs.StringVar(&c.Funder.Address, "address", "", "expected funder address; must equal the key's address")
	fs.Uint64Var(&c.MaxTotalFunding, "max-total-funding", 0, "raise the lifetime funding cap (utia); asks for a confirmation")
	fs.BoolVar(&c.YesFundingCap, "yes", false, "confirm --max-total-funding without asking; does not start the run")
	fs.StringVar(&c.TrustedHeader, "trusted-header", "", "HEIGHT:HASH from a source you choose, instead of the explorer")
	fs.DurationVar(&c.FundTimeout, "fund-timeout", 5*time.Minute, "how long to wait for funds before asking")
	fs.DurationVar(&c.PollEvery, "poll-every", 5*time.Second, "poll interval while waiting")
	fs.StringVar(&c.Overrides.ExplorerTxURL, "explorer-tx-url", "", "explorer tx link template with {hash}")
	fs.StringVar(&c.Overrides.ExplorerBlockURL, "explorer-block-url", "", "explorer block link template with {height}")
	fs.StringVar(&c.Overrides.HeadersRPC, "headers-rpc", "", "CometBFT RPC for headers (untrusted)")
	fs.StringVar(&c.Overrides.TxRPC, "tx-rpc", "", "CometBFT RPC for the transaction and its proofs")
	fs.StringVar(&c.Overrides.TrustRootAPI, "trust-root-api", "", "trust-root block API template with {height}")
	fs.StringVar(&c.Overrides.TrustRootPage, "trust-root-page", "", "trust-root block page template with {height}")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return c, nil
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// runDemo returns the demo's exit code: 0 ok, 1 wrong, 2 inconclusive,
// 3 not authorized, 4 usage, 130 interrupted.
func runDemo(ctx context.Context, args []string, out io.Writer, in *os.File) int {
	cfg, err := parseDemo(args, out)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n%s\n", err, demoUsage)
		return demo.ExitUsage
	}
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitUsage
	}
	console, err := demo.NewTerminalConsole(in, out)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitUsage
	}
	screen := demo.NewScreen(out, isTTY(out), cfg.JSON)
	deps, closeDeps, err := demo.RealDeps(cfg, console, screen)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitCodeOf(err)
	}
	defer closeDeps()
	r, err := demo.New(cfg, deps)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitCodeOf(err)
	}
	res, _ := r.Run(ctx)
	return res.Code
}
