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
	"github.com/vgonkivs/edicta/celestia/verifycli"
)

const fastUsage = "usage: edicta demo fast-mode [--dir DIR] [--json]"

const fastLiveUsage = "usage: edicta demo fast-live [--restart] [--max-recorder-funding UTIA] [--network mocha] [--home DIR] [--json] " +
	"[--funder-keyring-dir DIR --funder-key NAME [--funder-passphrase-file FILE] [--address ADDR]] " +
	"[--max-total-funding UTIA [--yes]] [--trusted-header H:HASH]"

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
	demoFlags(fs, &c)
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return c, nil
}

func parseFastLive(args []string, out io.Writer) (demo.FastLiveConfig, error) {
	var c demo.FastLiveConfig
	fs := flag.NewFlagSet("demo fast-live", flag.ContinueOnError)
	fs.SetOutput(out)
	demoFlags(fs, &c.Config)
	fs.BoolVar(&c.Restart, "restart", false, "stop the in-process edictad before the anchor lands and start it again")
	fs.Uint64Var(&c.MaxRecorderFunding, "max-recorder-funding", 0, "cap of one funding send to the run's Recorder account (utia); default 20000")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return c, nil
}

// demoFlags are the flags the live scenes share: network, funder and
// endpoints.
func demoFlags(fs *flag.FlagSet, c *demo.Config) {
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
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// runDemo returns the demo's exit code: 0 ok, 1 wrong, 2 inconclusive,
// 3 not authorized, 4 usage, 130 interrupted.
func runDemo(ctx context.Context, args []string, out io.Writer, in *os.File) int {
	if len(args) > 0 && args[0] == "fast-mode" {
		return runFastDemo(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "fast-live" {
		return runFastLive(ctx, args[1:], out, in)
	}
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

// runFastLive runs fast mode on the live network with the exit codes of
// runDemo.
func runFastLive(ctx context.Context, args []string, out io.Writer, in *os.File) int {
	cfg, err := parseFastLive(args, out)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n%s\n", err, fastLiveUsage)
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
	deps, closeDeps, err := demo.RealDeps(cfg.Config, console, demo.NewScreen(out, isTTY(out), cfg.JSON))
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitCodeOf(err)
	}
	defer closeDeps()
	f, err := demo.NewFastLive(cfg, deps)
	if err != nil {
		fmt.Fprintf(out, "edicta: %v\n", err)
		return demo.ExitCodeOf(err)
	}
	res, _ := f.Run(ctx)
	return res.Code
}

// runFastDemo runs the offline fast-mode scene: 0 when the verifier ended as
// the scene expects, 1 when it did not, 4 on bad flags.
func runFastDemo(ctx context.Context, args []string, out io.Writer) int {
	var cfg demo.FastSceneConfig
	var jsonOut bool
	fs := flag.NewFlagSet("demo fast-mode", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.Dir, "dir", "", "where the kept run directory is created; default the system temp directory")
	fs.BoolVar(&jsonOut, "json", false, "print one JSON event per line")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(out, fastUsage)
		return demo.ExitUsage
	}
	res, _ := demo.RunFastScene(ctx, cfg, demo.NewScreen(out, isTTY(out), jsonOut), verifycli.Run)
	return res.Code
}
