// SPDX-License-Identifier: Apache-2.0

// Package signercmd is the command line of the executor after the gate,
// shared by the edicta-signer command and edicta signer serve. The executor
// holds the payer key and signs an Eden escrow deposit only for a decision
// that carries both the agent's signed envelope and the gate's Authorization
// for exactly those action bytes. It sends the transaction, waits for Eden to
// include it, and then asks the gate to record the rail_ref with its executor
// key.
package signercmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vgonkivs/edicta/services/signer/signerd"
)

// Main runs the signer until SIGINT or SIGTERM. args is the command line as in
// os.Args: args[0] names the command in the usage text. It returns the exit
// code: 0 after a clean stop or -h, 2 on a flag error, 1 otherwise.
func Main(args []string, stdout, stderr io.Writer) int {
	name, rest := "edicta-signer", args
	if len(args) > 0 {
		name, rest = args[0], args[1:]
	}
	// ContinueOnError with these codes prints and exits as the ExitOnError
	// global flag set the signer used to parse with.
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path of edicta-signer.toml")
	check := fs.Bool("check-config", false, "validate the configuration and exit, without reading keys or calling any RPC")
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := run(*path, *check, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, selfName(name)+":", err)
		return 1
	}
	return 0
}

// selfName is the name the signer gives itself in its error messages: the
// subcommand when the edicta command runs it, the standalone binary otherwise.
func selfName(argv0 string) string {
	if strings.HasSuffix(argv0, " signer serve") {
		return "edicta signer serve"
	}
	return "edicta-signer"
}

func run(path string, check bool, stdout, stderr io.Writer) error {
	if path == "" {
		return errors.New("-config is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	cfg, err := signerd.ParseConfig(data)
	if err != nil {
		return err
	}
	cfg.ApplyDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return err
	}
	if check {
		fmt.Fprintln(stdout, "configuration ok")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(stderr, nil))
	d, err := signerd.Build(ctx, cfg, log)
	if err != nil {
		return err
	}
	return d.Serve(ctx, nil)
}
