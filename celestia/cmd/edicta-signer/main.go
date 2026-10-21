// SPDX-License-Identifier: Apache-2.0

// Command edicta-signer is the executor after the gate: it holds the payer
// key and signs an Eden escrow deposit only for a decision that carries both
// the agent's signed envelope and the gate's Authorization for exactly those
// action bytes. It sends the transaction, waits for Eden to include it, and
// then asks the gate to record the rail_ref with its executor key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgonkivs/edicta/celestia/signerd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edicta-signer:", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "path of edicta-signer.toml")
	check := flag.Bool("check-config", false, "validate the configuration and exit, without reading keys or calling any RPC")
	flag.Parse()
	if *path == "" {
		return errors.New("-config is required")
	}
	data, err := os.ReadFile(*path)
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
	if *check {
		fmt.Println("configuration ok")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	d, err := signerd.Build(ctx, cfg, log)
	if err != nil {
		return err
	}
	return d.Serve(ctx, nil)
}
