// Command edicta-live runs the live demo end to end against a running
// edictad and a real network: a price agent publishes its decision, the gate
// authorizes it, an executor with its own chain key performs the transfer
// with the commitment hash as memo, and the run prints the evidence.
//
// It takes no network name: endpoints and keys come from flags. Secrets are
// read from files (or a no-echo prompt) and are never printed.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := execute(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Stdin)
	stop()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "edicta-live: FAILED:", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, out, logw io.Writer, in *os.File) error {
	if len(args) > 0 && args[0] == "pubkey" {
		return pubkeyCmd(args[1:], out)
	}
	cfg, err := parseFlags(args, logw)
	if err != nil {
		return err
	}
	return live(ctx, cfg, runEnv{Out: out, Log: logw, Stdin: in})
}

// pubkeyCmd prints the Ed25519 public key (hex) of a 32-byte seed file: the
// value for edictad's agents file and executor_keys.
func pubkeyCmd(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: edicta-live pubkey <seed-file>")
	}
	k, err := readSeed(args[0], "seed")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	return err
}
