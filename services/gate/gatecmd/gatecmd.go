// SPDX-License-Identifier: Apache-2.0

// Package gatecmd is the command line of the gate and optional Recorder
// daemon: edicta gate serve.
package gatecmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/gate/edictad"
	"github.com/vgonkivs/edicta/services/gate/edictad/wire"
)

// self is the command's name in its error messages.
const self = "edicta gate serve"

// Main runs the daemon until SIGINT or SIGTERM. args is the command line as in
// os.Args: args[0] names the command in the usage text. It returns the exit
// code: 0 after a clean stop or -h, 2 on a flag error, 1 otherwise.
func Main(args []string, stdout, stderr io.Writer) int {
	name, rest := self, args
	if len(args) > 0 {
		name, rest = args[0], args[1:]
	}
	// ContinueOnError with these codes prints and exits as the ExitOnError
	// global flag set the daemon used to parse with.
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path of edicta.toml or of the legacy edictad.toml")
	printCfg := fs.Bool("print-config", false, "print the parsed configuration (paths only, no secrets) and exit")
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := run(*path, *printCfg, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, self+":", err)
		return 1
	}
	return 0
}

// loadConfig reads edicta.toml when the file names a Celestia network and the
// legacy edictad.toml otherwise.
func loadConfig(data []byte) (edictad.Config, error) {
	if !config.IsEdictaConfig(data) {
		return edictad.ParseConfig(data)
	}
	c, err := config.Parse(data, nil)
	if err == nil {
		err = c.ApplyDefaults(config.Builtin{})
	}
	if err == nil {
		err = c.ValidateBasic()
	}
	if err != nil {
		return edictad.Config{}, err
	}
	return edictad.FromEdicta(c)
}

func run(path string, printCfg bool, stdout, stderr io.Writer) error {
	if path == "" {
		return errors.New("-config is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	cfg, err := loadConfig(data)
	if err != nil {
		return err
	}
	if printCfg {
		out, err := toml.Marshal(cfg)
		if err != nil {
			return err
		}
		_, err = stdout.Write(out)
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(stderr, nil))
	deps, closeAll, err := wire.Adapters(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeAll()
	srv, err := edictad.Start(ctx, cfg, deps)
	if err != nil {
		return err
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownBudget())
	defer cancel()
	return srv.Shutdown(sctx)
}
