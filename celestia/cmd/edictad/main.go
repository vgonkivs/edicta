// Command edictad is the gate and optional Recorder daemon.
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
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
)

// errNoAdapters is returned until the consensus and keyring adapters over the
// node seam exist; the daemon never starts without them.
var errNoAdapters = errors.New("this build has no consensus gRPC or keyring submitter adapter")

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "edictad:", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "path of the TOML configuration")
	printCfg := flag.Bool("print-config", false, "print the parsed configuration (paths only, no secrets) and exit")
	flag.Parse()
	if *path == "" {
		return errors.New("-config is required")
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	cfg, err := edictad.ParseConfig(data)
	if err != nil {
		return err
	}
	if *printCfg {
		out, err := toml.Marshal(cfg)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(out)
		return err
	}

	rd, cons, sub, err := adapters(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := edictad.Start(ctx, cfg, edictad.Deps{Reader: rd, Consensus: cons, Submitter: sub, Logger: log})
	if err != nil {
		return err
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func adapters(edictad.Config) (node.Reader, node.Consensus, recorder.Submitter, error) {
	return nil, nil, nil, errNoAdapters
}
