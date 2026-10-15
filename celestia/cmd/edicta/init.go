package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/initcmd"
)

const initUsage = "usage: edicta init [--home DIR] [--preset CELESTIA+SETTLEMENT] [--set network.key=value]..."

// initEnv and initRun are the seams unit tests replace so that no probe
// touches the network.
var (
	initEnv = doctor.NewSystemEnv
	initRun = initcmd.Run
)

func runInit(ctx context.Context, args []string, out io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	home := fs.String("home", "", "the Edicta home directory (default: $"+config.EnvHome+", else ~/.edicta)")
	preset := fs.String("preset", initcmd.DefaultPreset, "celestia network and settlement chain, joined by +")
	var sets setFlags
	fs.Var(&sets, "set", "override one network key, network.key=value (repeatable)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		fmt.Fprintf(out, "edicta init: %v\n%s\n", err, initUsage)
		return doctorUsage
	}
	overrides, err := sets.overrides()
	if err != nil {
		fmt.Fprintf(out, "edicta init: %v\n", err)
		return doctorUsage
	}
	if *home == "" {
		if *home, err = config.Home(); err != nil {
			fmt.Fprintf(out, "edicta init: %v\n", err)
			return doctorUsage
		}
	}

	env := initEnv()
	defer func() { _ = env.Close() }()
	res, err := initRun(ctx, initcmd.Config{Home: *home, Preset: *preset, Overrides: overrides}, env, nil)
	if len(res.Preflight.Items) > 0 && (err != nil || res.Preflight.Count(doctor.OK) != len(res.Preflight.Items)) {
		fmt.Fprintln(out, "preflight:")
		if werr := res.Preflight.WriteText(out); werr != nil {
			return doctorFailed
		}
	}
	if err == nil || !errors.Is(err, initcmd.ErrPreflight) {
		if werr := res.WriteText(out); werr != nil {
			fmt.Fprintf(out, "edicta init: writing the report: %v\n", werr)
			return doctorFailed
		}
	}
	if err != nil {
		fmt.Fprintf(out, "edicta init: %v\n", err)
		if errors.Is(err, initcmd.ErrConfig) || errors.Is(err, config.ErrConfig) || errors.Is(err, config.ErrPreset) {
			return doctorUsage
		}
		return doctorFailed
	}
	return 0
}
