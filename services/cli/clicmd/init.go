package clicmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/doctor"
	"github.com/vgonkivs/edicta/services/cli/initcmd"
)

const initUsage = "usage: edicta init [--home DIR] [--preset CELESTIA+SETTLEMENT] [--set network.key=value]... [--max-per-payment USDC] [--max-per-hour USDC]"

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
	perPayment := fs.String("max-per-payment", "", "starter mandate limit per payment, in USDC (default 0.10)")
	perHour := fs.String("max-per-hour", "", "starter mandate limit per rolling hour, in USDC (default 1)")
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
	var limits [2]uint64
	for i, f := range []struct{ name, v string }{{"max-per-payment", *perPayment}, {"max-per-hour", *perHour}} {
		if f.v == "" {
			continue
		}
		if limits[i], err = parseUSDC(f.v); err != nil {
			fmt.Fprintf(out, "edicta init: --%s: %v\n", f.name, err)
			return doctorUsage
		}
	}
	if *home == "" {
		if *home, err = config.Home(); err != nil {
			fmt.Fprintf(out, "edicta init: %v\n", err)
			return doctorUsage
		}
	}

	env := initEnv()
	defer func() { _ = env.Close() }()
	res, err := initRun(ctx, initcmd.Config{
		Home: *home, Preset: *preset, Overrides: overrides,
		MaxPerPayment: limits[0], MaxPerHour: limits[1],
	}, env, nil)
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
	if limited := *perPayment != "" || *perHour != ""; limited && (res.Mandate != nil && res.Mandate.Status == initcmd.Exists || res.Config.Status == initcmd.Exists) {
		fmt.Fprintln(out, "the mandate or edicta.toml exists: --max-per-* is not applied to it; sign a new mandate version to change the limits")
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

// parseUSDC reads a positive decimal USDC amount, at most six decimals, as
// base units.
func parseUSDC(s string) (uint64, error) {
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" || len(frac) > initcmd.USDCScale || !digits(whole) || !digits(frac) {
		return 0, fmt.Errorf("%q is not a USDC amount like 0.25", s)
	}
	frac += strings.Repeat("0", initcmd.USDCScale-len(frac))
	v, err := strconv.ParseUint(whole+frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is too large an amount", s)
	}
	if v == 0 {
		return 0, fmt.Errorf("%q is not a positive USDC amount", s)
	}
	return v, nil
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
