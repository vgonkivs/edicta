package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/services/cli/doctor"
)

// Exit codes follow the other subcommands: 1 for a failed check, 4 for misuse.
const (
	doctorFailed = 1
	doctorUsage  = 4
)

// doctorEnv and doctorChecks are the seams unit tests replace so that no
// probe touches the network.
var (
	doctorEnv    = doctor.NewSystemEnv
	doctorChecks = doctor.Checks
)

type setFlags []string

func (s *setFlags) String() string     { return strings.Join(*s, ",") }
func (s *setFlags) Set(v string) error { *s = append(*s, v); return nil }

func (s setFlags) overrides() (map[string]string, error) {
	if len(s) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(s))
	for _, kv := range s {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--set %q: want key=value", kv)
		}
		m[k] = v
	}
	return m, nil
}

func runDoctor(ctx context.Context, args []string, out io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "path to edicta.toml (default: the Edicta home)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var sets setFlags
	fs.Var(&sets, "set", "override one config key, key=value (repeatable)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			err = fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		fmt.Fprintf(out, "edicta doctor: %v\nusage: edicta doctor [--config PATH] [--set key=value]... [--json]\n", err)
		return doctorUsage
	}
	overrides, err := sets.overrides()
	if err != nil {
		fmt.Fprintf(out, "edicta doctor: %v\n", err)
		return doctorUsage
	}
	if *path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			fmt.Fprintf(out, "edicta doctor: %v\n", err)
			return doctorUsage
		}
		*path = p
	}

	presets := config.Builtin{}
	cfg, loadErr := config.LoadValid(*path, overrides, presets)
	var rep doctor.Report
	if loadErr != nil {
		rep = doctor.Run(ctx, config.Config{}, []doctor.Check{doctor.ConfigCheck{Err: loadErr}})
	} else {
		cc := doctor.ConfigCheck{}
		cc.Drift, err = cfg.Drift(presets)
		if err != nil {
			cc.Err = err
		}
		cc.Presets = describePresets(cfg, presets)
		env := doctorEnv()
		defer func() { _ = env.Close() }()
		rep = doctor.Run(ctx, cfg, doctorChecks(env, cc))
	}

	var werr error
	if *asJSON {
		werr = rep.WriteJSON(out)
	} else {
		werr = rep.WriteText(out)
	}
	if werr != nil {
		fmt.Fprintf(out, "edicta doctor: writing the report: %v\n", werr)
		return doctorFailed
	}
	if rep.Failed() {
		return doctorFailed
	}
	return 0
}

func describePresets(c config.Config, p config.Presets) string {
	v, err := c.Versions(p)
	if err != nil {
		return "presets: " + c.Network.Celestia + ", " + c.Network.Settlement
	}
	return fmt.Sprintf("celestia %s v%d, settlement %s v%d", c.Network.Celestia, v.Celestia, c.Network.Settlement, v.Settlement)
}
