// SPDX-License-Identifier: Apache-2.0

// Package clicmd holds the bodies of the edicta subcommands init, doctor,
// commit, agent and verify|replay|absence. Each parses its own arguments with
// the standard flag package and returns the exit code.
package clicmd

import (
	"context"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/vgonkivs/edicta/services/cli/verifycli"
)

// Init runs edicta init; args follow the subcommand.
func Init(args []string, stdout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runInit(ctx, args, stdout)
}

// Doctor runs edicta doctor; args follow the subcommand.
func Doctor(args []string, stdout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDoctor(ctx, args, stdout)
}

// Commit runs edicta commit; args follow the subcommand.
func Commit(args []string, stdin io.Reader, stdout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCommit(ctx, args, stdout, stdin)
}

// Agent runs edicta agent; args follow the subcommand and start with serve.
func Agent(args []string, stdout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx, args, stdout)
}

// Verify runs edicta verify, replay or absence; args[0] is the subcommand.
// The defaults of the flags not given come from edicta.toml unless
// --no-config is given, which runs the command on its flags alone.
func Verify(args []string, stdout io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rest, noConfig := withoutNoConfig(args)
	if noConfig {
		return verifycli.Run(ctx, rest, stdout)
	}
	return verifycli.RunWith(ctx, rest, stdout, verifyDefaults)
}

// withoutNoConfig removes every --no-config switch before the "--" that ends
// the flags and reports whether the last one was on. With it on, the command
// runs without the config support at all, so it parses, prints its usage and
// fails exactly as the verifier that never read a config did: --config is
// then an unknown flag. The config-reading flag set lists --no-config only for
// its help; a value that is not a boolean is left in place, and that flag set
// refuses it.
func withoutNoConfig(args []string) ([]string, bool) {
	if len(args) == 0 {
		return args, false
	}
	rest := []string{args[0]}
	on := false
	for i, a := range args[1:] {
		if a == "--" {
			rest = append(rest, args[1+i:]...)
			break
		}
		v, ok := noConfigValue(a)
		if !ok {
			rest = append(rest, a)
			continue
		}
		on = v
	}
	return rest, on
}

// noConfigValue parses a as -no-config or --no-config, bare or with =BOOL.
func noConfigValue(a string) (on, ok bool) {
	name, val, hasVal := strings.Cut(a, "=")
	if name != "-no-config" && name != "--no-config" {
		return false, false
	}
	if !hasVal {
		return true, true
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false, false
	}
	return b, true
}
