// SPDX-License-Identifier: Apache-2.0

// Package edictacli routes the edicta command line to its subcommands:
//
//	edicta init | doctor | commit | agent serve
//	edicta verify | replay | absence <commitment_hash> [flags]
//	edicta gate serve -config PATH
//	edicta signer serve -config PATH
//	edicta principal <command> [flags]
//	edicta dev init --home DIR (builds with the edictadev tag only)
//
// cobra only routes. Every leaf takes its arguments unparsed, -h included, and
// parses them with the standard flag package as the separate binaries did, so
// single-dash long flags, flags after a positional argument, the usage texts
// and the exit codes stay what they were.
package edictacli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/vgonkivs/edicta/internal/principalcli"
	"github.com/vgonkivs/edicta/services/cli/clicmd"
	"github.com/vgonkivs/edicta/services/gate/gatecmd"
	"github.com/vgonkivs/edicta/services/signer/signercmd"
)

// exitUsage is the code of a command line that names no command.
const exitUsage = 4

const usageCore = "usage: edicta init [--home DIR] [--preset CELESTIA+SETTLEMENT] [--set network.key=value]... [--max-per-payment USDC] [--max-per-hour USDC]" +
	" | doctor [--config PATH] [--set key=value]... [--json]" +
	" | commit [--request FILE|-] [flags]" +
	" | agent serve [--listen ADDR] [flags]" +
	" | verify|replay|absence <commitment_hash> --gate-key HEX (--archive DIR | --archive-url URL) [--config PATH | --no-config] [flags]" +
	" | gate serve -config PATH [-print-config]" +
	" | signer serve -config PATH [-check-config]" +
	" | principal render|typed-data|signdoc|private|sign|verify|publish [flags]"

const usageDev = " | dev init --home DIR [flags]"

// NewRoot builds the command tree. The exit code of the command that ran is
// stored in code.
func NewRoot(stdin io.Reader, stdout, stderr io.Writer, code *int) *cobra.Command {
	root := &cobra.Command{
		Use:   "edicta",
		Short: "Edicta: verifiable decisions for autonomous agents",
		Long: "Edicta commits an agent's decision before the action, authorizes exactly\n" +
			"the committed action bytes and lets anyone verify the decision later.",
		Args: cobra.ArbitraryArgs,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)

	root.AddCommand(
		leaf("init", "Create the Edicta home: keys, mandate and edicta.toml", code, func(a []string) int {
			return clicmd.Init(a, stdout)
		}),
		leaf("doctor", "Check the configuration and every endpoint it names", code, func(a []string) int {
			return clicmd.Doctor(a, stdout)
		}),
		leaf("commit", "Publish and commit one decision and print the gate's Authorization", code, func(a []string) int {
			return clicmd.Commit(a, stdin, stdout)
		}),
		leaf("agent", "agent serve: the local commit service for agents", code, func(a []string) int {
			return clicmd.Agent(a, stdout)
		}),
	)
	for _, name := range []string{"verify", "replay", "absence"} {
		root.AddCommand(leaf(name, verifyShort[name], code, func(a []string) int {
			return clicmd.Verify(append([]string{name}, a...), stdout)
		}))
	}
	root.AddCommand(
		group("gate", "The gate daemon", stdout, code,
			leaf("serve", "Run the gate and the optional Recorder", code, func(a []string) int {
				return gatecmd.Main(append([]string{argv0() + " gate serve"}, a...), stdout, stderr)
			})),
		group("signer", "The executor that holds the payer key", stdout, code,
			leaf("serve", "Run the signer", code, func(a []string) int {
				return signercmd.Main(append([]string{argv0() + " signer serve"}, a...), stdout, stderr)
			})),
		leaf("principal", "The principal's mandate tool: render, sign, verify, publish", code, func(a []string) int {
			return principalcli.Main(append([]string{argv0() + " principal"}, a...), stdout, stderr)
		}),
	)
	usage := usageCore
	if addDev(root, stdout, stderr, code) {
		usage += usageDev
	}

	root.RunE = func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Fprintln(stdout, usage)
		} else {
			fmt.Fprintf(stdout, "edicta: unknown subcommand %q\n%s\n", args[0], usage)
		}
		*code = exitUsage
		return nil
	}
	return root
}

var verifyShort = map[string]string{
	"verify":  "Verify an archived decision",
	"replay":  "Verify an archived decision as of its reference time",
	"absence": "Prove a fast-mode anchor absent and archive the proofs",
}

// Execute runs the command line args (without the program name) and returns
// the exit code.
func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code := 0
	root := NewRoot(stdin, stdout, stderr, &code)
	if args == nil {
		// cobra reads os.Args for a nil slice.
		args = []string{}
	}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return exitUsage
	}
	return code
}

// leaf is a command whose body parses its own arguments.
func leaf(use, short string, code *int, body func([]string) int) *cobra.Command {
	return &cobra.Command{
		Use:                   use,
		Short:                 short,
		DisableFlagParsing:    true,
		DisableFlagsInUseLine: true,
		Args:                  cobra.ArbitraryArgs,
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(_ *cobra.Command, args []string) error {
			*code = body(args)
			return nil
		},
	}
}

// group is a command that only holds subcommands. Run alone or with an
// unknown subcommand it prints its help and fails as a usage error.
func group(use, short string, stdout io.Writer, code *int, subs ...*cobra.Command) *cobra.Command {
	g := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				fmt.Fprintf(stdout, "edicta %s: unknown subcommand %q\n", c.Name(), args[0])
			}
			*code = exitUsage
			return c.Help()
		},
	}
	g.AddCommand(subs...)
	return g
}

// argv0 is the program name as invoked, which the standard flag package put
// in the usage header of the gate and signer daemons.
func argv0() string {
	if len(os.Args) > 0 {
		return os.Args[0]
	}
	return "edicta"
}
