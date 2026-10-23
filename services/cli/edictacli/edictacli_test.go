// SPDX-License-Identifier: Apache-2.0

package edictacli

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/internal/principalcli"
	"github.com/vgonkivs/edicta/plugins/celestia/celestiatest/fibrefix"
	"github.com/vgonkivs/edicta/services/cli/clicmd"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
	"github.com/vgonkivs/edicta/services/gate/gatecmd"
	"github.com/vgonkivs/edicta/services/signer/signercmd"
)

type result struct {
	code           int
	stdout, stderr string
}

func edicta(t *testing.T, args ...string) result {
	t.Helper()
	if os.Getenv(config.EnvHome) == "" {
		t.Setenv(config.EnvHome, t.TempDir())
	}
	var out, errOut bytes.Buffer
	code := Execute(args, strings.NewReader(""), &out, &errOut)
	return result{code, out.String(), errOut.String()}
}

func TestNoSubcommandIsAUsageError(t *testing.T) {
	r := edicta(t)
	assert.Equal(t, exitUsage, r.code)
	for _, sub := range []string{"init", "doctor", "commit", "agent serve", "verify|replay|absence", "--no-config", "gate serve", "signer serve", "principal"} {
		assert.Contains(t, r.stdout, sub, "the usage names the subcommand")
	}
	assert.NotContains(t, r.stdout, "demo", "the demo is an example binary, not a subcommand")
	assert.Empty(t, r.stderr)
}

func TestUnknownSubcommandIsAUsageError(t *testing.T) {
	for _, sub := range []string{"frobnicate", "VERIFY", "--verify", "-", "demo", "edictad", "serve", "completion"} {
		r := edicta(t, sub)
		assert.Equal(t, exitUsage, r.code, "%q: %+v", sub, r)
		assert.NotEmpty(t, r.stdout+r.stderr, sub)
	}
}

func TestRootHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		r := edicta(t, args...)
		assert.Equal(t, 0, r.code, "%q", args)
		for _, sub := range []string{"init", "doctor", "commit", "agent", "verify", "replay", "absence", "gate", "signer", "principal"} {
			assert.Contains(t, r.stdout, "\n  "+sub+" ", "%q lists %s", args, sub)
		}
		assert.NotContains(t, r.stdout, "completion", "the default completion command is off")
	}
}

// A group is only a path to its leaves: alone, with an unknown word or with a
// flag of its own it is a usage error.
func TestGroupWithoutLeafIsAUsageError(t *testing.T) {
	for _, args := range [][]string{{"gate"}, {"signer"}, {"gate", "bogus"}, {"signer", "-config", "x"}, {"gate", "--bogus"}} {
		r := edicta(t, args...)
		assert.Equal(t, exitUsage, r.code, "%q: %+v", args, r)
		assert.Contains(t, r.stdout+r.stderr, "serve", "%q shows the leaf", args)
	}
}

// Each leaf hands its arguments, -h and flags after positionals included, to
// its body unparsed, so routing changes neither output nor exit code.
func TestLeavesRunTheirBodyUnchanged(t *testing.T) {
	t.Setenv(config.EnvHome, t.TempDir())
	argv0 := os.Args[0]
	type body func(args []string, stdout, stderr *bytes.Buffer) int
	cases := []struct {
		route []string
		args  [][]string
		body  body
	}{
		{[]string{"gate", "serve"}, [][]string{{"-h"}, {"--help"}, {}, {"--bogus"}, {"-config"}, {"extra", "-config", "x"}, {"--config=/nonexistent", "--print-config=maybe"}},
			func(a []string, o, e *bytes.Buffer) int {
				return gatecmd.Main(append([]string{argv0 + " gate serve"}, a...), o, e)
			}},
		{[]string{"signer", "serve"}, [][]string{{"-h"}, {"-help"}, {}, {"--bogus"}, {"--config=/nonexistent", "--check-config"}},
			func(a []string, o, e *bytes.Buffer) int {
				return signercmd.Main(append([]string{argv0 + " signer serve"}, a...), o, e)
			}},
		{[]string{"principal"}, [][]string{{}, {"-h"}, {"--help"}, {"bogus"}, {"render", "-h"}, {"render"}, {"verify", "--signed", "/nonexistent"}},
			func(a []string, o, e *bytes.Buffer) int {
				return principalcli.Main(append([]string{argv0 + " principal"}, a...), o, e)
			}},
		{[]string{"init"}, [][]string{{"-h"}, {"--help"}, {"--bogus"}, {"--preset=bogus", "--home", t.TempDir()}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Init(a, o) }},
		{[]string{"doctor"}, [][]string{{"-h"}, {"--bogus"}, {"-config", "/nonexistent", "-json"}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Doctor(a, o) }},
		{[]string{"commit"}, [][]string{{"-h"}, {"--bogus"}, {}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Commit(a, strings.NewReader(""), o) }},
		{[]string{"agent"}, [][]string{{}, {"bogus"}, {"serve", "-h"}, {"serve", "--bogus"}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Agent(a, o) }},
		{[]string{"verify"}, [][]string{{}, {"-h"}, {"--help", "--json"}, {strings.Repeat("00", 32), "--bogus"}, {"--no-config", "-h"}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Verify(append([]string{"verify"}, a...), o) }},
		{[]string{"replay"}, [][]string{{"--help"}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Verify(append([]string{"replay"}, a...), o) }},
		{[]string{"absence"}, [][]string{{"--help"}, {"--no-config", "--help"}},
			func(a []string, o, _ *bytes.Buffer) int { return clicmd.Verify(append([]string{"absence"}, a...), o) }},
	}
	for _, c := range cases {
		for _, a := range c.args {
			var o, e bytes.Buffer
			wantCode := c.body(a, &o, &e)
			got := edicta(t, append(append([]string{}, c.route...), a...)...)
			assert.Equal(t, result{wantCode, o.String(), e.String()}, got, "%q %q", c.route, a)
		}
	}
}

// The usage header of the daemons names the command path after the program,
// where the standalone binaries printed the program alone.
func TestDaemonUsageNamesTheCommandPath(t *testing.T) {
	r := edicta(t, "gate", "serve", "-h")
	assert.Equal(t, 0, r.code)
	assert.True(t, strings.HasPrefix(r.stderr, "Usage of "+os.Args[0]+" gate serve:\n"), r.stderr)
	assert.Contains(t, r.stderr, "-print-config")

	r = edicta(t, "signer", "serve", "--bogus")
	assert.Equal(t, 2, r.code)
	assert.True(t, strings.HasPrefix(r.stderr, "flag provided but not defined: -bogus\nUsage of "+os.Args[0]+" signer serve:\n"), r.stderr)
}

func TestTopLevelRoutesCommitAndAgent(t *testing.T) {
	r := edicta(t, "agent")
	assert.Equal(t, commitcmd.ExitUsage, r.code)
	assert.Contains(t, r.stdout, "serve")
	r = edicta(t, "commit", "--nope")
	assert.Equal(t, commitcmd.ExitUsage, r.code)
	assert.Contains(t, r.stdout, "commit")
}

// edicta verify --no-config keeps the interface and the exit codes of the
// former standalone verifier.
func TestNoConfigVerifiesAndKeepsItsExitCodes(t *testing.T) {
	l := fibrefix.LoadLive(t)
	d := l.WriteDecision(t, l.Evidence(t))
	trusted := l.TrustedFile(t, nil)
	h := hex.EncodeToString(d.Hash[:])

	r := edicta(t, "verify", "--no-config", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, h)
	require.Equal(t, 0, r.code, r.stdout)
	assert.Contains(t, r.stdout, "verdict: valid")

	r = edicta(t, "verify", "--archive", d.Dir, "--gate-key", d.GateKeyHex, h, "--no-config")
	assert.Equal(t, 2, r.code, r.stdout)

	r = edicta(t, "replay", "--no-config", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, h)
	assert.Equal(t, 0, r.code, r.stdout)

	other := bytes.Clone(d.Hash[:])
	other[0] ^= 1
	r = edicta(t, "verify", "--no-config", "--archive", d.Dir, "--gate-key", d.GateKeyHex, "--trusted", trusted, hex.EncodeToString(other))
	assert.Equal(t, 2, r.code, "no record is no verdict: %s", r.stdout)

	r = edicta(t, "verify", "--no-config")
	assert.Equal(t, 4, r.code, r.stdout)
	r = edicta(t, "verify", "--no-config", "--archive", "/nonexistent", "--gate-key", d.GateKeyHex, h)
	assert.Equal(t, 4, r.code, r.stdout)
}
