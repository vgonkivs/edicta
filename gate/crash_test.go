package gate_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

const (
	crashDBEnv = "EDICTA_CRASH_DB"
	crashAtEnv = "EDICTA_CRASH_AT"
	crashExit  = 3
)

// TestCrashChild runs only inside the re-executed test binary. It admits one
// commitment on a bbolt file and kills the process at the chosen point.
func TestCrashChild(t *testing.T) {
	path := os.Getenv(crashDBEnv)
	if path == "" {
		t.Skip("helper for TestCrashReexec")
	}
	reg, err := boltreg.Open(path, gatefix.Epoch)
	require.NoError(t, err)
	e, _, b, _ := happy(t, gatefix.WithRegistry(reg))
	die := func() error { os.Exit(crashExit); return nil }
	switch os.Getenv(crashAtEnv) {
	case "reserve":
		e.Gate.SetAfterReserve(die)
	case "execute":
		e.Gate.SetAfterExecute(die)
	case "resolve":
		e.Gate.SetBeforeResolve(die)
	default:
		require.FailNow(t, "no crash point")
	}
	_, _ = e.Admit(b)
	require.FailNow(t, "process survived the crash point")
}

// TestCrashReexec kills a real process after the nonce was reserved (and,
// in the second case, after the executor was called), then reopens the file.
func TestCrashReexec(t *testing.T) {
	for _, at := range []string{"reserve", "execute", "resolve"} {
		t.Run(at, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nonces.db")
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
			cmd.Env = append(os.Environ(), crashDBEnv+"="+path, crashAtEnv+"="+at)
			err := cmd.Run()
			var ee *exec.ExitError
			require.ErrorAs(t, err, &ee, "child did not crash as planned")
			require.Equalf(t, crashExit, ee.ExitCode(), "child did not crash as planned: %v", err)

			// The epoch argument of a reopen must not rewrite the stored epoch.
			reg, err := boltreg.Open(path, gatefix.Epoch+5000)
			require.NoError(t, err)
			t.Cleanup(func() { _ = reg.Close() })
			m, err := reg.Meta(context.Background())
			require.NoErrorf(t, err, "meta %+v", m)
			require.Equalf(t, gatefix.Epoch, m.Epoch, "meta %+v %v", m, err)
			e, c, b, _ := happy(t, gatefix.WithRegistry(reg))
			ent, err := e.Entry(c)
			require.NoErrorf(t, err, "entry after restart %+v", ent)
			require.Equalf(t, registry.StateUnknown, ent.State, "entry after restart %+v %v", ent, err)
			require.EqualValuesf(t, registry.SourceRecover, ent.History[0].Source, "entry after restart %+v %v", ent, err)
			_, err = e.Admit(b)
			require.ErrorIs(t, err, gate.ErrNonceUsed, "replay")
			e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeNotFound}, nil)
			e.Clock.Set(c.ValidUntil + e.Cfg.SettleS + 1)
			rep, err := e.Gate.Reconcile(context.Background())
			require.NoErrorf(t, err, "%+v", rep)
			require.EqualValuesf(t, 1, rep.Rejected, "%+v %v", rep, err)
			require.EqualValuesf(t, 0, e.Exec.Calls(), "the restarted gate executed %d times", e.Exec.Calls())
		})
	}
}
