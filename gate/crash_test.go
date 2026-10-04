package gate_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
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

func registries() map[string]func(t *testing.T) registry.Registry {
	return map[string]func(t *testing.T) registry.Registry{
		"memreg": func(t *testing.T) registry.Registry { return gatefix.MemReg(t, gatefix.Epoch) },
		"boltreg": func(t *testing.T) registry.Registry {
			r, err := boltreg.Open(filepath.Join(t.TempDir(), "nonces.db"), gatefix.Epoch)
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Close() })
			return r
		},
	}
}

// exitingRegistry kills the process around the durable mark.
type exitingRegistry struct {
	registry.Registry
	before, after bool
}

func (r *exitingRegistry) Claim() (func(), error) {
	return r.Registry.(registry.Claimer).Claim()
}

func (r *exitingRegistry) Consume(ctx context.Context, e registry.Entry, tol uint64) error {
	if r.before {
		os.Exit(crashExit)
	}
	err := r.Registry.Consume(ctx, e, tol)
	if r.after && err == nil {
		os.Exit(crashExit)
	}
	return err
}

// TestCrashChild runs only inside the re-executed test binary. It authorizes
// one commitment on a bbolt file and kills the process at the chosen point.
func TestCrashChild(t *testing.T) {
	path := os.Getenv(crashDBEnv)
	if path == "" {
		t.Skip("helper for TestCrashReexec")
	}
	reg, err := boltreg.Open(path, gatefix.Epoch)
	require.NoError(t, err)
	at := os.Getenv(crashAtEnv)
	require.Contains(t, []string{"before-mark", "after-mark"}, at, "no crash point")
	wrapped := &exitingRegistry{Registry: reg, before: at == "before-mark", after: at == "after-mark"}
	e, _, b, _ := happy(t, gatefix.WithRegistry(wrapped))
	_, _ = e.Authorize(b)
	require.FailNow(t, "process survived the crash point")
}

// TestCrashReexec kills a real process before and after the nonce mark is
// durable, then reopens the file.
func TestCrashReexec(t *testing.T) {
	run := func(t *testing.T, at string) string {
		path := filepath.Join(t.TempDir(), "nonces.db")
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
		cmd.Env = append(os.Environ(), crashDBEnv+"="+path, crashAtEnv+"="+at)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		require.ErrorAs(t, err, &ee, "child did not crash as planned")
		require.Equalf(t, crashExit, ee.ExitCode(), "child did not crash as planned: %s", out)
		return path
	}
	reopen := func(t *testing.T, path string) (*gatefix.Env, *commitment.Commitment, []byte, commitment.Hash) {
		reg, err := boltreg.Open(path, gatefix.Epoch+5000)
		require.NoError(t, err)
		t.Cleanup(func() { _ = reg.Close() })
		m, err := reg.Meta(context.Background())
		require.NoError(t, err)
		require.Equal(t, gatefix.Epoch, m.Epoch, "a reopen must not rewrite the epoch")
		return happy(t, gatefix.WithRegistry(reg))
	}

	t.Run("before the mark: nothing burned, the retry succeeds", func(t *testing.T) {
		path := run(t, "before-mark")
		e, c, b, h := reopen(t, path)
		_, err := e.Entry(c)
		require.ErrorIs(t, err, registry.ErrNotFound)
		res, err := e.Authorize(b)
		require.NoError(t, err)
		gatefix.CheckAuthorization(t, res.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)
	})

	t.Run("after the mark: the retry gets the stored Authorization", func(t *testing.T) {
		path := run(t, "after-mark")
		e, c, b, h := reopen(t, path)
		ent, err := e.Entry(c)
		require.NoError(t, err)
		require.NotEmpty(t, ent.Authorization)
		gatefix.CheckAuthorization(t, ent.Authorization, gatefix.Action(t), c, h, commitment.PathDA, 0, gatefix.Now)

		res, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, ent.Authorization, res.Authorization)

		other := gatefix.Action(t)
		other[0] ^= 1
		res, err = e.AuthorizeWith(b, other)
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		require.Nil(t, res.Authorization)
	})
}

// A mark that fails leaves nothing: the Authorization stays in gate memory.
func TestNoAuthorizationBeforeTheMarkIsDurable(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			spy := &spyRegistry{Registry: open(t)}
			e, c, b, _ := happy(t, gatefix.WithRegistry(spy))
			failing := &failingConsume{spyRegistry: spy}
			e.Deps.Registry = failing
			require.NoError(t, e.Restart())
			failing.fail = true
			res, err := e.Authorize(b)
			require.ErrorIs(t, err, gate.ErrRegistryUnavailable)
			require.Nil(t, res.Authorization)
			_, gerr := e.Entry(c)
			require.ErrorIs(t, gerr, registry.ErrNotFound)

			failing.fail = false
			res, err = e.Authorize(b)
			require.NoError(t, err)
			require.NotEmpty(t, res.Authorization)
		})
	}
}

type failingConsume struct {
	*spyRegistry
	fail bool
}

func (f *failingConsume) Consume(ctx context.Context, e registry.Entry, tol uint64) error {
	if f.fail {
		return os.ErrClosed
	}
	return f.spyRegistry.Consume(ctx, e, tol)
}

// Closing and reopening a durable registry keeps the Authorization.
func TestBoltRetryAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	reg, err := boltreg.Open(path, gatefix.Epoch)
	require.NoError(t, err)
	e, _, b, _ := happy(t, gatefix.WithRegistry(reg))
	first, err := e.Authorize(b)
	require.NoError(t, err)
	require.NoError(t, e.Gate.Close())
	require.NoError(t, reg.Close())

	reg2, err := boltreg.Open(path, gatefix.Epoch+1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg2.Close() })
	e2, _, _, _ := happy(t, gatefix.WithRegistry(reg2))
	res, err := e2.Authorize(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.Equal(t, first.Authorization, res.Authorization)
}
