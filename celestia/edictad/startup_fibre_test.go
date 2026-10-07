package edictad_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestFibreStartServesDA1Only(t *testing.T) {
	e, _ := newFibreEnv(t)
	srv := e.start(fibreEdits()...)
	require.NotEmpty(t, srv.Addr())
	assert.True(t, e.registryExists())

	h, err := e.client("").Health(bg)
	require.NoError(t, err)
	assert.Equal(t, []uint64{1}, h.AllowedDA, "da = fibre allows da 1 only")
	assert.Equal(t, fibreChainID, h.ChainID)
}

func TestFibreInstanceRefusesADA2Commitment(t *testing.T) {
	e, _ := newFibreEnv(t)
	e.start(fibreEdits()...)
	d := e.decision(gatefix.Template(t), 1)
	require.EqualValues(t, 2, d.c.PayloadRef.DA)
	st, _, body := e.authorizeRaw(d)
	assert.Equal(t, 403, st)
	assert.True(t, hasCode(body, "ErrDANotAllowed"))
}

func TestFibreStartRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *env, ff *fibreFakes)
		edits [][2]string
	}{
		{"chain outside the allowlist", nil, fibreEdits(rep(`fibre_chain_ids = ["mocha-5"]`, `fibre_chain_ids = ["other-1"]`))},
		{"build pin", func(_ *env, ff *fibreFakes) { ff.deps.CheckBuild = func() error { return errSeam } }, nil},
		{"nmt pin", func(_ *env, ff *fibreFakes) { ff.deps.CheckNMT = func() error { return errSeam } }, nil},
		{"known answers", func(_ *env, ff *fibreFakes) { ff.deps.SelfTest = func() error { return errSeam } }, nil},
		{"app version 9", func(e *env, _ *fibreFakes) {
			hd := fibreHeader(101, t0)
			hd.AppVersion = 9
			e.chain.AddHeader(hd)
		}, nil},
		{"app version 11", func(e *env, _ *fibreFakes) {
			hd := fibreHeader(101, t0)
			hd.AppVersion = 11
			e.chain.AddHeader(hd)
		}, nil},
		{"x/fibre absent", func(e *env, _ *fibreFakes) { e.cons.Fibre = nil }, nil},
		{"retention below 10 minutes", func(e *env, _ *fibreFakes) { e.cons.Fibre = &node.FibreParams{RetentionS: 599} }, nil},
		{"retention above 168 hours", func(e *env, _ *fibreFakes) { e.cons.Fibre = &node.FibreParams{RetentionS: 168*3600 + 1} }, nil},
		{"consensus on another network", func(e *env, _ *fibreFakes) { e.cons.ChainID = "else-1" }, nil},
		{"consensus down", func(e *env, _ *fibreFakes) { e.cons.Fail = node.ErrUnavailable }, nil},
		{"bridge node down", func(e *env, _ *fibreFakes) { e.chain.Fail = node.ErrUnavailable }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ff := newFibreEnv(t)
			if tc.setup != nil {
				tc.setup(e, ff)
			}
			edits := tc.edits
			if edits == nil {
				edits = fibreEdits()
			}
			srv, err := edictad.Start(bg, e.cfg(edits...), e.deps)
			require.ErrorIs(t, err, node.ErrUnsupported)
			require.Nil(t, srv)
			assert.Zero(t, e.listens, "no listener after a refused check")
			assert.False(t, e.registryExists(), "the registry is not created before the check passes")
			assert.NoDirExists(t, e.path("archive"), "nor the archive")
		})
	}
}

func TestFibreStartRefusesMissingDependencies(t *testing.T) {
	cases := map[string]func(e *env, ff *fibreFakes){
		"no fibre deps":   func(e *env, _ *fibreFakes) { e.deps.Fibre = nil },
		"no chain reader": func(_ *env, ff *fibreFakes) { ff.deps.Chain = nil },
		"no bridge":       func(_ *env, ff *fibreFakes) { ff.deps.Bridge = nil },
		"no direct":       func(_ *env, ff *fibreFakes) { ff.deps.Direct = nil },
		"no node reader":  func(e *env, _ *fibreFakes) { e.deps.Reader = nil },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e, ff := newFibreEnv(t)
			setup(e, ff)
			srv, err := edictad.Start(bg, e.cfg(fibreEdits()...), e.deps)
			require.Error(t, err)
			require.Nil(t, srv)
			assert.Zero(t, e.listens)
			assert.False(t, e.registryExists())
		})
	}
}

func TestFibreStartCrossChecksTheBridgeLimit(t *testing.T) {
	t.Run("a bridge with other limits is refused", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		ff.deps.Bridge = bridgeWithLimits{FibreChain: ff.chain, lim: node.BridgeLimits{NamespaceDataBytes: 12345}}
		srv, err := edictad.Start(bg, e.cfg(fibreEdits()...), e.deps)
		require.Error(t, err)
		require.Nil(t, srv)
		assert.Zero(t, e.listens)
		assert.False(t, e.registryExists())
	})
	t.Run("a bridge limited as the config says is accepted", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		cfg := e.cfg(fibreEdits()...)
		ff.deps.Bridge = bridgeWithLimits{FibreChain: ff.chain, lim: cfg.FibreBridgeLimits()}
		srv, err := edictad.Start(bg, cfg, e.deps)
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Shutdown(bg) })
	})
}

func TestFibreStartRefusesAnUnusableCommitter(t *testing.T) {
	e, ff := newFibreEnv(t)
	small, err := fibrecommit.New(1024)
	require.NoError(t, err)
	ff.deps.Committer = small // cap below fibre.max_data_bytes
	srv, err := edictad.Start(bg, e.cfg(fibreEdits()...), e.deps)
	require.Error(t, err)
	require.Nil(t, srv)
	assert.Zero(t, e.listens)
	assertRegistryReleased(t, e)
}

func assertRegistryReleased(t *testing.T, e *env) {
	t.Helper()
	if !e.registryExists() {
		return
	}
	reg, err := boltreg.Open(e.path("registry.db"), 1)
	require.NoError(t, err, "a refused start closes the registry")
	require.NoError(t, reg.Close())
}

func TestFibreStartRefusesWithoutAnObserver(t *testing.T) {
	t.Run("the first sample fails", func(t *testing.T) {
		e, _ := newFibreEnv(t)
		e.cons.SetHeight(0) // no latest height: the retention observer cannot sample
		srv, err := edictad.Start(bg, e.cfg(fibreEdits()...), e.deps)
		require.Error(t, err)
		require.Nil(t, srv)
		assert.Zero(t, e.listens)
		assertRegistryReleased(t, e)
	})
	t.Run("the retention store is bound to another chain", func(t *testing.T) {
		e, _ := newFibreEnv(t)
		both := rep(`fibre_chain_ids = ["mocha-5"]`, `fibre_chain_ids = ["mocha-5", "mocha-4"]`)
		srv := e.start(fibreEdits(both)...)
		require.NoError(t, srv.Shutdown(bg))

		retarget(e, "mocha-4")
		srv2, err := edictad.Start(bg, e.cfg(fibreEdits(both)...), e.deps)
		require.Error(t, err, "the registry's retention samples belong to mocha-5")
		require.Nil(t, srv2)
		assertRegistryReleased(t, e)
	})
}

func TestFibreStartLogsTheHeightCheckSummaryOnce(t *testing.T) {
	cases := []struct {
		name      string
		status    heightcheck.Status
		retention string
		level     string
		perLine   []string
	}{
		{"honoured", heightcheck.Honoured, "retention=direct", "level=INFO", []string{"consensus: height honoured"}},
		{"ignoring", heightcheck.Ignoring, "retention=observations-only", "level=WARN", []string{"consensus: height-ignoring, observations-only mode"}},
		{"inconclusive", heightcheck.Inconclusive, "retention=observations-only", "level=WARN", []string{"consensus: height check inconclusive, observations-only mode"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newFibreEnv(t)
			e.cons.CanaryStatus = tc.status
			e.start(fibreEdits()...)
			for _, l := range tc.perLine {
				assert.NotEmpty(t, e.logLines(l), l)
			}
			lines := e.logLines("at-height reads")
			require.Len(t, lines, 1, "exactly one summary line per start")
			assert.Contains(t, lines[0], "da=fibre")
			assert.Contains(t, lines[0], tc.retention)
			assert.Contains(t, lines[0], tc.level)
			if tc.status != heightcheck.Honoured {
				assert.Contains(t, lines[0], "reason=")
			}
		})
	}
}

func TestBlobStartLogsTheHeightCheckSummaryOnce(t *testing.T) {
	t.Run("bridge honoured", func(t *testing.T) {
		e := newEnv(t)
		e.chain.AddHeader(blockAt(90, 8))
		e.chain.AddHeader(blockAt(100, 8))
		e.start()
		lines := e.logLines("at-height reads")
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], "da=celestia_blob")
		assert.Contains(t, lines[0], "retention=unused")
		assert.Contains(t, lines[0], "bridge=honoured")
		assert.NotEmpty(t, e.logLines("bridge: height honoured"))
	})
	t.Run("bridge inconclusive", func(t *testing.T) {
		e := newEnv(t) // no header at head - 10
		e.start()
		lines := e.logLines("at-height reads")
		require.Len(t, lines, 1)
		assert.Contains(t, lines[0], "bridge=inconclusive")
		assert.NotEmpty(t, e.logLines("bridge: height check inconclusive"))
	})
}

func TestBridgeFallbackIsEnabledOnlyByAPassingCapabilityProbe(t *testing.T) {
	on := rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nbridge_fallback = true")
	fallbackLines := func(e *env) []string { return e.logLines("bridge download fallback") }

	t.Run("off by default, the probe is never run", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		var calls atomic.Int32
		ff.deps.BridgeCompat = func(context.Context) error { calls.Add(1); return nil }
		e.start(fibreEdits()...)
		assert.Zero(t, calls.Load())
		assert.NotEmpty(t, fallbackLines(e), "one line says the fallback is off")
		assert.Empty(t, e.logLines("level=WARN", "bridge download fallback"))
	})
	t.Run("a passing probe enables it", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		var calls atomic.Int32
		ff.deps.BridgeCompat = func(context.Context) error { calls.Add(1); return nil }
		e.start(fibreEdits(on)...)
		// The probe runs in the background after the listener is up.
		require.Eventually(t, func() bool { return len(e.logLines("bridge download fallback")) >= 2 }, 5*time.Second, 5*time.Millisecond)
		assert.EqualValues(t, 1, calls.Load())
		assert.Empty(t, e.logLines("level=WARN", "bridge download fallback"))
	})
	t.Run("a failing probe leaves it off with a warning and the start continues", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		var calls atomic.Int32
		ff.deps.BridgeCompat = func(context.Context) error { calls.Add(1); return errSeam }
		srv := e.start(fibreEdits(on)...)
		require.NotEmpty(t, srv.Addr())
		require.Eventually(t, func() bool { return len(e.logLines("level=WARN", "bridge download fallback")) > 0 }, 5*time.Second, 5*time.Millisecond)
		assert.EqualValues(t, 1, calls.Load())
		warn := e.logLines("level=WARN", "bridge download fallback")
		assert.Contains(t, warn[0], "seam failure", "the reason is logged")
	})
	t.Run("no probe means no fallback, never a silent skip", func(t *testing.T) {
		e, ff := newFibreEnv(t)
		ff.deps.BridgeCompat = nil
		srv := e.start(fibreEdits(on)...)
		require.NotEmpty(t, srv.Addr())
		assert.NotEmpty(t, e.logLines("level=WARN", "bridge download fallback"))
	})
	for name, probeErr := range map[string]error{
		"inconclusive": fmt.Errorf("%w: no anchored blob", gatechain.ErrProbeInconclusive),
		"incompatible": fmt.Errorf("%w: method not found", node.ErrBridgeIncompatible),
	} {
		t.Run("a "+name+" probe is a warning, never a refusal", func(t *testing.T) {
			e, ff := newFibreEnv(t)
			ff.deps.BridgeCompat = func(context.Context) error { return probeErr }
			srv := e.start(fibreEdits(on)...)
			require.NotEmpty(t, srv.Addr())
			require.Eventually(t, func() bool { return len(e.logLines("level=WARN", "bridge download fallback")) > 0 }, 5*time.Second, 5*time.Millisecond)
			assert.Contains(t, e.logLines("level=WARN", "bridge download fallback")[0], probeErr.Error())
		})
	}
}

func TestListenerBindsBeforeTheBridgeProbeFinishes(t *testing.T) {
	on := rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nbridge_fallback = true")
	e, ff := newFibreEnv(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ff.deps.BridgeCompat = func(context.Context) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	ff.deps.Fallback = nodefake.NewDownloader()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	srv := e.start(fibreEdits(on)...)
	require.NotEmpty(t, srv.Addr())
	require.Equal(t, 1, e.listens, "the listener is bound while the probe is still running")
	<-entered
	resp, err := http.Get("http://" + srv.Addr() + "/v0/health")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	assert.Empty(t, e.logLines("bridge download fallback on"), "the fallback is off until the probe passes")

	released = true
	close(release)
	require.Eventually(t, func() bool { return len(e.logLines("bridge download fallback on")) == 1 }, 5*time.Second, 5*time.Millisecond)
}
