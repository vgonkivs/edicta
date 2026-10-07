package edictad_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
)

func parseFibre(t *testing.T, e *env, extra ...[2]string) (edictad.Config, error) {
	t.Helper()
	return edictad.ParseConfig([]byte(e.tomlOf(fibreEdits(extra...)...)))
}

func TestDAConstantsAndMapping(t *testing.T) {
	assert.Equal(t, "celestia_blob", edictad.DAConfigBlob)
	assert.Equal(t, "fibre", edictad.DAConfigFibre)
	e := newEnv(t)
	assert.Equal(t, commitment.DACelestiaBlob, e.cfg().DA())
	c, err := parseFibre(t, e)
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, c.DA())
}

func TestBlobAliasIsRefusedWithAHint(t *testing.T) {
	e := newEnv(t)
	_, err := edictad.ParseConfig([]byte(e.tomlOf(rep(`da = "celestia_blob"`, `da = "blob"`))))
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "celestia_blob", "the refusal names the replacement")
}

func TestArchiveSectionIsRequired(t *testing.T) {
	e := newEnv(t)
	_, err := edictad.ParseConfig([]byte(e.tomlOf(rep(`dir = "`+e.path("archive")+`"`, `dir = ""`))))
	require.ErrorIs(t, err, edictad.ErrConfig)

	// A missing section is a missing dir, not a default location.
	_, err = edictad.ParseConfig([]byte(e.tomlOf(rep("[archive]\n", "[archive_off]\n"))))
	require.ErrorIs(t, err, edictad.ErrConfig)
}

func TestWithDefaults(t *testing.T) {
	e := newEnv(t)
	t.Run("fibre fills its keys and the archive keys", func(t *testing.T) {
		c, err := edictad.ParseConfig([]byte(e.tomlOf(fibreEdits()...)))
		require.NoError(t, err)
		// Explicit values from fibreEdits stay.
		assert.EqualValues(t, 1048576, c.Fibre.MaxDataBytes)
		assert.EqualValues(t, 1048576, c.Fibre.MaxReadBytes)
		assert.EqualValues(t, 60, c.Fibre.LookupTimeoutS)
		assert.EqualValues(t, 30, c.Fibre.SampleEveryS)
		assert.EqualValues(t, 600, c.Fibre.CanaryEveryS)
		assert.Zero(t, c.Fibre.AnchorCacheBytes, "no cross-request cache by default")
		assert.Zero(t, c.Fibre.AssumedLagBlocks)
		assert.False(t, c.Fibre.BridgeFallback, "the fallback is off by default")
		assert.EqualValues(t, 10, c.Archive.WriteTimeoutS)
		assert.EqualValues(t, 600, c.Archive.SweepIntervalS)
	})
	t.Run("fibre defaults for an absent fibre table", func(t *testing.T) {
		c, err := edictad.ParseConfig([]byte(e.tomlOf(fibreEdits()[:3]...)))
		require.NoError(t, err)
		assert.EqualValues(t, 16<<20, c.Fibre.MaxDataBytes)
		assert.EqualValues(t, 16<<20, c.Fibre.MaxReadBytes)
	})
	t.Run("blob leaves the fibre table alone", func(t *testing.T) {
		c := e.cfg()
		assert.Equal(t, edictad.FibreConfig{}, c.Fibre)
		assert.EqualValues(t, 10, c.Archive.WriteTimeoutS)
	})
	t.Run("idempotent", func(t *testing.T) {
		for _, c := range []edictad.Config{e.cfg(), mustFibre(t, e)} {
			once := c.WithDefaults()
			assert.Equal(t, once, once.WithDefaults())
			assert.Equal(t, c, once, "ParseConfig already applied the defaults")
		}
	})
	t.Run("ValidateBasic never applies defaults", func(t *testing.T) {
		c := mustFibre(t, e)
		c.Fibre.MaxReadBytes = 0
		require.ErrorIs(t, c.ValidateBasic(), edictad.ErrConfig)
		require.NoError(t, c.WithDefaults().ValidateBasic())

		b := e.cfg()
		b.Archive.WriteTimeoutS = 0
		require.ErrorIs(t, b.ValidateBasic(), edictad.ErrConfig)
		require.NoError(t, b.WithDefaults().ValidateBasic())
	})
}

func mustFibre(t *testing.T, e *env, extra ...[2]string) edictad.Config {
	t.Helper()
	c, err := parseFibre(t, e, extra...)
	require.NoError(t, err)
	return c
}

func TestValidateBasicRefusals(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("a", 21)
	cases := []struct {
		name  string
		fibre bool
		edit  [][2]string
	}{
		// A half-switched config never starts.
		{"blob with a fibre key", false, [][2]string{rep("[archive]\n", "[fibre]\nmax_data_bytes = 1024\n\n[archive]\n")}},
		{"blob with bridge_fallback", false, [][2]string{rep("[archive]\n", "[fibre]\nbridge_fallback = true\n\n[archive]\n")}},
		{"blob with fibre_chain_ids", false, [][2]string{rep(`da = "celestia_blob"`, "da = \"celestia_blob\"\nfibre_chain_ids = [\"mocha-5\"]")}},
		{"blob with recorder.own_node", false, [][2]string{rep("[recorder.quota]", "own_node = true\n\n[recorder.quota]")}},
		{"blob with recorder.escrow_margin_utia", false, [][2]string{rep("[recorder.quota]", "escrow_margin_utia = 5\n\n[recorder.quota]")}},
		{"blob with recorder.submit_timeout_s", false, [][2]string{rep("[recorder.quota]", "submit_timeout_s = 5\n\n[recorder.quota]")}},
		{"blob with recorder.upload_drain_s", false, [][2]string{rep("[recorder.quota]", "upload_drain_s = 5\n\n[recorder.quota]")}},
		{"blob with recorder.close_timeout_s", false, [][2]string{rep("[recorder.quota]", "close_timeout_s = 5\n\n[recorder.quota]")}},

		{"archive dir empty", false, [][2]string{rep(`dir = "`+e.path("archive")+`"`, `dir = ""`)}},
		{"archive write timeout above 60", false, [][2]string{rep("write_timeout_s = 10", "write_timeout_s = 61")}},
		{"archive sweep interval below 60", false, [][2]string{rep("sweep_interval_s = 600", "sweep_interval_s = 59")}},
		{"archive sweep interval above a day", false, [][2]string{rep("sweep_interval_s = 600", "sweep_interval_s = 86401")}},

		{"fibre with min_app_version", true, [][2]string{rep(`fibre_chain_ids = ["mocha-5"]`, "fibre_chain_ids = [\"mocha-5\"]\nmin_app_version = 3")}},
		{"fibre with max_app_version", true, [][2]string{rep(`fibre_chain_ids = ["mocha-5"]`, "fibre_chain_ids = [\"mocha-5\"]\nmax_app_version = 10")}},
		{"fibre empty chain id", true, [][2]string{rep(`fibre_chain_ids = ["mocha-5"]`, `fibre_chain_ids = [""]`)}},
		{"fibre no chain ids entry list", true, [][2]string{rep(`fibre_chain_ids = ["mocha-5"]`, `fibre_chain_ids = ["mocha-5", "mocha-5"]`)}},
		{"fibre chain id above 20 bytes", true, [][2]string{rep(`fibre_chain_ids = ["mocha-5"]`, `fibre_chain_ids = ["`+long+`"]`)}},
		{"fibre max_data_bytes above 16 MiB", true, [][2]string{rep("max_data_bytes = 1048576", "max_data_bytes = 16777217")}},
		{"fibre max_read_bytes below 64 KiB", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 65535")}},
		{"fibre max_read_bytes above 1 GiB", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1073741825")}},
		{"fibre cache below read limit plus slack", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nanchor_cache_bytes = 1052671")}},
		{"fibre cache above 1 GiB", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nanchor_cache_bytes = 1073741825")}},
		{"fibre lookup timeout above 600", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nlookup_timeout_s = 601")}},
		{"fibre sample interval above 300", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nsample_every_s = 301")}},
		{"fibre canary interval below 60", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\ncanary_every_s = 59")}},
		{"fibre canary interval above 3600", true, [][2]string{rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\ncanary_every_s = 3601")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var edits [][2]string
			if tc.fibre {
				edits = fibreEdits(tc.edit...)
			} else {
				edits = tc.edit
			}
			_, err := edictad.ParseConfig([]byte(e.tomlOf(edits...)))
			require.ErrorIs(t, err, edictad.ErrConfig)
		})
	}
}

// The Recorder is wired for da = fibre; without own_node it is still refused,
// and no longer as an unsupported mode.
func TestFibreRecorderNeedsOwnNode(t *testing.T) {
	e, _ := newFibreEnv(t)
	edits := fibreEdits()
	edits = append(edits[:2:2], edits[3:]...) // keep enabled = true
	_, err := edictad.ParseConfig([]byte(e.tomlOf(edits...)))
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.NotErrorIs(t, err, edictad.ErrDANotSupported)
	assert.Contains(t, err.Error(), "recorder.own_node")
}

func TestNoBridgeVersionOrCapabilityInConfig(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name string
		edit [][2]string
	}{
		{"bridge version in fibre table", fibreEdits(rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nbridge_version = \"v0.34.2-mocha\""))},
		{"bridge version in bridge table", fibreEdits(rep("[network.bridge]\n", "[network.bridge]\nversion = \"v0.34.2-mocha\"\n"))},
		{"bridge probe override", fibreEdits(rep("max_read_bytes = 1048576", "max_read_bytes = 1048576\nbridge_compatible = true"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := edictad.ParseConfig([]byte(e.tomlOf(tc.edit...)))
			require.ErrorIs(t, err, edictad.ErrConfig)
		})
	}
}

func TestFibreDerivedValues(t *testing.T) {
	e := newEnv(t)
	c := mustFibre(t, e, rep("max_read_bytes = 1048576", "max_read_bytes = 2097152\nanchor_cache_bytes = 4194304\nlookup_timeout_s = 7"))

	t.Run("bridge limit is the gate read limit", func(t *testing.T) {
		assert.EqualValues(t, 2097152, c.FibreBridgeLimits().NamespaceDataBytes)
		assert.Equal(t, node.BridgeLimits{NamespaceDataBytes: c.Fibre.MaxReadBytes}, c.FibreBridgeLimits())
	})
	t.Run("anchor options", func(t *testing.T) {
		o := c.FibreAnchorOptions()
		assert.EqualValues(t, 2097152, o.MaxReadBytes)
		assert.EqualValues(t, 4194304, o.CacheBytes)
		assert.Equal(t, 7*time.Second, o.LookupTimeout)
		assert.False(t, o.SkipCertificate, "the certificate check is always on")
		require.NoError(t, o.ValidateBasic())
	})
	t.Run("expect carries the allowlist and never a version", func(t *testing.T) {
		log := slog.Default()
		x := c.FibreExpect(log)
		assert.Equal(t, []string{"mocha-5"}, x.ChainIDs)
		assert.Same(t, log, x.Log)
		assert.Nil(t, x.BridgeVersion, "a version is never read from configuration")
		assert.Empty(t, x.PinnedBridgeVersion)
	})
}
