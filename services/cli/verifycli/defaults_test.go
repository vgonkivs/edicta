package verifycli

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	dKey  = hex.EncodeToString(bytes32(1))
	dKey2 = hex.EncodeToString(bytes32(2))
	dHash = hex.EncodeToString(bytes32(9))
)

func bytes32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func loader(d Defaults, got *string) DefaultsLoader {
	return func(path string) (Defaults, error) {
		if got != nil {
			*got = path
		}
		return d, nil
	}
}

func TestDefaultsFillFlagsTheUserDidNotPass(t *testing.T) {
	var path string
	d := Defaults{GateKeys: dKey, ArchiveDir: "/cfg/archive", ExcludeHosts: []string{"gate.example.org"}}
	f, err := parseFlagsWith([]string{"verify", dHash, "--config", "/x/edicta.toml"}, &bytes.Buffer{}, loader(d, &path))
	require.NoError(t, err)
	assert.Equal(t, "/x/edicta.toml", path)
	assert.Len(t, f.gateKeys, 1)
	assert.Equal(t, "/cfg/archive", f.archiveDir)
	assert.Equal(t, []string{"gate.example.org"}, f.excludeHosts)
}

func TestExplicitFlagsBeatTheConfig(t *testing.T) {
	d := Defaults{GateKeys: dKey, ArchiveDir: "/cfg/archive", ExcludeHosts: []string{"cfg.example.org"}}
	dir := t.TempDir()
	f, err := parseFlagsWith([]string{"verify", dHash, "--gate-key", dKey2, "--archive-url", "https://a.example.org", "--exclude-host", "cli.example.org"},
		&bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(f.gateKeys[0]), dKey2)
	assert.Empty(t, f.archiveDir, "an explicit archive source turns the configured directory off")
	assert.Equal(t, "https://a.example.org", f.archiveURL)
	assert.Equal(t, []string{"cli.example.org"}, f.excludeHosts)

	f, err = parseFlagsWith([]string{"verify", dHash, "--archive", dir}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Equal(t, dir, f.archiveDir)
}

func TestConfiguredCheckpointSourcesNeedAHeadersSource(t *testing.T) {
	d := Defaults{
		GateKeys: dKey, ArchiveDir: "/a", CheckpointRPC: []string{"https://c1.example.org", "https://c2.example.org"},
		HeadersRPC: "https://h.example.org", Quorum: 2, CrossCheckRPC: []string{"https://x.example.org"},
	}
	f, err := parseFlagsWith([]string{"verify", dHash}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Equal(t, d.CheckpointRPC, f.checkpointRPC)
	assert.Equal(t, "https://h.example.org", f.headersRPC)
	assert.Equal(t, 2, f.quorum)
	assert.Equal(t, d.CrossCheckRPC, f.crossRPC)

	// The user's own trust anchor is not mixed with configured sources.
	f, err = parseFlagsWith([]string{"verify", dHash, "--trusted", "/t.json"}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Empty(t, f.checkpointRPC)
	assert.Empty(t, f.headersRPC)
	assert.Equal(t, "/t.json", f.trustedPath)

	// Without a headers source the checkpoint sources would be unusable.
	d.HeadersRPC = ""
	f, err = parseFlagsWith([]string{"verify", dHash, "--trusted", "/t.json"}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	f, err = parseFlagsWith([]string{"verify", dHash}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Empty(t, f.checkpointRPC)
}

func TestExecutionSourcesComeFromTheConfigOnlyWhenChecked(t *testing.T) {
	d := Defaults{GateKeys: dKey, ArchiveDir: "/a", TxRPC: []string{"https://tx.example.org"}, HeadersRPC: "https://h.example.org"}
	f, err := parseFlagsWith([]string{"verify", dHash}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Empty(t, f.txRPC)
	f, err = parseFlagsWith([]string{"verify", dHash, "--check-execution", "--receipt", "/r"}, &bytes.Buffer{}, loader(d, nil))
	require.NoError(t, err)
	assert.Equal(t, d.TxRPC, f.txRPC)
	assert.Equal(t, d.HeadersRPC, f.headersRPC)
}

func TestLoaderErrorIsAUsageError(t *testing.T) {
	_, err := parseFlagsWith([]string{"verify", dHash}, &bytes.Buffer{}, func(string) (Defaults, error) { return Defaults{}, errors.New("boom") })
	var u usageError
	require.ErrorAs(t, err, &u)
}

func TestNoLoaderMeansNoConfigFlag(t *testing.T) {
	_, err := parseFlags([]string{"verify", dHash, "--config", "x", "--gate-key", dKey, "--archive", t.TempDir()}, &bytes.Buffer{})
	require.Error(t, err)
}

func TestNoConfigAndNoFlagsStillNeedsTheSources(t *testing.T) {
	_, err := parseFlagsWith([]string{"verify", dHash}, &bytes.Buffer{}, loader(Defaults{}, nil))
	require.Error(t, err)
}
