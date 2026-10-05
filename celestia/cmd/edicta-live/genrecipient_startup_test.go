package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closedLoopbackAddr is a local address nothing listens on: connecting is
// refused at once, with no traffic leaving the machine.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestStartupFailureLeavesNoRecipientKeyFile(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "agent.key")
	require.NoError(t, os.WriteFile(agent, bytes.Repeat([]byte{7}, seedLen), 0o600))
	execKey := filepath.Join(dir, "exec.key")
	require.NoError(t, os.WriteFile(execKey, bytes.Repeat([]byte{8}, seedLen), 0o600))
	pass := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(pass, []byte("fixture-passphrase\n"), 0o600))
	gen := filepath.Join(dir, "recipient.key")
	dead := closedLoopbackAddr(t)

	cfg, err := parse(t,
		"--agent-key-file", agent,
		"--executor-passphrase-file", pass,
		"--executor-ed25519-file", execKey,
		"--bridge-addr", dead, "--bridge-tls=false",
		"--grpc-addr", dead, "--grpc-tls=false",
		"--gen-recipient-key", gen,
	)
	require.NoError(t, err)
	require.Equal(t, gen, cfg.GenRecipient)
	cfg.Timeout = 5 * time.Second

	var logs bytes.Buffer
	err = live(context.Background(), cfg, runEnv{Out: &bytes.Buffer{}, Log: &logs, Stdin: os.Stdin})
	require.Error(t, err)

	_, statErr := os.Stat(gen)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "a failed startup must not burn the recipient key path")
	assert.NotContains(t, logs.String(), "created recipient key file")
}

func TestExistingRecipientKeyPathRefusedBeforeAnyNetworkStep(t *testing.T) {
	dir := t.TempDir()
	agent := filepath.Join(dir, "agent.key")
	require.NoError(t, os.WriteFile(agent, bytes.Repeat([]byte{7}, seedLen), 0o600))
	execKey := filepath.Join(dir, "exec.key")
	require.NoError(t, os.WriteFile(execKey, bytes.Repeat([]byte{8}, seedLen), 0o600))
	pass := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(pass, []byte("fixture-passphrase\n"), 0o600))
	gen := filepath.Join(dir, "recipient.key")
	require.NoError(t, os.WriteFile(gen, []byte("keep me\n"), 0o600))
	dead := closedLoopbackAddr(t)

	cfg, err := parse(t,
		"--agent-key-file", agent,
		"--executor-passphrase-file", pass,
		"--executor-ed25519-file", execKey,
		"--bridge-addr", dead, "--bridge-tls=false",
		"--grpc-addr", dead, "--grpc-tls=false",
		"--gen-recipient-key", gen,
	)
	require.NoError(t, err)
	cfg.Timeout = 5 * time.Second

	var logs bytes.Buffer
	err = live(context.Background(), cfg, runEnv{Out: &bytes.Buffer{}, Log: &logs, Stdin: os.Stdin})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), gen)
	assert.NotContains(t, err.Error(), "bridge")
	assert.NotContains(t, err.Error(), "consensus")
	assert.NotContains(t, logs.String(), "chain ")

	b, rerr := os.ReadFile(gen)
	require.NoError(t, rerr)
	assert.Equal(t, "keep me\n", string(b))
}

func TestReserveRecipientKeyExistingPathRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipient.key")
	require.NoError(t, os.WriteFile(path, []byte("keep me\n"), 0o600))

	_, rel, err := reserveRecipientKey(path)
	require.ErrorIs(t, err, os.ErrExist)
	assert.Contains(t, err.Error(), path)
	assert.Nil(t, rel)

	b, rerr := os.ReadFile(path)
	require.NoError(t, rerr)
	assert.Equal(t, "keep me\n", string(b))
}

func TestReserveRecipientKeyRelease(t *testing.T) {
	for _, keep := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "recipient.key")
		rc, rel, err := reserveRecipientKey(path)
		require.NoError(t, err)
		require.NotNil(t, rc.PublicKey)
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

		rel(keep)
		rel(keep)
		_, err = os.Stat(path)
		if keep {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}
