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
