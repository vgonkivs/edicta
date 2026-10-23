// SPDX-License-Identifier: Apache-2.0

//go:build unix

package clicmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

// Two agent serve processes on one state directory would each keep their
// own in-memory order of the handoff's once mark; the second must not start.
func TestAgentServeHoldsTheStateDirectory(t *testing.T) {
	fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
	dir := filepath.Join(t.TempDir(), "state")
	args := []string{"serve", "--listen", "127.0.0.1:0", "--state-dir", dir, "--payment-server", "https://pay.example"}

	ctx, cancel := context.WithCancel(context.Background())
	var first syncBuffer
	done := make(chan int, 1)
	go func() { done <- runAgent(ctx, args, &first) }()
	require.Eventually(t, func() bool { return strings.Contains(first.String(), "listening on 127.0.0.1:") }, 5*time.Second, 10*time.Millisecond)

	// Bounded so that a second serve that does start ends the test instead
	// of hanging it.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	var second syncBuffer
	code := runAgent(ctx2, args, &second)
	assert.Equal(t, commitcmd.ExitUnavailable, code)
	assert.Contains(t, second.String(), "held by another process")
	assert.NotContains(t, second.String(), "listening")

	cancel()
	select {
	case code := <-done:
		assert.Equal(t, commitcmd.ExitOK, code)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}

	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err, "a stopped serve lets the directory go")
	unlock()
}

func TestAgentServeRefusesAHeldStateDirectoryBeforeBuilding(t *testing.T) {
	g := newCLIGate(t)
	fakeService(t, g, sdktest.NewPublisher(commitment.DACelestiaBlob))
	dir := filepath.Join(t.TempDir(), "state")
	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err)
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out syncBuffer
	code := runAgent(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--state-dir", dir}, &out)
	assert.Equal(t, commitcmd.ExitUnavailable, code)
	assert.Contains(t, out.String(), "state directory in use")
	assert.Empty(t, g.got.stateDir, "the service is not built over a held directory")
}

// A one-shot commit on the directory a serve holds would save its run
// beside the serve's own, outside the serve's ordering of the once mark.
func TestCommitRefusesAStateDirectoryAServeHolds(t *testing.T) {
	g := newCLIGate(t)
	fakeService(t, g, sdktest.NewPublisher(commitment.DACelestiaBlob))
	dir := filepath.Join(t.TempDir(), "state")

	ctx, cancel := context.WithCancel(context.Background())
	var serving syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- runAgent(ctx, []string{"serve", "--listen", "127.0.0.1:0", "--state-dir", dir}, &serving)
	}()
	require.Eventually(t, func() bool { return strings.Contains(serving.String(), "listening on 127.0.0.1:") }, 5*time.Second, 10*time.Millisecond)

	for _, args := range [][]string{
		{"--request", "-", "--recipient", "00", "--state-dir", dir},
		{"--request", "-", "--recipient", "00", "--state-dir", dir, "--resume-hash", strings.Repeat("ab", 32)},
	} {
		g.got = commonOpts{}
		code, out := commit(t, goodRequest, args...)
		assert.Equal(t, commitcmd.ExitUnavailable, code, out)
		var body struct {
			Error struct {
				Code      string `json:"code"`
				Message   string `json:"message"`
				Retryable bool   `json:"retryable"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &body), out)
		assert.Equal(t, "busy", body.Error.Code)
		assert.True(t, body.Error.Retryable)
		assert.Contains(t, body.Error.Message, "held by another process")
		assert.Empty(t, g.got.stateDir, "the service is not built over a held directory")
	}

	cancel()
	select {
	case code := <-done:
		assert.Equal(t, commitcmd.ExitOK, code)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}

	code, out := commit(t, goodRequest, "--request", "-", "--recipient", "00", "--state-dir", dir)
	require.Equal(t, commitcmd.ExitOK, code, out)
	unlock, err := commitcmd.LockStateDir(dir)
	require.NoError(t, err, "a finished commit lets the directory go")
	unlock()
}

func TestCommitRefusesAnUnusableStateDirectory(t *testing.T) {
	fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
	open := filepath.Join(t.TempDir(), "open")
	require.NoError(t, os.Mkdir(open, 0o755))
	require.NoError(t, os.Chmod(open, 0o755))
	code, out := commit(t, goodRequest, "--request", "-", "--recipient", "00", "--state-dir", open)
	assert.Equal(t, commitcmd.ExitUsage, code, out)
	assert.Contains(t, out, "only its owner can access")
}
