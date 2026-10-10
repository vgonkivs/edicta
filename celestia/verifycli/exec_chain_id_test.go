package verifycli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
)

// --exec-chain-id names the chain a revealed private bank send is rebuilt
// for; without it the chain of the trusted header at the reference height
// is taken. A chain the transfer did not run on gives another action, which
// the action hash refuses, and the reason says a chain mismatch may be why.
func TestExecChainID(t *testing.T) {
	ok := []cometfake.Result{{Code: 0, Data: []byte("r"), GasWanted: 10, GasUsed: 9}}
	run := func(t *testing.T, extra ...string) (int, map[string]any, string) {
		t.Helper()
		w := newProvenWorld(t, provenOpts{results: ok})
		ro, err := fsarchive.OpenReadOnly(w.s.archiveDir, nil)
		require.NoError(t, err)
		dec, err := ro.Decision(context.Background(), w.s.hash)
		require.NoError(t, err)
		privatize(t, w, dec.ActionSalt)
		args := append([]string{"verify", hexOf(w.s.hash[:]), "--archive", w.s.archiveDir, "--gate-key", w.s.gateKey,
			"--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json"}, extra...)
		code, out := exec(t, args)
		return code, decodeReport(t, out), out
	}

	t.Run("the chain the transfer ran on", func(t *testing.T) {
		code, rep, out := run(t, "--exec-chain-id", chainID)
		require.Equal(t, exitValid, code, out)
		assert.Equal(t, "pass", statusOf(t, rep, "action"))
		assert.Equal(t, "pass", statusOf(t, rep, "execution"))
	})
	t.Run("another chain", func(t *testing.T) {
		code, rep, out := run(t, "--exec-chain-id", "celestia")
		assert.Equal(t, exitUnchecked, code, out)
		c := checkOf(t, rep, "action")
		assert.Equal(t, "unchecked", c["status"])
		assert.Equal(t, "source_corrupt", c["reason"])
		assert.Contains(t, c["error"], "another chain")
		assert.NotEqual(t, "valid", rep["verdict"])
	})
	t.Run("only with --check-execution", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{})
		code, out := exec(t, s.args("verify", "--trusted", s.chain.trustedFile(t, checkpointH, nil), "--exec-chain-id", chainID))
		assert.Equal(t, codeUsage, code, out)
		assert.Contains(t, out, "--exec-chain-id is used only with --check-execution")
	})
}
