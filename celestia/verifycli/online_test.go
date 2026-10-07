package verifycli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/cometfake"
)

func decodeReport(t *testing.T, out string) map[string]any {
	t.Helper()
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	return rep
}

func trustOf(t *testing.T, rep map[string]any) map[string]any {
	t.Helper()
	ht, ok := rep["header_trust"].(map[string]any)
	require.True(t, ok)
	return ht
}

func statusOf(t *testing.T, rep map[string]any, name string) string {
	t.Helper()
	for _, c := range rep["checks"].([]any) {
		m := c.(map[string]any)
		if m["name"] == name {
			return m["status"].(string)
		}
	}
	return "absent"
}

func TestOnlineWithAnExplicitCheckpoint(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	rpc := s.rpc(t, s.cometChain(), nodeID(1))

	args := s.onlineArgs("verify", au, "--headers-rpc", rpc.URL, "--checkpoint", s.explicitCheckpoint())
	code, out := exec(t, args)
	require.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "[ok] header_trust")
	assert.Contains(t, out, "verdict: valid")

	code, out = exec(t, append(args, "--json"))
	require.Equal(t, exitValid, code, out)
	ht := trustOf(t, decodeReport(t, out))
	assert.Equal(t, "valid", ht["status"])
	assert.Equal(t, "explicit", ht["mode"])
	assert.EqualValues(t, checkpointH, ht["checkpoint_height"])
}

func TestOnlineHashMayComeBeforeOrAfterTheFlags(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	rpc := s.rpc(t, s.cometChain(), nodeID(1))
	h := fmt.Sprintf("%x", s.hash[:])
	flags := []string{"--gate-key", s.gateKey, "--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", s.explicitCheckpoint()}

	for name, args := range map[string][]string{
		"hash first": append([]string{"verify", h}, flags...),
		"hash last":  append(append([]string{"verify"}, flags...), h),
	} {
		code, out := exec(t, args)
		assert.Equal(t, exitValid, code, "%s: %s", name, out)
	}
}

func TestOnlineWithAnAgreedCheckpoint(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	ckpt := s.rpc(t, s.cometChain(), nodeID(2))

	args := s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint-rpc", ckpt.HostURL("localhost"), "--json")
	code, out := exec(t, args)
	require.Equal(t, exitValid, code, out)
	rep := decodeReport(t, out)
	ht := trustOf(t, rep)
	assert.Equal(t, "valid", ht["status"])
	assert.Equal(t, "agreed", ht["mode"])
	assert.EqualValues(t, 1, ht["quorum"], "the default quorum is one operator")
	assert.EqualValues(t, 1, ht["agreed"])
	assert.Equal(t, []any{"localhost"}, ht["sources"], "the report names the operator by host")
	assert.EqualValues(t, checkpointH, ht["checkpoint_height"])
	assert.Equal(t, hexOf(s.chain.hash(checkpointH)), ht["checkpoint_hash"])

	assert.NotEmpty(t, ckpt.Hits())
	for _, h := range headers.Hits() {
		assert.NotContains(t, h, "/status", "headers come from --headers-rpc, the checkpoint from --checkpoint-rpc")
	}
}

func TestOnlineWalksTheChainFromTheOnlineSource(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint()))
	require.Equal(t, exitValid, code, out)
	assert.NotEmpty(t, headers.Hits())
}

func TestOnlineUsesTheArchivedHeaderAtTheNeededHeight(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint()))
	require.Equal(t, exitValid, code, out)
	for _, h := range headers.Hits() {
		assert.NotEqual(t, fmt.Sprintf("/header?height=%d", anchorHeight), h, "the archived header of the anchor is offered first")
	}
}

func TestOnlineArchivedHeaderThatDoesNotLinkFails(t *testing.T) {
	s := newScenario(t, scenarioOpts{forgedHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint()))
	assert.Equal(t, exitInvalid, code, out)
	assert.Contains(t, out, "[FAIL] header_trust")
}

func TestOnlineHeaderThatDoesNotLinkIsTheSourcesFault(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	liar := s.rpc(t, s.forkAt(anchorHeight+4), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", liar.URL, "--checkpoint", s.explicitCheckpoint()))
	assert.Equal(t, exitUnchecked, code, "one source's bad header makes the check unchecked, not the decision invalid\n%s", out)
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.NotContains(t, out, "[FAIL]")
}

func TestOnlineCheckpointSources(t *testing.T) {
	t.Run("sources that disagree fail whatever the quorum", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		honest := s.rpc(t, s.cometChain(), nodeID(2))
		liar := s.rpc(t, s.forkFrom(anchorHeight+2), nodeID(3))
		for _, q := range []string{"1", "2"} {
			code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
				"--checkpoint-rpc", honest.HostURL("localhost"), "--checkpoint-rpc", liar.URL, "--checkpoint-quorum", q))
			assert.Equal(t, exitInvalid, code, "quorum %s\n%s", q, out)
			assert.Contains(t, out, "[FAIL] header_trust")
		}
	})
	t.Run("too few answering operators is unchecked", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		alive := s.rpc(t, s.cometChain(), nodeID(2))
		dead := s.rpc(t, s.cometChain(), nodeID(3))
		dead.Close()
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", alive.HostURL("localhost"), "--checkpoint-rpc", dead.URL, "--checkpoint-quorum", "2"))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] header_trust")
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("two host names of one node count once", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		a := s.rpc(t, s.cometChain(), nodeID(9))
		b := s.rpc(t, s.cometChain(), nodeID(9))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", a.HostURL("localhost"), "--checkpoint-rpc", b.URL, "--checkpoint-quorum", "2"))
		assert.Equal(t, exitUnchecked, code, out)

		code, out = exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", a.HostURL("localhost"), "--checkpoint-rpc", b.URL, "--checkpoint-quorum", "1", "--json"))
		require.Equal(t, exitValid, code, out)
		ht := trustOf(t, decodeReport(t, out))
		assert.EqualValues(t, 1, ht["agreed"])
	})
	t.Run("two distinct operators meet quorum two", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		a := s.rpc(t, s.cometChain(), nodeID(2))
		b := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", a.HostURL("localhost"), "--checkpoint-rpc", b.URL, "--checkpoint-quorum", "2", "--json"))
		require.Equal(t, exitValid, code, out)
		ht := trustOf(t, decodeReport(t, out))
		assert.EqualValues(t, 2, ht["agreed"])
		assert.EqualValues(t, 2, ht["quorum"])
		assert.ElementsMatch(t, []any{"localhost", "127.0.0.1"}, ht["sources"])
	})
	t.Run("the same host twice is refused", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		a := s.rpc(t, s.cometChain(), nodeID(2))
		b := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint-rpc", a.URL, "--checkpoint-rpc", b.URL))
		assert.Equal(t, exitUsage, code, out)
		assert.NotContains(t, out, "verdict")
	})
}

func TestOnlineCrossCheck(t *testing.T) {
	t.Run("agreeing node", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		ckpt := s.rpc(t, s.cometChain(), nodeID(2))
		cross := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", ckpt.HostURL("localhost"), "--cross-check", cross.URL, "--json"))
		require.Equal(t, exitValid, code, out)
		assert.Equal(t, "pass", trustOf(t, decodeReport(t, out))["cross_check"])
	})
	t.Run("a mismatch fails the verdict even when the checkpoint passed at quorum one", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		ckpt := s.rpc(t, s.cometChain(), nodeID(2))
		liar := s.rpc(t, s.forkFrom(anchorHeight-2), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", ckpt.HostURL("localhost"), "--cross-check", liar.URL, "--json"))
		assert.Equal(t, exitInvalid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "invalid", rep["verdict"])
		assert.Equal(t, "mismatch", trustOf(t, rep)["cross_check"])
		assert.Equal(t, "fail", statusOf(t, rep, "header_trust"))
	})
	t.Run("an unreachable node is reported and does not fail", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		ckpt := s.rpc(t, s.cometChain(), nodeID(2))
		dead := s.rpc(t, s.cometChain(), nodeID(3))
		dead.Close()
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", ckpt.HostURL("localhost"), "--cross-check", dead.URL, "--json"))
		require.Equal(t, exitValid, code, out)
		assert.Equal(t, "unavailable", trustOf(t, decodeReport(t, out))["cross_check"])
	})
	t.Run("a host that gave the checkpoint is not a cross-check", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		ckpt := s.rpc(t, s.cometChain(), nodeID(2))
		same := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint-rpc", ckpt.URL, "--cross-check", same.URL))
		assert.Equal(t, exitUsage, code, out)
	})
	t.Run("two cross-check urls on one host are refused", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		a := s.rpc(t, s.cometChain(), nodeID(2))
		b := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint(),
			"--cross-check", a.URL, "--cross-check", b.URL))
		assert.Equal(t, exitUsage, code, out)
	})
}

func TestOnlineWithoutAnyTrustedHeaderIsUnchecked(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	code, out := exec(t, s.onlineArgs("verify", au))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] header_trust")
}

func TestOnlineTrustedFileStillWorksWithTheRemoteArchive(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.onlineArgs("verify", au, "--trusted", trusted, "--json"))
	require.Equal(t, exitValid, code, out)
	assert.Equal(t, "file", trustOf(t, decodeReport(t, out))["mode"])
}

func TestOnlineArchiveOutcomes(t *testing.T) {
	trust := func(s *scenario, t *testing.T) []string {
		return []string{"--trusted", s.chain.trustedFile(t, checkpointH, nil)}
	}
	t.Run("a withheld authorization is not authorized", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, hide(map[string]int{s.path("authorization"): http.StatusNotFound}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitNotAuthorized, code, out)
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("a withheld payload fails", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		pay := "/payload/2/" + hexOf(s.commitmentBytes(t))
		au := s.serveArchive(t, hide(map[string]int{pay: http.StatusGone}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitInvalid, code, out)
		assert.Contains(t, out, "[FAIL] payload")
	})
	t.Run("a withheld decision fails", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, hide(map[string]int{s.path("decision"): http.StatusNotFound}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitInvalid, code, out)
		assert.Contains(t, out, "[FAIL] decision")
	})
	t.Run("a tampered payload fails the payload check", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{tamperBlob: true, realHeader: true})
		au := s.serveArchive(t, nil)
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitInvalid, code, out)
		assert.Contains(t, out, "[FAIL] payload")
	})
	faults := []int{http.StatusServiceUnavailable, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError}
	for _, code := range faults {
		for _, kind := range []string{"decision", "authorization", "payload", "evidence"} {
			t.Run(fmt.Sprintf("a %d on the %s gives no verdict", code, kind), func(t *testing.T) {
				s := newScenario(t, scenarioOpts{realHeader: true})
				p := s.path(kind)
				if kind == "payload" || kind == "evidence" {
					p = "/" + kind + "/2/" + hexOf(s.commitmentBytes(t))
				}
				au := s.serveArchive(t, hide(map[string]int{p: code}))
				got, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
				assert.Equal(t, exitUsage, got, out)
				assert.NotContains(t, out, "verdict:")

				got, out = exec(t, s.onlineArgs("verify", au, append(trust(s, t), "--json")...))
				assert.Equal(t, exitUsage, got)
				var e map[string]any
				require.NoError(t, json.Unmarshal([]byte(out), &e), out)
				assert.NotEmpty(t, e["error"])
				assert.NotContains(t, e, "verdict")
			})
		}
	}
	t.Run("a fault on a marker read gives no verdict", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{pending: true, realHeader: true})
		p := "/rejection/" + hexOf(s.hash[:]) + "/ErrNonceUsed"
		au := s.serveArchive(t, hide(map[string]int{p: http.StatusServiceUnavailable}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitUsage, code, out)
		assert.NotContains(t, out, "pending")
	})
	t.Run("the archive server is down", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		code, out := exec(t, s.onlineArgs("verify", "http://127.0.0.1:1", trust(s, t)...))
		assert.Equal(t, exitUsage, code, out)
	})
	t.Run("replay reads the same way", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		code, out := exec(t, s.onlineArgs("replay", au, trust(s, t)...))
		assert.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "retention replay")
	})
}

func TestOnlineUsageErrors(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	rpc := s.rpc(t, s.cometChain(), nodeID(1))
	h := hexOf(s.hash[:])
	base := []string{"verify", h, "--gate-key", s.gateKey}
	with := func(extra ...string) []string { return append(append([]string(nil), base...), extra...) }
	tests := []struct {
		name string
		args []string
	}{
		{"no archive at all", with()},
		{"both archive kinds", with("--archive", s.archiveDir, "--archive-url", au)},
		{"archive url is not http", with("--archive-url", "ftp://archive.example")},
		{"archive url has a query", with("--archive-url", au+"?x=1")},
		{"archive url has user info", with("--archive-url", "http://u:p@127.0.0.1:1")},
		{"archive url empty", with("--archive-url", "")},
		{"checkpoint without a colon", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", "4200010")},
		{"checkpoint height not a number", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", "x:"+hexOf(s.chain.hash(checkpointH)))},
		{"checkpoint hash not hex", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", "4200010:zz")},
		{"checkpoint height zero", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", "0:"+hexOf(s.chain.hash(checkpointH)))},
		{"checkpoint hash empty", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", "4200010:")},
		{"quorum zero", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint-rpc", rpc.URL, "--checkpoint-quorum", "0")},
		{"quorum negative", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint-rpc", rpc.URL, "--checkpoint-quorum", "-1")},
		{"quorum not a number", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint-rpc", rpc.URL, "--checkpoint-quorum", "two")},
		{"headers rpc is not a url", with("--archive-url", au, "--headers-rpc", "not a url", "--checkpoint", s.explicitCheckpoint())},
		{"headers rpc is not http", with("--archive-url", au, "--headers-rpc", "ftp://rpc.example", "--checkpoint", s.explicitCheckpoint())},
		{"checkpoint rpc is not http", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint-rpc", "ws://rpc.example")},
		{"cross-check is not http", with("--archive-url", au, "--headers-rpc", rpc.URL, "--checkpoint", s.explicitCheckpoint(), "--cross-check", "ftp://rpc.example")},
		{"receipt file missing", with("--archive-url", au, "--receipt", "/nonexistent/receipt.cbor", "--check-execution")},
		{"unknown flag", with("--archive-url", au, "--no-such-flag")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out := exec(t, tc.args)
			assert.Equal(t, exitUsage, code, out)
			assert.NotEmpty(t, out)
			assert.NotContains(t, out, "verdict:")
		})
	}
}

func TestOnlineUsageErrorsAreJSONWithTheFlag(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	code, out := exec(t, []string{"verify", hexOf(s.hash[:]), "--gate-key", s.gateKey, "--archive-url", "ftp://x", "--json"})
	assert.Equal(t, exitUsage, code)
	var e map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &e), out)
	assert.NotEmpty(t, e["error"])
}

// execution

const execHeight = anchorHeight + 3

type bankWorld struct {
	s       *scenario
	au      string
	headers *cometfake.Server
	tx      []byte
	ref     string
	receipt string
}

func newBankWorld(t *testing.T, mod func(w *bankWorld, tx *cometfake.Tx)) *bankWorld {
	t.Helper()
	s := newScenario(t, scenarioOpts{bank: true, realHeader: true})
	w := &bankWorld{s: s, au: s.serveArchive(t, nil)}
	w.tx = s.bankTx(t, 7_000_000)
	w.ref = refOf(w.tx)
	w.headers = s.rpc(t, s.cometChain(), nodeID(1))
	tx := cometfake.Tx{Height: execHeight, Bytes: w.tx}
	if mod != nil {
		mod(w, &tx)
	}
	w.headers.PutTx(tx)
	w.receipt = writeReceipt(t, s.receipt(t, w.ref))
	return w
}

func (w *bankWorld) args(extra ...string) []string {
	a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
		"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json")
	return append(a, extra...)
}

func TestExecutionCheckThroughTheCLI(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		w := newBankWorld(t, nil)
		code, out := exec(t, w.args())
		require.Equal(t, exitValid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "valid", rep["verdict"])
		assert.Equal(t, "pass", statusOf(t, rep, "execution"))
		assert.Equal(t, "pass", statusOf(t, rep, "receipt"))

		ex, ok := rep["execution"].(map[string]any)
		require.True(t, ok, "the report carries the execution facts")
		assert.Equal(t, w.ref, ex["rail_ref"])
		assert.EqualValues(t, execHeight, ex["height"])
		assert.Equal(t, hexOf(w.s.chain.hash(execHeight)), ex["header_hash"])
		assert.NotZero(t, ex["block_time"])
		assert.Equal(t, "node-attested", ex["inclusion"], "no proof from this node")
		assert.Equal(t, "node-attested", ex["result"])
		assert.Equal(t, "off", ex["cross_check"])
		assert.Equal(t, []any{"127.0.0.1"}, ex["sources"])

		rc := rep["receipt"].(map[string]any)
		assert.Equal(t, false, rc["proven_execution"])
		assert.Equal(t, true, rc["gate_attested"])
	})
	t.Run("text report", func(t *testing.T) {
		w := newBankWorld(t, nil)
		args := w.args()
		args = args[:len(args)-1]
		code, out := exec(t, args)
		require.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "[ok] execution")
		assert.Contains(t, out, "verdict: valid")
	})
	t.Run("without the flag the receipt is only attested", func(t *testing.T) {
		w := newBankWorld(t, nil)
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(), "--receipt", w.receipt, "--json")
		code, out := exec(t, a)
		require.Equal(t, exitValid, code, out)
		rep := decodeReport(t, out)
		assert.NotContains(t, rep, "execution")
		assert.Equal(t, "absent", statusOf(t, rep, "execution"))
		for _, h := range w.headers.Hits() {
			assert.NotContains(t, h, "/tx?", "no transaction is looked up unless asked")
		}
	})
	t.Run("a transaction at the anchor height", func(t *testing.T) {
		w := newBankWorld(t, func(_ *bankWorld, tx *cometfake.Tx) { tx.Height = anchorHeight })
		code, out := exec(t, w.args())
		assert.Equal(t, exitInvalid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "fail", statusOf(t, rep, "execution"))
	})
	t.Run("a failed transaction", func(t *testing.T) {
		w := newBankWorld(t, func(_ *bankWorld, tx *cometfake.Tx) { tx.Code = 5 })
		code, out := exec(t, w.args())
		assert.Equal(t, exitInvalid, code, out)
		assert.Equal(t, "fail", statusOf(t, decodeReport(t, out), "execution"))
	})
	t.Run("a transaction the node does not have", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{bank: true, realHeader: true})
		au := s.serveArchive(t, nil)
		empty := s.rpc(t, s.cometChain(), nodeID(1))
		tx := s.bankTx(t, 7_000_000)
		args := s.onlineArgs("verify", au, "--headers-rpc", empty.URL, "--checkpoint", s.explicitCheckpoint(),
			"--receipt", writeReceipt(t, s.receipt(t, refOf(tx))), "--tx-rpc", empty.URL, "--check-execution", "--json")
		code, out := exec(t, args)
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
		assert.NotEqual(t, "valid", rep["verdict"])
	})
	t.Run("the transaction source is down", func(t *testing.T) {
		w := newBankWorld(t, nil)
		dead := s2dead(t, w)
		code, out := exec(t, w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", dead, "--check-execution", "--json"))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Equal(t, "unchecked", statusOf(t, decodeReport(t, out), "execution"))
	})
	t.Run("the receipt names another transaction with the same body", func(t *testing.T) {
		w := newBankWorld(t, nil)
		other := w.s.bankTx(t, 7_000_001)
		w.headers.PutTx(cometfake.Tx{Height: execHeight, Bytes: other, Code: 0})
		receipt := writeReceipt(t, w.s.receipt(t, refOf(other)))
		args := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json")
		code, out := exec(t, args)
		assert.Equal(t, exitValid, code, "a second transaction with the same body is not detected here\n%s", out)
	})
	t.Run("the transaction is above the trusted header", func(t *testing.T) {
		w := newBankWorld(t, nil)
		args := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL,
			"--checkpoint", fmt.Sprintf("%d:%s", anchorHeight+2, hexOf(w.s.chain.hash(anchorHeight+2))),
			"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json")
		code, out := exec(t, args)
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "pass", statusOf(t, rep, "header_trust"))
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
	})
	t.Run("requested without a receipt", func(t *testing.T) {
		w := newBankWorld(t, nil)
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--tx-rpc", w.headers.URL, "--check-execution")
		code, out := exec(t, a)
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] execution")
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("requested without a transaction source", func(t *testing.T) {
		w := newBankWorld(t, nil)
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--check-execution")
		code, out := exec(t, a)
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] execution")
	})
	t.Run("a bad receipt file", func(t *testing.T) {
		w := newBankWorld(t, nil)
		bad := writeReceipt(t, []byte("garbage"))
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", bad, "--tx-rpc", w.headers.URL, "--check-execution", "--json")
		code, out := exec(t, a)
		assert.Equal(t, exitInvalid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "fail", statusOf(t, rep, "receipt"))
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
	})
	t.Run("a cross-check node that agrees", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx})
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		require.Equal(t, exitValid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "pass", rep["execution"].(map[string]any)["cross_check"])
		assert.Equal(t, "pass", trustOf(t, rep)["cross_check"])
	})
	t.Run("a cross-check node that disagrees fails the execution", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx, Code: 11})
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		assert.Equal(t, exitInvalid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "fail", statusOf(t, rep, "execution"))
		assert.Equal(t, "pass", statusOf(t, rep, "header_trust"), "the headers agree; the transaction does not")
	})
	t.Run("a cross-check node without the transaction", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		require.Equal(t, exitValid, code, out)
		assert.Equal(t, "unavailable", decodeReport(t, out)["execution"].(map[string]any)["cross_check"])
	})
}

func s2dead(t *testing.T, w *bankWorld) string {
	t.Helper()
	dead := w.s.rpc(t, w.s.cometChain(), nodeID(5))
	dead.Close()
	return dead.URL
}
