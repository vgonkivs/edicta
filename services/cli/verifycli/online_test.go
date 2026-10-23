package verifycli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
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

func checkOf(t *testing.T, rep map[string]any, name string) map[string]any {
	t.Helper()
	for _, c := range rep["checks"].([]any) {
		m := c.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	require.Failf(t, "no such check", "%s", name)
	return nil
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

// The archive presents a header that the trusted chain does not have. The
// archive is a source, so this says nothing about the decision itself.
func TestOnlineArchivedHeaderThatDoesNotLinkIsInconclusive(t *testing.T) {
	s := newScenario(t, scenarioOpts{forgedHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint()))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.Contains(t, out, "reason: chain_mismatch")
	assert.Contains(t, out, "advice: another archive copy, or check the trusted header")
	assert.NotContains(t, out, "[FAIL]")
}

func TestOnlineHeaderThatDoesNotLinkIsTheSourcesFault(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	liar := s.rpc(t, s.forkAt(anchorHeight+4), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", liar.URL, "--checkpoint", s.explicitCheckpoint()))
	assert.Equal(t, exitUnchecked, code, "one source's bad header makes the check unchecked, not the decision invalid\n%s", out)
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.Contains(t, out, "reason: header_not_linking")
	assert.Contains(t, out, "source: 127.0.0.1", "the source that served the header is named")
	assert.NotContains(t, out, "[FAIL]")
}

func TestOnlineCheckpointSources(t *testing.T) {
	t.Run("sources that disagree are inconclusive whatever the quorum", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		honest := s.rpc(t, s.cometChain(), nodeID(2))
		liar := s.rpc(t, s.forkFrom(anchorHeight+2), nodeID(3))
		for _, q := range []string{"1", "2"} {
			code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
				"--checkpoint-rpc", honest.HostURL("localhost"), "--checkpoint-rpc", liar.URL, "--checkpoint-quorum", q))
			assert.Equal(t, exitUnchecked, code, "quorum %s\n%s", q, out)
			assert.Contains(t, out, "[unchecked] header_trust")
			assert.Contains(t, out, "reason: header_disagreement")
			assert.Contains(t, out, "possible bad trusted header, hostile source, or fork")
			assert.NotContains(t, out, "[FAIL]")
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
		assert.Contains(t, out, "reason: checkpoint_quorum")
		assert.NotContains(t, out, "verdict: valid")
	})
	t.Run("no operator answers", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		dead := s.rpc(t, s.cometChain(), nodeID(3))
		dead.Close()
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint-rpc", dead.URL))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "reason: header_source_unavailable")
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
		cross := s.rpc(t, s.cometChain(), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint", s.explicitCheckpoint(), "--cross-check", cross.HostURL("localhost"), "--json"))
		require.Equal(t, exitValid, code, out)
		assert.Equal(t, "pass", trustOf(t, decodeReport(t, out))["cross_check"])
	})
	t.Run("a mismatch holds the verdict back even when the checkpoint passed at quorum one", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		liar := s.rpc(t, s.forkFrom(anchorHeight-2), nodeID(3))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint", s.explicitCheckpoint(), "--cross-check", liar.HostURL("localhost"), "--json"))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", rep["verdict"])
		assert.Equal(t, "mismatch", trustOf(t, rep)["cross_check"])
		assert.Equal(t, "unchecked", statusOf(t, rep, "header_trust"))
		assert.Equal(t, "header_disagreement", checkOf(t, rep, "header_trust")["reason"])
	})
	t.Run("an unreachable node is reported and does not fail", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		dead := s.rpc(t, s.cometChain(), nodeID(3))
		dead.Close()
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
			"--checkpoint", s.explicitCheckpoint(), "--cross-check", dead.HostURL("localhost"), "--json"))
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
	t.Run("a withheld payload is inconclusive: a retention failure of the operator", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		pay := "/payload/2/" + hexOf(s.commitmentBytes(t))
		au := s.serveArchive(t, hide(map[string]int{pay: http.StatusGone}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] payload")
		assert.Contains(t, out, "reason: payload_unavailable")
		assert.Contains(t, out, "advice: another archive copy")
		assert.NotContains(t, out, "[FAIL]")
	})
	t.Run("a withheld evidence record is inconclusive", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		ev := "/evidence/2/" + hexOf(s.commitmentBytes(t))
		au := s.serveArchive(t, hide(map[string]int{ev: http.StatusNotFound}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "reason: evidence_unavailable")
	})
	t.Run("a withheld decision is inconclusive", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, hide(map[string]int{s.path("decision"): http.StatusNotFound}))
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] decision")
		assert.Contains(t, out, "reason: decision_unavailable")
	})
	t.Run("a tampered payload is inconclusive: try another copy", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{tamperBlob: true, realHeader: true})
		au := s.serveArchive(t, nil)
		code, out := exec(t, s.onlineArgs("verify", au, trust(s, t)...))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Contains(t, out, "[unchecked] payload")
		assert.Contains(t, out, "reason: source_corrupt")
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
	return append(w.textArgs("--json"), extra...)
}

// textArgs is args without --json, for the text report.
func (w *bankWorld) textArgs(extra ...string) []string {
	a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
		"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution")
	return append(a, extra...)
}

// provenOpts shapes a world whose chain commits to the transaction: the data
// root of its block is the root of a real inclusion proof, and the header
// after it carries the hash of the block's results.
type provenOpts struct {
	// results are what the node serves for the block, and the headers commit
	// to; nil serves none, as a node that keeps no results.
	results []cometfake.Result
	// committed are the results the header commits to, if they are not the
	// served ones.
	committed []cometfake.Result
	// txCode is the code the node reports for the transaction.
	txCode uint32
	// height is the block of the transaction.
	height uint64
}

func newProvenWorld(t *testing.T, o provenOpts) *bankWorld {
	t.Helper()
	height := o.height
	if height == 0 {
		height = execHeight
	}
	// The transaction and the commitment hash are the same in every scenario,
	// so a first one gives the bytes the chain has to commit to.
	probe := newScenario(t, scenarioOpts{bank: true, realHeader: true})
	tx := probe.bankTx(t, 7_000_000)
	pf, root := proofOf(t, [][]byte{tx}, 0)

	committed := o.committed
	if committed == nil {
		committed = o.results
	}
	toTx := func(rs []cometfake.Result) []railverify.TxResult {
		out := make([]railverify.TxResult, len(rs))
		for i, r := range rs {
			out[i] = railverify.TxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}
		}
		return out
	}
	resRoot, err := railverify.ResultsRoot(toTx(committed))
	require.NoError(t, err)
	s := newScenario(t, scenarioOpts{bank: true, realHeader: true, chainMod: func(h uint64, hd *core.Header) {
		switch h {
		case height:
			hd.DataHash = root
		case height + 1:
			hd.LastResultsHash = resRoot
		}
	}})
	w := &bankWorld{s: s, au: s.serveArchive(t, nil), tx: tx, ref: refOf(tx)}
	w.headers = s.rpc(t, s.cometChain(), nodeID(1))
	w.headers.PutTx(cometfake.Tx{Height: height, Bytes: tx, Code: o.txCode, Proof: pf})
	if o.results != nil {
		w.headers.Results[height] = o.results
	}
	w.receipt = writeReceipt(t, s.receipt(t, w.ref))
	return w
}

func TestExecutionCheckThroughTheCLI(t *testing.T) {
	ok := []cometfake.Result{{Code: 0, Data: []byte("r"), GasWanted: 10, GasUsed: 9}}

	t.Run("valid: the inclusion and the result are proven against the trusted chain", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
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
		assert.Equal(t, "proven", ex["inclusion"])
		assert.Equal(t, "success", ex["outcome"])
		assert.Equal(t, "proven", ex["result"])
		assert.Equal(t, "off", ex["cross_check"])
		assert.Equal(t, []any{map[string]any{"name": "127.0.0.1", "role": "primary", "result": "used"}}, ex["sources"])

		rc := rep["receipt"].(map[string]any)
		assert.Equal(t, true, rc["proven_execution"])
		assert.Equal(t, true, rc["gate_attested"])
	})
	t.Run("text report", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		code, out := exec(t, w.textArgs())
		require.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "[ok] execution")
		assert.Contains(t, out, "tx source 127.0.0.1 (primary): used")
		assert.Contains(t, out, "verdict: valid")
		assert.NotContains(t, out, "node-attested")
	})
	t.Run("the proven code replaces the node's", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok, txCode: 5})
		code, out := exec(t, w.args())
		require.Equal(t, exitValid, code, "a node that says failed cannot fail a transaction whose result is proven\n%s", out)
		assert.Equal(t, "success", decodeReport(t, out)["execution"].(map[string]any)["outcome"])
	})
	t.Run("a failed result that is proven is invalid", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: []cometfake.Result{{Code: 11, Data: []byte("r")}}})
		code, out := exec(t, w.args())
		assert.Equal(t, exitInvalid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "fail", statusOf(t, rep, "execution"))
		assert.Equal(t, "failure", rep["execution"].(map[string]any)["outcome"])
	})
	t.Run("results that do not hash to the trusted header are unchecked", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: []cometfake.Result{{Code: 0}, {Code: 7}}, committed: ok})
		code, out := exec(t, w.args())
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
		c := checkOf(t, rep, "execution")
		assert.Equal(t, "results_root_mismatch", c["reason"])
		assert.Equal(t, []any{"127.0.0.1"}, c["sources"])
		assert.Equal(t, "another results source", c["advice"])
	})
	t.Run("a node that keeps no results leaves the result unproven", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{committed: ok})
		code, out := exec(t, w.args())
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		c := checkOf(t, rep, "execution")
		assert.Equal(t, "result_unproven", c["reason"])
		assert.Equal(t, "a tx source that serves inclusion proofs and a source that serves block_results", c["advice"])
		assert.Equal(t, "proven", rep["execution"].(map[string]any)["inclusion"], "the inclusion still holds")
		assert.Equal(t, "pass", statusOf(t, rep, "header_trust"))
	})
	t.Run("the result of the newest block waits for the next header", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok, height: checkpointH})
		code, out := exec(t, w.args())
		assert.Equal(t, exitUnchecked, code, out)
		assert.Equal(t, "result_header_unreachable", checkOf(t, decodeReport(t, out), "execution")["reason"])
	})
	t.Run("a transaction at the anchor height with a proof is invalid", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok, height: anchorHeight})
		code, out := exec(t, w.args())
		assert.Equal(t, exitInvalid, code, out)
		assert.Equal(t, "fail", statusOf(t, decodeReport(t, out), "execution"))
	})
	t.Run("a second transaction source is tried when the first knows nothing", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		// The headers node knows no transaction; the alternate holds it all.
		alt := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		for k, v := range w.headers.Txs {
			alt.Txs[k] = v
		}
		alt.Results[execHeight] = ok
		w.headers.Txs = map[string]cometfake.Tx{}
		args := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--tx-rpc", alt.HostURL("localhost"), "--check-execution", "--json")
		code, out := exec(t, args)
		require.Equal(t, exitValid, code, out)
		sources := decodeReport(t, out)["execution"].(map[string]any)["sources"].([]any)
		require.Len(t, sources, 2)
		first := sources[0].(map[string]any)
		assert.Equal(t, "127.0.0.1", first["name"])
		assert.Equal(t, "set_aside", first["result"])
		assert.Equal(t, "tx_not_found", first["reason"])
		assert.Equal(t, "alternate", sources[1].(map[string]any)["role"])
		assert.Equal(t, "used", sources[1].(map[string]any)["result"])
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
		assert.Equal(t, "tx_not_found", checkOf(t, rep, "execution")["reason"])
		assert.NotEqual(t, "valid", rep["verdict"])
	})
	t.Run("the transaction source is down", func(t *testing.T) {
		w := newBankWorld(t, nil)
		dead := s2dead(t, w)
		code, out := exec(t, w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", dead, "--check-execution", "--json"))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
		assert.Equal(t, "tx_source_unavailable", checkOf(t, rep, "execution")["reason"])
	})
	t.Run("the receipt names another transaction with the same body", func(t *testing.T) {
		w := newBankWorld(t, nil)
		other := w.s.bankTx(t, 7_000_001)
		w.headers.PutTx(cometfake.Tx{Height: execHeight, Bytes: other, Code: 0})
		receipt := writeReceipt(t, w.s.receipt(t, refOf(other)))
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: other})
		args := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", receipt, "--tx-rpc", w.headers.URL, "--cross-check", cross.HostURL("localhost"), "--check-execution", "--json")
		code, out := exec(t, args)
		assert.Equal(t, exitUnchecked, code, "agreeing sources without a result proof never pass\n%s", out)
		rep := decodeReport(t, out)
		assert.Equal(t, "result_unproven", checkOf(t, rep, "execution")["reason"])
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
		assert.Equal(t, "header_above_checkpoint", checkOf(t, rep, "execution")["reason"])
	})
	t.Run("requested without a receipt", func(t *testing.T) {
		w := newBankWorld(t, nil)
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--tx-rpc", w.headers.URL, "--check-execution")
		code, out := exec(t, a)
		assert.Equal(t, exitUsage, code, out)
		assert.Contains(t, out, "--check-execution needs --receipt and --tx-rpc")
		assert.NotContains(t, out, "verdict")
	})
	t.Run("requested without a transaction source", func(t *testing.T) {
		w := newBankWorld(t, nil)
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--check-execution")
		code, out := exec(t, a)
		assert.Equal(t, exitUsage, code, out)
		assert.Contains(t, out, "--check-execution needs --receipt and --tx-rpc")
		assert.NotContains(t, out, "verdict")
	})
	t.Run("a bad receipt file", func(t *testing.T) {
		w := newBankWorld(t, nil)
		bad := writeReceipt(t, []byte("garbage"))
		a := w.s.onlineArgs("verify", w.au, "--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", bad, "--tx-rpc", w.headers.URL, "--check-execution", "--json")
		code, out := exec(t, a)
		assert.Equal(t, exitUnchecked, code, "a receipt file is a source")
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "receipt"))
		assert.Equal(t, "source_corrupt", checkOf(t, rep, "receipt")["reason"])
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
		assert.Equal(t, "blocked", checkOf(t, rep, "execution")["reason"])
	})
}

// With one node that serves no proof, the result is its word alone, and the
// verdict says so rather than passing it.
func TestASingleNodeWithoutProofsIsInconclusive(t *testing.T) {
	w := newBankWorld(t, nil)
	code, out := exec(t, w.args())
	require.Equal(t, exitUnchecked, code, out)
	rep := decodeReport(t, out)
	assert.Equal(t, "unchecked", rep["verdict"])
	c := checkOf(t, rep, "execution")
	assert.Equal(t, "result_unproven", c["reason"])
	assert.Equal(t, []any{"127.0.0.1"}, c["sources"])
	assert.Equal(t, "a tx source that serves inclusion proofs and a source that serves block_results", c["advice"])
	ex := rep["execution"].(map[string]any)
	assert.Equal(t, "node-attested", ex["inclusion"])
	assert.Equal(t, "node-attested", ex["result"])

	code, out = exec(t, w.textArgs())
	assert.Equal(t, exitUnchecked, code)
	assert.Contains(t, out, "reason: result_unproven")
	assert.Contains(t, out, "source: 127.0.0.1")
	assert.Contains(t, out, "advice: a tx source that serves inclusion proofs and a source that serves block_results")
	assert.Contains(t, out, "execution height: node-attested")
	assert.NotContains(t, out, "verdict: valid")
}

// Independent sources that agree are reported but never prove the result, and
// one source that contradicts them only holds the verdict back.
func TestCrossTxSourcesAreReportedNeverProof(t *testing.T) {
	t.Run("an agreeing cross source", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx})
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		require.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "result_unproven", checkOf(t, rep, "execution")["reason"])
		ex := rep["execution"].(map[string]any)
		assert.Equal(t, "pass", ex["cross_check"])
		assert.Equal(t, "cross-confirmed", ex["result"])
		assert.Equal(t, "node-attested", ex["inclusion"])
		assert.Equal(t, "pass", trustOf(t, rep)["cross_check"])
	})
	t.Run("a cross source that disagrees leaves it unchecked, never invalid", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx, Code: 11})
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
		c := checkOf(t, rep, "execution")
		assert.Equal(t, "cross_disagree", c["reason"])
		assert.ElementsMatch(t, []any{"127.0.0.1", "localhost"}, c["sources"])
		assert.Equal(t, "pass", statusOf(t, rep, "header_trust"), "the headers agree; the transaction does not")
	})
	t.Run("a cross source that cannot contradict a proven result", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: []cometfake.Result{{Code: 0}}})
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx, Code: 11})
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		require.Equal(t, exitValid, code, out)
		ex := decodeReport(t, out)["execution"].(map[string]any)
		assert.Equal(t, "mismatch", ex["cross_check"])
		assert.Equal(t, "proven", ex["result"])
	})
	t.Run("a cross source without the transaction", func(t *testing.T) {
		w := newBankWorld(t, nil)
		cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
		code, out := exec(t, w.args("--cross-check", cross.HostURL("localhost")))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unavailable", rep["execution"].(map[string]any)["cross_check"])
		assert.Equal(t, "result_unproven", checkOf(t, rep, "execution")["reason"])
	})
}

// A cross-check source that serves another header at the transaction height
// contradicts the trusted chain. The verifier cannot tell which side is
// honest, so the result is inconclusive and says so prominently.
func TestHeaderDisagreementAtTheTransactionHeight(t *testing.T) {
	w := newProvenWorld(t, provenOpts{results: []cometfake.Result{{Code: 0}}})
	liar := w.s.rpc(t, w.s.forkAt(execHeight), nodeID(2))
	cross := []string{"--cross-check", liar.HostURL("localhost")}

	code, out := exec(t, w.args(cross...))
	assert.Equal(t, exitUnchecked, code, out)
	rep := decodeReport(t, out)
	assert.Equal(t, "unchecked", rep["verdict"])
	assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
	assert.Equal(t, "unchecked", statusOf(t, rep, "header_trust"), "the pass at the anchor does not stand against a contradiction")
	for _, n := range []string{"execution", "header_trust"} {
		c := checkOf(t, rep, n)
		assert.Equal(t, "header_disagreement", c["reason"], n)
		assert.Equal(t, "check the trusted header against an independent source", c["advice"], n)
	}
	assert.Equal(t, "mismatch", trustOf(t, rep)["cross_check"])

	code, out = exec(t, w.textArgs(cross...))
	assert.Equal(t, exitUnchecked, code)
	assert.Contains(t, out, "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork")
	assert.Contains(t, out, "!!!", "the line stands out")
	assert.Contains(t, out, "reason: header_disagreement")
	assert.NotContains(t, out, "verdict: valid")
	assert.NotContains(t, out, "verdict: invalid")
}

// The same disagreement at the anchor, through a header cross-check.
func TestHeaderDisagreementAtTheAnchor(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	liar := s.rpc(t, s.forkFrom(anchorHeight-2), nodeID(3))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL,
		"--checkpoint", s.explicitCheckpoint(), "--cross-check", liar.HostURL("localhost")))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.Contains(t, out, "reason: header_disagreement")
	assert.Contains(t, out, "source: localhost")
	assert.Contains(t, out, "possible bad trusted header, hostile source, or fork")
	assert.NotContains(t, out, "[FAIL]")
}

func s2dead(t *testing.T, w *bankWorld) string {
	t.Helper()
	dead := w.s.rpc(t, w.s.cometChain(), nodeID(5))
	dead.Close()
	return dead.URL
}
