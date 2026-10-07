package verifycli

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/cometfake"
)

// A header source that tells /header another story than /blockchain can make
// the execution check unchecked, never failed and never passed.
func TestHostileHeaderAtTheTransactionHeightIsUnchecked(t *testing.T) {
	forged := map[string]func(*core.Header){
		"another chain id":  func(h *core.Header) { h.ChainID = "evil-1" },
		"another data hash": func(h *core.Header) { h.DataHash = filler("evil-data", execHeight) },
	}
	for name, mod := range forged {
		t.Run(name, func(t *testing.T) {
			w := newBankWorld(t, nil)
			hd := w.s.chain.hdrs[execHeight]
			mod(&hd)
			w.headers.SingleHeader = map[uint64]core.Header{execHeight: hd}

			code, out := exec(t, w.args())
			assert.Equal(t, exitUnchecked, code, out)
			rep := decodeReport(t, out)
			assert.Equal(t, "unchecked", statusOf(t, rep, "execution"))
			assert.Equal(t, "header_not_linking", checkOf(t, rep, "execution")["reason"])
			assert.Equal(t, "pass", statusOf(t, rep, "header_trust"))
			assert.NotEqual(t, "invalid", rep["verdict"])
			assert.NotEqual(t, "valid", rep["verdict"])
		})
	}
}

func TestExplicitCheckpoint(t *testing.T) {
	t.Run("a hash that is not 32 bytes is a usage error", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		rpc := s.rpc(t, s.cometChain(), nodeID(1))
		for _, cp := range []string{"5:ab", "5:" + strings.Repeat("ab", 33)} {
			code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", rpc.URL, "--checkpoint", cp))
			assert.Equal(t, exitUsage, code, cp)
			assert.NotContains(t, out, "verdict")
		}
	})
	t.Run("a headers source that does not serve it leaves the decision unchecked", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		liar := s.rpc(t, s.forkFrom(checkpointH), nodeID(1))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", liar.URL, "--checkpoint", s.explicitCheckpoint(), "--json"))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "header_trust"))
		assert.NotEqual(t, "invalid", rep["verdict"])
	})
}

func TestReportSaysWhoTheVerdictRestsOn(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, nil)
	headers := s.rpc(t, s.cometChain(), nodeID(1))
	ckpt := s.rpc(t, s.cometChain(), nodeID(2))
	args := s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint-rpc", ckpt.HostURL("localhost"))

	code, out := exec(t, append(args, "--json"))
	require.Equal(t, exitValid, code, out)
	rep := decodeReport(t, out)
	model, _ := rep["trust_model"].(string)
	assert.Contains(t, model, "no validator signatures are checked")
	assert.Contains(t, model, "localhost")
	assert.Contains(t, model, "127.0.0.1", "the headers operator is named")
	ht := trustOf(t, rep)
	assert.Equal(t, "127.0.0.1", ht["headers_source"])
	sources, ok := ht["header_sources"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "archive", sources[strconv.FormatUint(anchorHeight, 10)], "the anchor header came from the archive")

	code, out = exec(t, args)
	require.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "trust model: ")
	assert.Contains(t, out, "needed headers: ")
}

// Under the interim rule a node-attested pass is only possible with agreeing
// cross sources, and the report still says the height is the source's word.
func TestNodeAttestedHeightIsMarked(t *testing.T) {
	w := newBankWorld(t, nil)
	cross := w.s.rpc(t, w.s.cometChain(), nodeID(2))
	cross.PutTx(cometfake.Tx{Height: execHeight, Bytes: w.tx})
	code, out := exec(t, w.textArgs("--cross-check", cross.HostURL("localhost")))
	require.Equal(t, exitValid, code, out)
	assert.Contains(t, out, "execution height: node-attested")
	assert.Contains(t, out, "no inclusion proof")
}

func TestCrossCheckSources(t *testing.T) {
	t.Run("on the headers host is refused", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		same := s.rpc(t, s.cometChain(), nodeID(2))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint(), "--cross-check", same.URL))
		assert.Equal(t, exitUsage, code, out)
		assert.Contains(t, out, "--headers-rpc")
	})
	t.Run("one node under two host names counts once", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		alias := s.rpc(t, s.cometChain(), nodeID(1))
		code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint(),
			"--cross-check", alias.HostURL("localhost"), "--json"))
		require.Equal(t, exitValid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "off", trustOf(t, rep)["cross_check"], "no independent source was left")
		assert.Contains(t, strings.Join(warningsOf(rep), "\n"), "same node")
	})
	t.Run("an excluded host is refused", func(t *testing.T) {
		s := newScenario(t, scenarioOpts{realHeader: true})
		au := s.serveArchive(t, nil)
		headers := s.rpc(t, s.cometChain(), nodeID(1))
		cross := s.rpc(t, s.cometChain(), nodeID(2))
		args := s.onlineArgs("verify", au, "--headers-rpc", headers.URL, "--checkpoint", s.explicitCheckpoint(),
			"--cross-check", cross.HostURL("localhost"))
		code, out := exec(t, append(args, "--exclude-host", "LOCALHOST"))
		assert.Equal(t, exitUsage, code, out)
		assert.Contains(t, out, "excluded")
		code, out = exec(t, append(args, "--exclude-host", "gate.example"))
		assert.Equal(t, exitValid, code, out)
	})
}

func warningsOf(rep map[string]any) []string {
	var out []string
	ws, _ := rep["warnings"].([]any)
	for _, w := range ws {
		out = append(out, w.(string))
	}
	return out
}

func TestUselessFlagCombinationsAreUsageErrors(t *testing.T) {
	w := newBankWorld(t, nil)
	other := w.s.rpc(t, w.s.cometChain(), nodeID(2))
	base := func(extra ...string) []string {
		return append(w.s.onlineArgs("verify", w.au), extra...)
	}
	cp := w.s.explicitCheckpoint()
	cases := map[string][]string{
		"cross-check with nothing to cross-check": base("--cross-check", other.HostURL("localhost")),
		"quorum with an explicit checkpoint":      base("--headers-rpc", w.headers.URL, "--checkpoint", cp, "--checkpoint-quorum", "1"),
		"quorum with nothing":                     base("--checkpoint-quorum", "2"),
		"check-execution without a tx source":     base("--headers-rpc", w.headers.URL, "--checkpoint", cp, "--receipt", w.receipt, "--check-execution"),
		"check-execution without a receipt":       base("--headers-rpc", w.headers.URL, "--checkpoint", cp, "--tx-rpc", w.headers.URL, "--check-execution"),
		"headers-rpc with nothing to read":        base("--headers-rpc", w.headers.URL),
		"zero timeout":                            base("--timeout", "0s"),
	}
	for name, args := range cases {
		code, out := exec(t, args)
		assert.Equal(t, exitUsage, code, "%s: %s", name, out)
		assert.NotContains(t, out, "verdict", name)
	}
}

// The trust layer takes the evidence the verifier read; it never asks the
// archive for it again, where a different answer could be given.
func TestEvidenceIsReadOnce(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	var evidence atomic.Int32
	au := s.serveArchive(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/evidence/") {
				evidence.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	rpc := s.rpc(t, s.cometChain(), nodeID(1))
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", rpc.URL, "--checkpoint", s.explicitCheckpoint()))
	require.Equal(t, exitValid, code, out)
	assert.EqualValues(t, 1, evidence.Load())
}

func TestTimeoutStopsTheRun(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	au := s.serveArchive(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	rpc := s.rpc(t, s.cometChain(), nodeID(1))
	start := time.Now()
	code, out := exec(t, s.onlineArgs("verify", au, "--headers-rpc", rpc.URL, "--checkpoint", s.explicitCheckpoint(), "--timeout", "200ms"))
	assert.Equal(t, exitUsage, code, out)
	assert.NotContains(t, out, "verdict")
	assert.Less(t, time.Since(start), 2*time.Second)
}
