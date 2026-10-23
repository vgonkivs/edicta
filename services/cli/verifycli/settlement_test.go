// SPDX-License-Identifier: Apache-2.0

package verifycli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

const edenVectors = "vectors/profiles/eden-escrow"

func edenJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, edenVectors, name))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, v))
}

// edenF14 is the synthetic form T action with the F14 deposit, and the
// recorded Eden answers about the real (relayed) F14 transaction.
type edenF14 struct {
	action  []byte
	railRef string
	answers map[string]json.RawMessage
}

func loadEdenF14(t testing.TB) edenF14 {
	t.Helper()
	var acts struct {
		Cases []struct {
			ID      string `json:"id"`
			CBORHex string `json:"cbor_hex"`
		} `json:"cases"`
	}
	edenJSON(t, "action.json", &acts)
	var e edenF14
	for _, c := range acts.Cases {
		if c.ID == "tx_f14_714" {
			b, err := hex.DecodeString(c.CBORHex)
			require.NoError(t, err)
			e.action = b
		}
	}
	require.NotNil(t, e.action)
	var f14 struct {
		Deposit struct {
			Hash       string          `json:"hash"`
			RPCTx      json.RawMessage `json:"rpc_tx"`
			RPCReceipt json.RawMessage `json:"rpc_receipt"`
		} `json:"deposit"`
	}
	edenJSON(t, "live/f14.json", &f14)
	var code struct {
		RPCReads []struct {
			URL    string          `json:"url"`
			Method string          `json:"method"`
			Params []string        `json:"params"`
			Result json.RawMessage `json:"result"`
		} `json:"rpc_reads"`
	}
	edenJSON(t, "live/escrow-code.json", &code)
	e.railRef = strings.TrimPrefix(f14.Deposit.Hash, "0x")
	e.answers = map[string]json.RawMessage{
		"eth_chainId":               json.RawMessage(`"0x2ca"`),
		"eth_blockNumber":           json.RawMessage(`"0xd9579f0"`),
		"eth_getTransactionByHash":  f14.Deposit.RPCTx,
		"eth_getTransactionReceipt": f14.Deposit.RPCReceipt,
	}
	for _, r := range code.RPCReads {
		if r.Method == "eth_getCode" && r.URL == "https://rpc.eden.gateway.fm/" && r.Params[0] == "0x65d77c98e73dfbea91ecb72b27c9753e186a94c8" {
			e.answers["eth_getCode"] = r.Result
		}
	}
	require.Contains(t, e.answers, "eth_getCode")
	return e
}

// edenRPC serves recorded answers by method on the loopback.
func edenRPC(t testing.TB, answers map[string]json.RawMessage) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(body, &req) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		res, ok := answers[req.Method]
		if !ok {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}`, req.ID)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, res)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSettlementFlags(t *testing.T) {
	h := strings.Repeat("ab", 32)
	base := []string{"verify", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir()}
	with := func(extra ...string) []string { return append(append([]string(nil), base...), extra...) }
	bad := map[string][]string{
		"source without --settlement": with("--settlement-rpc", "http://a"),
		"level without --settlement":  with("--settlement-level", "L1"),
		"no receipt":                  with("--settlement", "--settlement-rpc", "http://a"),
		"no source":                   with("--settlement", "--receipt", "r"),
		"bad level":                   with("--settlement", "--receipt", "r", "--settlement-rpc", "http://a", "--settlement-level", "L3"),
		"one host twice":              with("--settlement", "--receipt", "r", "--settlement-rpc", "http://a", "--settlement-own-rpc", "https://A:8545"),
		"L1 with one source":          with("--settlement", "--receipt", "r", "--settlement-rpc", "http://a", "--settlement-level", "L1"),
		"bad URL":                     with("--settlement", "--receipt", "r", "--settlement-rpc", "ftp://a"),
		"bad DA URL":                  with("--settlement", "--receipt", "r", "--settlement-rpc", "http://a", "--settlement-da", "a"),
		"replay":                      {"replay", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--settlement", "--settlement-rpc", "http://a"},
	}
	for name, args := range bad {
		_, err := parseFlags(args, &bytes.Buffer{})
		assert.Error(t, err, name)
	}
	f, err := parseFlags(with("--settlement", "--receipt", "r", "--settlement-rpc", "http://a", "--settlement-own-rpc", "http://b",
		"--settlement-level", "L2", "--settlement-min-sources", "2", "--settlement-confirm-depth", "5", "--settlement-da", "http://b:7331"), &bytes.Buffer{})
	require.NoError(t, err)
	assert.True(t, f.settle.on)
	assert.Equal(t, []string{"http://a"}, f.settle.rpc)
	assert.Equal(t, []string{"http://b"}, f.settle.ownRPC)
}

func TestSettlementExcludedHosts(t *testing.T) {
	h := strings.Repeat("ab", 32)
	base := []string{"verify", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--settlement", "--receipt", "r"}
	for name, extra := range map[string][]string{
		"public": {"--settlement-rpc", "https://gate.example/rpc"},
		"own":    {"--settlement-own-rpc", "http://gate.example:8545"},
		"da":     {"--settlement-rpc", "http://a", "--settlement-da", "http://gate.example:7331"},
	} {
		args := append(append([]string(nil), base...), extra...)
		_, err := parseFlags(args, &bytes.Buffer{})
		require.NoError(t, err, name)
		_, err = parseFlags(append(args, "--exclude-host", "GATE.example"), &bytes.Buffer{})
		require.ErrorContains(t, err, "excluded host", name)
	}
}

// TestSettlementReportEndToEnd runs the real client and checker on the
// recorded F14 answers: the claimed transaction is not the authorized form
// T bytes, so the settlement report is violated, while the verdict and the
// exit code stay what the core checks give.
func TestSettlementReportEndToEnd(t *testing.T) {
	e := loadEdenF14(t)
	s := newScenario(t, scenarioOpts{realHeader: true, edenAction: e.action})
	receipt := writeReceipt(t, s.receipt(t, e.railRef))
	srv := edenRPC(t, e.answers)
	trusted := s.chain.trustedFile(t, checkpointH, nil)

	codeWithout, out := exec(t, s.args("verify", "--trusted", trusted, "--receipt", receipt, "--json"))
	var without map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(out), &without), out)
	assert.NotContains(t, without, "rail_settlement")

	code, out := exec(t, s.args("verify", "--trusted", trusted, "--receipt", receipt, "--json",
		"--settlement", "--settlement-rpc", srv.URL))
	assert.Equal(t, codeWithout, code)
	var rep struct {
		Verdict        string `json:"verdict"`
		RailSettlement struct {
			Profile string `json:"profile"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			RailRef string `json:"rail_ref"`
			ChainID uint64 `json:"chain_id"`
			Sources []struct {
				Name   string `json:"name"`
				Class  string `json:"class"`
				Result string `json:"result"`
			} `json:"sources"`
		} `json:"rail_settlement"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	assert.Equal(t, string(without["verdict"]), `"`+rep.Verdict+`"`)
	assert.Equal(t, "valid", rep.Verdict)
	assert.Equal(t, "eden-escrow-v1", rep.RailSettlement.Profile)
	assert.Equal(t, "violated", rep.RailSettlement.Status)
	assert.Equal(t, "wrong_tx", rep.RailSettlement.Reason)
	assert.Equal(t, e.railRef, rep.RailSettlement.RailRef)
	assert.Equal(t, uint64(714), rep.RailSettlement.ChainID)
	require.Len(t, rep.RailSettlement.Sources, 1)
	assert.Equal(t, "127.0.0.1", rep.RailSettlement.Sources[0].Name)
	assert.Equal(t, "public-rpc", rep.RailSettlement.Sources[0].Class)
	assert.Equal(t, "used", rep.RailSettlement.Sources[0].Result)

	code, out = exec(t, s.args("verify", "--trusted", trusted, "--receipt", receipt,
		"--settlement", "--settlement-own-rpc", srv.URL))
	assert.Equal(t, codeWithout, code)
	assert.Contains(t, out, "rail settlement (eden-escrow-v1, does not change the verdict): violated, wrong_tx")
	assert.Contains(t, out, "rail settlement source 127.0.0.1 (own-node): used")
	assert.Contains(t, out, "verdict: valid")
}

func TestSettlementReportNotRun(t *testing.T) {
	s := newScenario(t, scenarioOpts{realHeader: true})
	receipt := writeReceipt(t, s.receipt(t, strings.Repeat("ab", 32)))
	trusted := s.chain.trustedFile(t, checkpointH, nil)
	code, out := exec(t, s.args("verify", "--trusted", trusted, "--receipt", receipt, "--json",
		"--settlement", "--settlement-rpc", "http://127.0.0.1:1"))
	assert.Equal(t, codeValid, code, out)
	var rep struct {
		RailSettlement struct {
			Status    string `json:"status"`
			BlockedOn string `json:"blocked_on"`
		} `json:"rail_settlement"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &rep), out)
	assert.Equal(t, "not_run", rep.RailSettlement.Status)
	assert.Equal(t, "no_checker", rep.RailSettlement.BlockedOn)
}
