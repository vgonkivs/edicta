package cometrpc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
)

var _ railverify.ResultsSource = (*cometrpc.Source)(nil)

const liveResults = "../../spec/vectors/verifier/live/block_results_1442606.json"

func resultsBody(t testing.TB, height string, txs string) []byte {
	t.Helper()
	return []byte(`{"jsonrpc":"2.0","id":-1,"result":{"height":"` + height + `","txs_results":` + txs + `}}`)
}

func TestBlockResultsLive(t *testing.T) {
	raw, err := os.ReadFile(liveResults)
	require.NoError(t, err)
	srv := serveFiles(t, map[string]answer{"/block_results": {body: raw}})
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)

	got, err := s.BlockResults(bg, 1442606)
	require.NoError(t, err)
	require.Len(t, got, 5)
	assert.Equal(t, uint32(0), got[0].Code)
	assert.Equal(t, int64(91137), got[0].GasWanted)
	assert.Equal(t, int64(81531), got[0].GasUsed)
	assert.Equal(t, "\x12&\n$/cosmos.bank.v1beta1.MsgSendResponse", string(got[0].Data))
	assert.Equal(t, []string{"/block_results?height=1442606"}, srv.requests())
}

func TestBlockResultsFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []railverify.TxResult
	}{
		{"no transactions", `null`, []railverify.TxResult{}},
		{"an empty list", `[]`, []railverify.TxResult{}},
		{"absent fields are zero", `[{}]`, []railverify.TxResult{{}}},
		{"null data", `[{"code":0,"data":null,"gas_wanted":"1","gas_used":"2"}]`, []railverify.TxResult{{GasWanted: 1, GasUsed: 2}}},
		{"a failed result", `[{"code":11,"log":"out of gas","gas_wanted":"5","gas_used":"5","codespace":"sdk","events":[]}]`, []railverify.TxResult{{Code: 11, GasWanted: 5, GasUsed: 5}}},
		{"data", `[{"code":0,"data":"AQI="}]`, []railverify.TxResult{{Data: []byte{1, 2}}}},
		{"negative gas", `[{"gas_wanted":"-1"}]`, []railverify.TxResult{{GasWanted: -1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveFiles(t, map[string]answer{"/block_results": {body: resultsBody(t, "7", tc.body)}})
			s, err := cometrpc.New(srv.URL, nil)
			require.NoError(t, err)
			got, err := s.BlockResults(bg, 7)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBlockResultsRefusesWhatIsNotAnAnswer(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"another height", resultsBody(t, "8", `[]`)},
		{"no height", []byte(`{"jsonrpc":"2.0","id":-1,"result":{"txs_results":[]}}`)},
		{"height with a leading zero", resultsBody(t, "07", `[]`)},
		{"results that are not a list", resultsBody(t, "7", `{}`)},
		{"a code above uint32", resultsBody(t, "7", `[{"code":4294967296}]`)},
		{"a negative code", resultsBody(t, "7", `[{"code":-1}]`)},
		{"a code that is not a number", resultsBody(t, "7", `[{"code":"zero"}]`)},
		{"gas as a number", resultsBody(t, "7", `[{"gas_wanted":5}]`)},
		{"gas that is not decimal", resultsBody(t, "7", `[{"gas_used":"0x5"}]`)},
		{"gas above int64", resultsBody(t, "7", `[{"gas_used":"9223372036854775808"}]`)},
		{"data that is not base64", resultsBody(t, "7", `[{"data":"***"}]`)},
		{"not JSON", []byte(`<html>`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveFiles(t, map[string]answer{"/block_results": {body: tc.body}})
			s, err := cometrpc.New(srv.URL, nil)
			require.NoError(t, err)
			got, err := s.BlockResults(bg, 7)
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// Some operators keep no finalize block responses: that is a fault of the
// source, like any other RPC error, and the caller goes on to another one.
func TestBlockResultsOfANodeThatKeepsNoResults(t *testing.T) {
	srv := cometfake.New(t, cometfake.BuildChain("mocha-4", 1, 10), 10, "ab")
	s, err := cometrpc.New(srv.URL, nil)
	require.NoError(t, err)
	got, err := s.BlockResults(bg, 7)
	require.ErrorIs(t, err, cometrpc.ErrUnavailable)
	assert.Contains(t, err.Error(), "not persisting finalize block responses")
	assert.Nil(t, got)

	srv.Results[7] = []cometfake.Result{{Code: 0, Data: []byte("d"), GasWanted: 3, GasUsed: 2}, {Code: 5}}
	got, err = s.BlockResults(bg, 7)
	require.NoError(t, err)
	assert.Equal(t, []railverify.TxResult{{Data: []byte("d"), GasWanted: 3, GasUsed: 2}, {Code: 5}}, got)
}

func TestBlockResultsHTTPFaults(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusForbidden, http.StatusBadGateway} {
		srv := serveFiles(t, map[string]answer{"/block_results": {code: code, body: []byte("no")}})
		s, err := cometrpc.New(srv.URL, nil)
		require.NoError(t, err)
		_, err = s.BlockResults(bg, 7)
		require.ErrorIs(t, err, cometrpc.ErrUnavailable, "status %d", code)
	}
}

func FuzzBlockResultsJSON(f *testing.F) {
	live, err := os.ReadFile(liveResults)
	require.NoError(f, err)
	f.Add(live, uint64(1442606))
	f.Add(resultsBody(f, "7", `[{"code":11,"data":"AQI=","gas_wanted":"5","gas_used":"4"}]`), uint64(7))
	f.Add(resultsBody(f, "7", `null`), uint64(7))
	f.Add([]byte(`{"result":{}}`), uint64(1))
	f.Add([]byte(`[]`), uint64(1))

	var mu sync.Mutex
	var current []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		b := current
		mu.Unlock()
		_, _ = w.Write(b)
	}))
	f.Cleanup(srv.Close)
	s, err := cometrpc.New(srv.URL, srv.Client())
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, body []byte, height uint64) {
		mu.Lock()
		current = body
		mu.Unlock()
		got, err := s.BlockResults(bg, height)
		if err != nil {
			assert.Nil(t, got)
			return
		}
		// An accepted answer names the height that was asked for.
		var env struct {
			Result struct {
				Height string `json:"height"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal(body, &env))
		assert.Equal(t, strconv.FormatUint(height, 10), env.Result.Height)
		assert.NotNil(t, got)
	})
}
