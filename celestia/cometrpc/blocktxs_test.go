package cometrpc_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/railverify"
)

var _ railverify.BlockSource = (*cometrpc.Source)(nil)

func blockBody(height, txs string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":-1,"result":{"block_id":{},"block":{"header":{"height":"` + height + `"},"data":{"txs":` + txs + `}}}}`)
}

func TestBlockTxs(t *testing.T) {
	srv := serveFiles(t, map[string]answer{"/block": {body: blockBody("7", `["AQID","BAU="]`)}})
	got, err := source(t, srv.URL).BlockTxs(bg, 7)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{1, 2, 3}, {4, 5}}, got, "in block order")
	assert.Equal(t, []string{"/block?height=7"}, srv.requests())
}

func TestBlockTxsOfAnEmptyBlock(t *testing.T) {
	srv := serveFiles(t, map[string]answer{"/block": {body: blockBody("7", `null`)}})
	got, err := source(t, srv.URL).BlockTxs(bg, 7)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestBlockTxsRefusesWhatIsNotAnAnswer(t *testing.T) {
	for name, body := range map[string][]byte{
		"another height":          blockBody("8", `["AQID"]`),
		"a leading zero":          blockBody("07", `["AQID"]`),
		"not base64":              blockBody("7", `["***"]`),
		"an empty tx":             blockBody("7", `[""]`),
		"txs that are not a list": blockBody("7", `{}`),
		"no block":                []byte(`{"jsonrpc":"2.0","id":-1,"result":{}}`),
		"no data":                 []byte(`{"jsonrpc":"2.0","id":-1,"result":{"block":{"header":{"height":"7"}}}}`),
		"not JSON":                []byte(`<html>`),
	} {
		t.Run(name, func(t *testing.T) {
			srv := serveFiles(t, map[string]answer{"/block": {body: body}})
			got, err := source(t, srv.URL).BlockTxs(bg, 7)
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestBlockTxsHTTPFaults(t *testing.T) {
	srv := serveFiles(t, map[string]answer{"/block": {code: http.StatusBadGateway, body: []byte("no")}})
	_, err := source(t, srv.URL).BlockTxs(bg, 7)
	require.ErrorIs(t, err, cometrpc.ErrUnavailable)
}

func TestBlockTxsRPCError(t *testing.T) {
	srv := serveFiles(t, map[string]answer{"/block": {body: []byte(`{"jsonrpc":"2.0","id":-1,"error":{"code":-32603,"message":"Internal error","data":"height 7 must be less than or equal to the current blockchain height 5"}}`)}})
	_, err := source(t, srv.URL).BlockTxs(bg, 7)
	require.ErrorIs(t, err, cometrpc.ErrUnavailable)
}
