package edictad_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
)

// prunedChain has moved far past every capture and no longer serves block
// results.
type prunedChain struct{}

func (prunedChain) Latest(context.Context) (uint64, error) { return 5000, nil }
func (prunedChain) Tx(context.Context, [32]byte, bool) (railverify.RawTx, error) {
	return railverify.RawTx{}, railverify.ErrTxNotFound
}
func (prunedChain) BlockTxs(context.Context, uint64) ([][]byte, error) {
	return nil, errors.New("pruned")
}
func (prunedChain) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	return nil, errors.New("pruned")
}
func (prunedChain) Header(context.Context, uint64) ([]byte, error) { return nil, errors.New("pruned") }

// A capture still missing past half the prune window degrades /v1/health
// and is logged at error level, as a skipped anchor intent is.
func TestStartWithCaptureAlertsOnAnOverdueCapture(t *testing.T) {
	p := newPolicyEnv(t)
	st, err := execcapture.OpenDir(p.path("capture"))
	require.NoError(t, err)
	ref := strings.Repeat("ef", 32)
	require.NoError(t, st.PutPending(bg, execcapture.Pending{RailRef: ref, ExecHeight: 100, SeenHead: 100}))
	p.deps.CaptureChain = prunedChain{}
	p.start(p.edits(rep("[http]", "[capture]\nenabled = true\ndir = \""+p.path("capture")+
		"\"\ncomet_rpc = \"http://127.0.0.1:1\"\nnode_prune_window_blocks = 1000\n\n[http]"))...)

	require.Eventually(t, func() bool {
		h, err := p.client("").Health(bg)
		return err == nil && h.Status == 2
	}, 20*time.Second, 20*time.Millisecond, "health is degraded while a capture is overdue")
	assert.NotEmpty(t, p.logLines("level=ERROR", "still missing past half the node prune window", ref))
}

func TestCaptureConfig(t *testing.T) {
	e := newEnv(t)
	bank := rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`, `action_types = ["`+bankaction.ActionType+`"]`)
	table := func(body string) [2]string { return rep("[http]", "[capture]\n"+body+"\n\n[http]") }
	ok := `enabled = true
dir = "` + e.path("capture") + `"
comet_rpc = "http://127.0.0.1:26657"
node_prune_window_blocks = 1000`

	t.Run("valid, retry default", func(t *testing.T) {
		c, err := edictad.ParseConfig([]byte(e.tomlOf(bank, table(ok))))
		require.NoError(t, err)
		assert.EqualValues(t, 1000, c.Capture.NodePruneWindowBlocks)
		assert.EqualValues(t, 30, c.Capture.RetryEveryS)
	})
	t.Run("absent table", func(t *testing.T) {
		c, err := edictad.ParseConfig([]byte(e.tomlOf()))
		require.NoError(t, err)
		assert.False(t, c.Capture.Enabled)
	})
	for name, tc := range map[string]struct {
		edits []([2]string)
		want  string
	}{
		"prune window below the minimum": {[][2]string{bank, table(ok + "\n"), rep("node_prune_window_blocks = 1000", "node_prune_window_blocks = 99")}, "capture.node_prune_window_blocks"},
		"prune window missing":           {[][2]string{bank, table(ok), rep("node_prune_window_blocks = 1000", "")}, "capture.node_prune_window_blocks"},
		"prune window too large":         {[][2]string{bank, table(ok), rep("node_prune_window_blocks = 1000", "node_prune_window_blocks = 6000001")}, "capture.node_prune_window_blocks"},
		"no dir":                         {[][2]string{bank, table(ok), rep(`dir = "`+e.path("capture")+`"`, "")}, "capture.dir"},
		"inside the archive":             {[][2]string{bank, table(ok), rep(`dir = "`+e.path("capture")+`"`, `dir = "`+e.path("archive")+`/cap"`)}, "capture.dir"},
		"comet_rpc not a URL":            {[][2]string{bank, table(ok), rep(`comet_rpc = "http://127.0.0.1:26657"`, `comet_rpc = "127.0.0.1:26657"`)}, "capture.comet_rpc"},
		"retry out of range":             {[][2]string{bank, table(ok + "\nretry_every_s = 3601")}, "capture.retry_every_s"},
		"no captured action type":        {[][2]string{table(ok)}, "capture.enabled needs"},
		"keys without enabled":           {[][2]string{bank, table("node_prune_window_blocks = 1000")}, "need capture.enabled"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := edictad.ParseConfig([]byte(e.tomlOf(tc.edits...)))
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
