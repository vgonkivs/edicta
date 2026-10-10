package edictad_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
)

// prunedChain is at head and no longer serves block results.
type prunedChain struct {
	head uint64
	id   string
}

func (c prunedChain) Latest(context.Context) (uint64, error) { return c.head, nil }
func (prunedChain) Tx(context.Context, [32]byte, bool) (railverify.RawTx, error) {
	return railverify.RawTx{}, railverify.ErrTxNotFound
}
func (prunedChain) BlockTxs(context.Context, uint64) ([][]byte, error) {
	return nil, errors.New("pruned")
}
func (prunedChain) BlockResults(context.Context, uint64) ([]railverify.TxResult, error) {
	return nil, errors.New("pruned")
}
func (c prunedChain) Header(_ context.Context, h uint64) ([]byte, error) {
	if h != c.head {
		return nil, errors.New("pruned")
	}
	ph := cmtproto.Header{ChainID: c.chainID(), Height: int64(h)}
	return ph.Marshal()
}

func (c prunedChain) chainID() string {
	if c.id != "" {
		return c.id
	}
	return "testchain-7"
}

// A capture still missing past half the prune window degrades /v1/health
// and is logged at error level, as a skipped anchor intent is.
func TestStartWithCaptureAlertsOnAnOverdueCapture(t *testing.T) {
	p := newPolicyEnv(t)
	st, err := execcapture.OpenDir(p.path("capture"))
	require.NoError(t, err)
	ref := strings.Repeat("ef", 32)
	require.NoError(t, st.PutPending(bg, execcapture.Pending{RailRef: ref, ExecHeight: 100, SeenHead: 100}))
	p.deps.CaptureChain = prunedChain{head: 700}
	p.start(p.edits(rep("[http]", "[capture]\nenabled = true\ndir = \""+p.path("capture")+
		"\"\ncomet_rpc = \"http://127.0.0.1:1\"\nnode_prune_window_blocks = 1000\n\n[http]"))...)

	require.Eventually(t, func() bool {
		h, err := p.client("").Health(bg)
		return err == nil && h.Status == 2
	}, 20*time.Second, 20*time.Millisecond, "health is degraded while a capture is overdue")
	assert.NotEmpty(t, p.logLines("level=ERROR", "still missing past half the node prune window", ref))
}

// Past the whole prune window the capture is lost: logged at error level
// once, and health no longer degraded by it.
func TestStartWithCaptureLostCaptureClearsTheAlert(t *testing.T) {
	p := newPolicyEnv(t)
	st, err := execcapture.OpenDir(p.path("capture"))
	require.NoError(t, err)
	ref := strings.Repeat("ef", 32)
	require.NoError(t, st.PutPending(bg, execcapture.Pending{RailRef: ref, ExecHeight: 100, SeenHead: 100}))
	p.deps.CaptureChain = prunedChain{head: 5000}
	p.start(p.edits(rep("[http]", "[capture]\nenabled = true\ndir = \""+p.path("capture")+
		"\"\ncomet_rpc = \"http://127.0.0.1:1\"\nnode_prune_window_blocks = 1000\n\n[http]"))...)

	require.Eventually(t, func() bool {
		lost, err := st.Lost(bg, ref)
		return err == nil && lost
	}, 20*time.Second, 20*time.Millisecond)
	h, err := p.client("").Health(bg)
	require.NoError(t, err)
	assert.EqualValues(t, 1, h.Status)
	assert.Len(t, p.logLines("level=ERROR", "capture is lost", ref), 1)
}

// A comet_rpc node of another chain would mix networks in the capture
// store: edictad refuses to start.
func TestStartWithCaptureRefusesANodeOfAnotherChain(t *testing.T) {
	p := newPolicyEnv(t)
	p.deps.CaptureChain = prunedChain{head: 700, id: "otherchain-1"}
	srv, err := edictad.Start(bg, p.cfg(p.edits(rep("[http]", "[capture]\nenabled = true\ndir = \""+p.path("capture")+
		"\"\ncomet_rpc = \"http://127.0.0.1:1\"\nnode_prune_window_blocks = 1000\n\n[http]"))...), p.deps)
	if srv != nil {
		t.Cleanup(func() { _ = srv.Shutdown(bg) })
	}
	require.ErrorIs(t, err, execcapture.ErrWrongChain)
	assert.Contains(t, err.Error(), "capture.comet_rpc")
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
