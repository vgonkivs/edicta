package edictad_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
)

const fibreChainID = "mocha-5"

// fibreEdits turns the default blob config into a valid da = fibre one: no
// app version range, the allowlist, a small read limit and no Recorder.
func fibreEdits(extra ...[2]string) [][2]string {
	return append([][2]string{
		rep(`da = "celestia_blob"`, "da = \"fibre\"\nfibre_chain_ids = [\""+fibreChainID+"\"]"),
		rep("min_app_version = 3\nmax_app_version = 10\n", ""),
		rep("enabled = true", "enabled = false"),
		rep("[archive]\n", "[fibre]\nmax_data_bytes = 1048576\nmax_read_bytes = 1048576\n\n[archive]\n"),
	}, extra...)
}

func fibreHeader(h uint64, t time.Time) node.Header {
	return node.Header{ChainID: fibreChainID, Height: h, Time: t, AppVersion: node.FibreAppVersion,
		DataRoot: bytes.Repeat([]byte{byte(h)}, 32)}
}

// fibreFakes are the da = 1 dependencies of one test.
type fibreFakes struct {
	chain *nodefake.FibreChain
	dl    *nodefake.Downloader
	deps  *edictad.FibreDeps
}

// newFibreEnv is an env whose chain is mocha-5 at app version 10 with
// x/fibre present, a consensus head, and every build pin check passing.
func newFibreEnv(t *testing.T) (*env, *fibreFakes) {
	t.Helper()
	e := newEnv(t)
	e.chain = nodefake.NewChain(recAddr)
	e.chain.AddHeader(fibreHeader(90, t0))
	e.chain.AddHeader(fibreHeader(100, t0))
	e.cons = nodefake.NewConsensus(fibreChainID)
	e.cons.Fibre = &node.FibreParams{RetentionS: 3600}
	e.cons.SetHeight(100)
	e.deps.Reader, e.deps.Consensus = e.chain, e.cons
	e.deps.WrapGate = nil
	fc := nodefake.NewFibreChain()
	ff := &fibreFakes{chain: fc, dl: nodefake.NewDownloader()}
	ff.deps = &edictad.FibreDeps{
		Chain: fc, Bridge: fc, Direct: ff.dl,
		SelfTest:   func() error { return nil },
		CheckBuild: func() error { return nil },
		CheckNMT:   func() error { return nil },
	}
	e.deps.Fibre = ff.deps
	return e, ff
}

// bridgeWithLimits is a FibreBridgeReader that reports its configured limits.
type bridgeWithLimits struct {
	*nodefake.FibreChain
	lim node.BridgeLimits
}

func (b bridgeWithLimits) Limits() node.BridgeLimits { return b.lim }

var errSeam = errors.New("seam failure")

// logLines are the captured log lines that contain every part.
func (e *env) logLines(parts ...string) []string {
	var out []string
next:
	for _, l := range strings.Split(e.logs.String(), "\n") {
		for _, p := range parts {
			if !strings.Contains(l, p) {
				continue next
			}
		}
		out = append(out, l)
	}
	return out
}

// retarget moves the fake chain and the consensus fake to another chain id.
func retarget(e *env, id string) {
	e.chain = nodefake.NewChain(recAddr)
	for _, h := range []uint64{90, 100} {
		hd := fibreHeader(h, t0)
		hd.ChainID = id
		e.chain.AddHeader(hd)
	}
	e.cons.ChainID = id
	e.cons.Providers = []string{id}
	e.deps.Reader = e.chain
}
