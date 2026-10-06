// Package fibreworld is a da = 1 Recorder over fakes around the live Mocha
// PayForFibre: one node, one submitter that lands that PFF at its live height,
// one archive. It is for tests of other packages only.
package fibreworld

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

const (
	// ChainID is the chain of the live vector.
	ChainID  = "mocha-5"
	Endpoint = "consensus.example:9090"
	// Window is the PaymentPromiseHeightWindow of the fake chain.
	Window = 300
)

// World holds the pieces. Publish the live payload (Live.Payload) through Rec.
type World struct {
	Live *fibrefix.Live
	Node *nodefake.FibreNode
	Sub  *nodefake.FibreSubmitter
	Dir  string
	St   archive.Store
	Rec  *recorder.FibreRecorder
	// Now is the Recorder's clock: the time of the head before the submit.
	Now time.Time
}

// TimeAt dates block h so that the live block keeps its real time.
func TimeAt(l *fibrefix.Live, h uint64) time.Time {
	return l.Header.Time.Add(time.Duration(int64(h)-int64(l.Height)) * 6 * time.Second)
}

// New builds the world. The head starts four blocks before the live PFF, and
// the first submit lands the live block.
func New(t testing.TB) *World {
	t.Helper()
	l := fibrefix.LoadLive(t)
	start := l.Height - 4
	timeAt := func(h uint64) time.Time { return TimeAt(l, h) }
	nd := nodefake.NewFibreNode(Endpoint, timeAt, fibrefix.BuildBlock(t))
	nd.SetHistoricalInfo(l.PromiseHeight, l.Hist)
	nd.SetSignedHeader(l.PromiseHeight, fibrefix.BoundSignedHeader(t, l.PromiseHeaderProto(t)))
	nd.SetValidatorSet(l.PromiseHeight+1, l.PromiseValsetNext(t))
	nd.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: Window})
	nd.SetHead(start)

	comm, err := fibrecommit.Commitment(l.Payload)
	require.NoError(t, err)
	us, err := fibrecommit.UploadSize(uint64(len(l.Payload)))
	require.NoError(t, err)
	sub := &nodefake.FibreSubmitter{
		Addr: make([]byte, 20), EscrowVal: node.Escrow{AvailableUtia: 10_000_000}, Endpt: Endpoint, Chain: nd,
		Plan: func(_ int, ns, _ []byte) nodefake.SubmitPlan {
			return nodefake.SubmitPlan{
				Land: &nodefake.LandedPFF{Header: l.Header, Block: fibrefix.VectorBlock(t, l.Case), Tx: l.PFFTx, Index: 1},
				Result: node.FibreResult{
					BlobID: fibrecommit.BlobID(comm), Height: l.Height, PromiseHeight: l.PromiseHeight,
					Namespace: ns, Commitment: comm, BlobSize: uint32(us),
				},
			}
		},
	}
	dir := t.TempDir()
	st, err := fsarchive.Open(dir, fibrefix.Committers(t))
	require.NoError(t, err)
	now := timeAt(start)
	c, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	rec, err := recorder.NewFibre(recorder.FibreConfig{
		Namespace: l.Ref.Namespace, MaxDataBytes: 1 << 10, SubmitTimeout: 5 * time.Second, UploadDrain: time.Hour,
		VisibleTimeout: 50 * time.Millisecond, PollInterval: time.Millisecond, OwnNode: true, Archive: st,
		Now: func() time.Time { return now },
	}, recorder.FibreDeps{
		Submitter: sub, Reader: nd, Chain: nd, ChainID: ChainID, Committer: c,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = rec.Close(ctx)
	})
	return &World{Live: l, Node: nd, Sub: sub, Dir: dir, St: st, Rec: rec, Now: now}
}
