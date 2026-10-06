package nodefake_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

func nodeAt(t *testing.T) (*nodefake.FibreNode, *fibrefix.Live) {
	t.Helper()
	l := fibrefix.LoadLive(t)
	timeAt := func(h uint64) time.Time { return t0.Add(time.Duration(h) * time.Second) }
	return nodefake.NewFibreNode("host:1", timeAt, fibrefix.BuildBlock(t)), l
}

func TestFibreNodeServesEmptyBlocksUpToTheHead(t *testing.T) {
	ctx := context.Background()
	n, _ := nodeAt(t)
	n.SetHead(10)
	assert.Equal(t, "host:1", n.Addr())

	h, err := n.LatestHeight(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 10, h)

	hd, err := n.Header(ctx, 7)
	require.NoError(t, err)
	assert.EqualValues(t, 7, hd.Height)
	assert.True(t, t0.Add(7*time.Second).Equal(hd.Time))
	assert.EqualValues(t, node.FibreAppVersion, hd.AppVersion)
	_, err = n.DAH(ctx, 7)
	require.NoError(t, err)
	_, err = n.NamespaceData(ctx, 7, libshare.PayForFibreNamespace)
	require.NoError(t, err)

	_, err = n.Header(ctx, 11)
	require.ErrorIs(t, err, node.ErrNotFound, "no block above the head")
	_, err = n.Header(ctx, 0)
	require.ErrorIs(t, err, node.ErrNotFound)

	n.SetHead(5)
	_, err = n.Header(ctx, 7)
	require.ErrorIs(t, err, node.ErrNotFound, "a node can lag")

	n.SetHead(10)
	n.Prune(8)
	_, err = n.Header(ctx, 7)
	require.ErrorIs(t, err, node.ErrNotFound, "pruned")
	_, err = n.Header(ctx, 8)
	require.NoError(t, err)
}

func TestFibreNodeLandInstallsTheBlockTheCodeAndThePlacement(t *testing.T) {
	ctx := context.Background()
	n, l := nodeAt(t)
	n.SetHead(3)
	land := l.Header
	hash := sha256.Sum256(l.PFFTx)
	n.Land(nodefake.LandedPFF{Header: land, Block: fibrefix.VectorBlock(t, l.Case), Tx: l.PFFTx, Code: 5, Index: 2})

	head, err := n.LatestHeight(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, l.Height, head, "the head moves up to the landing height")
	hd, err := n.Header(ctx, l.Height)
	require.NoError(t, err)
	assert.Equal(t, land.DataHash, hd.DataHash)
	code, err := n.TxCode(ctx, l.Height, hash)
	require.NoError(t, err)
	assert.EqualValues(t, 5, code)
	p, err := n.TxPlace(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, node.TxPlacement{Height: l.Height, Index: 2, Code: 5, Status: "COMMITTED"}, p)
	raw, err := n.SignedHeader(ctx, l.Height)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	_, err = n.TxPlace(ctx, [32]byte{9})
	require.ErrorIs(t, err, node.ErrNotFound)
	_, err = n.ValidatorSet(ctx, 4)
	require.ErrorIs(t, err, node.ErrNotFound)
	n.SetValidatorSet(4, []byte("set"))
	vs, err := n.ValidatorSet(ctx, 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("set"), vs)

	fp, err := n.FibreParams(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1000, fp.PromiseHeightWindow)
	n.SetFibreParams(node.FibreParams{RetentionS: 1, PromiseHeightWindow: 7})
	fp, err = n.FibreParams(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 7, fp.PromiseHeightWindow)
}

func TestFibreNodeFailures(t *testing.T) {
	ctx := context.Background()
	n, _ := nodeAt(t)
	n.SetHead(3)
	n.FailLatest = nodefake.ErrInjected
	_, err := n.LatestHeight(ctx)
	require.ErrorIs(t, err, nodefake.ErrInjected)
	_, err = n.Header(ctx, 1)
	require.NoError(t, err, "FailLatest touches only the head read")
	n.FailLatest = nil
	n.FailBridge = nodefake.ErrInjected
	_, err = n.DAH(ctx, 1)
	require.ErrorIs(t, err, nodefake.ErrInjected)
	n.FailBridge = nil
	n.Fail = nodefake.ErrInjected
	_, err = n.Header(ctx, 1)
	require.ErrorIs(t, err, nodefake.ErrInjected)
	_, err = n.TxPlace(ctx, [32]byte{})
	require.ErrorIs(t, err, nodefake.ErrInjected)
}

func TestFibreSubmitterFollowsItsPlan(t *testing.T) {
	ctx := context.Background()
	n, l := nodeAt(t)
	n.SetHead(3)
	block := make(chan struct{})
	boom := errors.New("boom")
	s := &nodefake.FibreSubmitter{
		Addr: []byte{1}, EscrowVal: node.Escrow{AvailableUtia: 9}, Endpt: "host:1", Chain: n,
		Plan: func(call int, ns, data []byte) nodefake.SubmitPlan {
			switch call {
			case 1:
				return nodefake.SubmitPlan{
					Land:   &nodefake.LandedPFF{Header: l.Header, Block: fibrefix.VectorBlock(t, l.Case), Tx: l.PFFTx},
					Result: node.FibreResult{Height: l.Height, Namespace: ns},
				}
			case 2:
				return nodefake.SubmitPlan{Err: boom}
			}
			return nodefake.SubmitPlan{Block: block}
		},
	}
	assert.Equal(t, "host:1", s.Endpoint())
	a, err := s.Address(ctx)
	require.NoError(t, err)
	assert.Equal(t, []byte{1}, a)
	e, err := s.Escrow(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 9, e.AvailableUtia)
	assert.Equal(t, 1, s.EscrowReads())

	res, err := s.SubmitFibre(ctx, []byte("ns"), []byte("data"))
	require.NoError(t, err)
	assert.Equal(t, l.Height, res.Height)
	head, _ := n.LatestHeight(ctx)
	assert.Equal(t, l.Height, head, "the plan landed the PFF")

	_, err = s.SubmitFibre(ctx, nil, nil)
	require.ErrorIs(t, err, boom)

	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := s.SubmitFibre(cctx, nil, nil); done <- err }()
	cancel()
	require.ErrorIs(t, <-done, node.ErrUnavailable, "a blocked call ends with its context")

	assert.Equal(t, 3, s.Calls())
	assert.NoError(t, s.UploadCtx(1).Err())
	assert.Error(t, s.UploadCtx(3).Err())
}
