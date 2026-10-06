package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// readChain is a consensus node whose block, tx and staking answers are hooks.
type readChain struct {
	block   func(h int64) (*cmtservice.GetBlockByHeightResponse, error)
	getTx   func(hash string) (*txtypes.GetTxResponse, error)
	history func(h int64) (*stakingtypes.QueryHistoricalInfoResponse, error)
}

type readCmt struct {
	cmtservice.UnimplementedServiceServer
	c *readChain
}

func (s *readCmt) GetBlockByHeight(_ context.Context, r *cmtservice.GetBlockByHeightRequest) (*cmtservice.GetBlockByHeightResponse, error) {
	return s.c.block(r.Height)
}

type readTx struct {
	txtypes.UnimplementedServiceServer
	c *readChain
}

func (s *readTx) GetTx(_ context.Context, r *txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
	return s.c.getTx(r.Hash)
}

type readStaking struct {
	stakingtypes.UnimplementedQueryServer
	c *readChain
}

func (s *readStaking) HistoricalInfo(_ context.Context, r *stakingtypes.QueryHistoricalInfoRequest) (*stakingtypes.QueryHistoricalInfoResponse, error) {
	return s.c.history(r.Height)
}

func startReadChain(t *testing.T, c *readChain) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	cmtservice.RegisterServiceServer(srv, &readCmt{c: c})
	txtypes.RegisterServiceServer(srv, &readTx{c: c})
	stakingtypes.RegisterQueryServer(srv, &readStaking{c: c})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	cl := NewConsensusConn(conn)
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func blockAt(h int64, dataHash []byte) *cmtservice.GetBlockByHeightResponse {
	return &cmtservice.GetBlockByHeightResponse{Block: &cmtproto.Block{
		Header: cmtproto.Header{Height: h, DataHash: dataHash, Time: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)},
	}}
}

func TestFibreHeader(t *testing.T) {
	dh := []byte{1, 2, 3}
	cases := []struct {
		name    string
		resp    *cmtservice.GetBlockByHeightResponse
		err     error
		want    error
		flagged bool
	}{
		{name: "the requested height", resp: blockAt(50, dh)},
		{name: "another height", resp: blockAt(51, dh), want: ErrUnavailable, flagged: true},
		{name: "negative height", resp: blockAt(-1, dh), want: ErrUnavailable, flagged: true},
		{name: "no data hash", resp: blockAt(50, nil), want: ErrUnavailable},
		{name: "no block", resp: &cmtservice.GetBlockByHeightResponse{}, want: ErrUnavailable},
		{name: "not found", err: status.Error(codes.NotFound, "no block"), want: ErrNotFound},
		{name: "node down", err: status.Error(codes.Unavailable, "down"), want: ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := startReadChain(t, &readChain{block: func(int64) (*cmtservice.GetBlockByHeightResponse, error) { return tc.resp, tc.err }})
			h, err := c.Header(tctx(t), 50)
			assert.Equal(t, tc.flagged, c.HeightFlag().Ignoring())
			if tc.want == nil {
				require.NoError(t, err)
				assert.EqualValues(t, 50, h.Height)
				assert.Equal(t, dh, h.DataHash)
				assert.False(t, h.Time.IsZero())
				return
			}
			require.ErrorIs(t, err, tc.want)
			if tc.flagged {
				assert.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
			}
		})
	}
	t.Run("height zero is refused before the call", func(t *testing.T) {
		called := false
		c := startReadChain(t, &readChain{block: func(int64) (*cmtservice.GetBlockByHeightResponse, error) {
			called = true
			return blockAt(0, dh), nil
		}})
		_, err := c.Header(tctx(t), 0)
		require.ErrorIs(t, err, ErrUnavailable)
		assert.False(t, called)
	})
}

func TestFibreSignedHeader(t *testing.T) {
	c := startReadChain(t, &readChain{block: func(h int64) (*cmtservice.GetBlockByHeightResponse, error) {
		if h == 60 {
			return blockAt(61, []byte{1}), nil
		}
		return blockAt(h, []byte{1}), nil
	}})
	raw, err := c.SignedHeader(tctx(t), 50)
	require.NoError(t, err)
	var hdr cmtproto.Header
	require.NoError(t, hdr.Unmarshal(raw))
	assert.EqualValues(t, 50, hdr.Height)

	_, err = c.SignedHeader(tctx(t), 60)
	require.ErrorIs(t, err, ErrUnavailable)
	assert.True(t, c.HeightFlag().Ignoring())
}

func TestFibreTxCode(t *testing.T) {
	hash := sha256.Sum256([]byte("tx"))
	upper := strings.ToUpper(hex.EncodeToString(hash[:]))
	resp := func(height int64, h string, code uint32) *txtypes.GetTxResponse {
		return &txtypes.GetTxResponse{TxResponse: &sdk.TxResponse{Height: height, TxHash: h, Code: code}}
	}
	other := sha256.Sum256([]byte("other"))
	cases := []struct {
		name string
		resp *txtypes.GetTxResponse
		err  error
		code uint32
		want error
	}{
		{name: "code zero", resp: resp(50, upper, 0)},
		{name: "code non-zero", resp: resp(50, upper, 11), code: 11},
		{name: "lower-case hash echo", resp: resp(50, strings.ToLower(upper), 0)},
		{name: "another height", resp: resp(51, upper, 0), want: ErrUnavailable},
		{name: "negative height", resp: resp(-1, upper, 0), want: ErrUnavailable},
		{name: "another tx", resp: resp(50, strings.ToUpper(hex.EncodeToString(other[:])), 0), want: ErrUnavailable},
		{name: "no result", resp: &txtypes.GetTxResponse{}, want: ErrNotFound},
		{name: "not found", err: status.Error(codes.NotFound, "no tx"), want: ErrNotFound},
		{name: "node down", err: status.Error(codes.Unavailable, "down"), want: ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			c := startReadChain(t, &readChain{getTx: func(h string) (*txtypes.GetTxResponse, error) {
				asked = h
				return tc.resp, tc.err
			}})
			code, err := c.TxCode(tctx(t), 50, hash)
			assert.False(t, c.HeightFlag().Ignoring(), "a by-hash read never marks the endpoint")
			assert.Equal(t, upper, asked, "queried by the upper-case hex hash")
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				if tc.want == ErrUnavailable {
					assert.NotErrorIs(t, err, ErrNotFound, "a mismatch is never absence")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.code, code)
		})
	}
}

func TestFibreHistoricalInfo(t *testing.T) {
	hist := func(h int64) *stakingtypes.QueryHistoricalInfoResponse {
		return &stakingtypes.QueryHistoricalInfoResponse{Hist: &stakingtypes.HistoricalInfo{Header: cmtproto.Header{Height: h}}}
	}
	cases := []struct {
		name    string
		resp    *stakingtypes.QueryHistoricalInfoResponse
		want    error
		flagged bool
	}{
		{name: "the requested height", resp: hist(40)},
		{name: "another height", resp: hist(41), want: ErrUnavailable, flagged: true},
		{name: "negative height", resp: hist(-3), want: ErrUnavailable, flagged: true},
		{name: "nothing recorded", resp: &stakingtypes.QueryHistoricalInfoResponse{}, want: ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := startReadChain(t, &readChain{history: func(int64) (*stakingtypes.QueryHistoricalInfoResponse, error) { return tc.resp, nil }})
			raw, err := c.HistoricalInfo(tctx(t), 40)
			assert.Equal(t, tc.flagged, c.HeightFlag().Ignoring())
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				return
			}
			require.NoError(t, err)
			var hi stakingtypes.HistoricalInfo
			require.NoError(t, hi.Unmarshal(raw))
			assert.EqualValues(t, 40, hi.Header.Height)
		})
	}
}

type stubChain struct{ FibreChainReader }
type stubBridge struct{ FibreBridgeReader }

func TestNewFibreAnchorReaderNeedsBothHalves(t *testing.T) {
	r, err := NewFibreAnchorReader(stubChain{}, stubBridge{})
	require.NoError(t, err)
	assert.NotNil(t, r)

	_, err = NewFibreAnchorReader(nil, stubBridge{})
	require.ErrorIs(t, err, ErrInvalidConfig)
	_, err = NewFibreAnchorReader(stubChain{}, nil)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestFibreConstructorsRefuseANilReadClient(t *testing.T) {
	_, err := NewFibreBridge(nil)
	require.Error(t, err)
	_, err = NewFibreBridgeDownloader(nil)
	require.Error(t, err)
}
