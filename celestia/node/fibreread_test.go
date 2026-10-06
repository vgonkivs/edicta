package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	core "github.com/cometbft/cometbft/types"
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

// readChain is a consensus node whose block stream, tx and staking answers
// are hooks.
type readChain struct {
	block   func(h int64) ([]*coregrpc.BlockByHeightResponse, error)
	getTx   func(hash string) (*txtypes.GetTxResponse, error)
	history func(h int64) (*stakingtypes.QueryHistoricalInfoResponse, error)

	mu        sync.Mutex
	blockReqs []int64
	cancelled int
}

func (c *readChain) blockReads() []int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int64(nil), c.blockReqs...)
}

func (c *readChain) streamsCancelled() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancelled
}

type readBlocks struct {
	coregrpc.BlockAPIServer
	c *readChain
}

// BlockByHeight sends the scripted messages and then holds the stream open
// until the client cancels it, as a node with more block parts would.
func (s *readBlocks) BlockByHeight(r *coregrpc.BlockByHeightRequest, st coregrpc.BlockAPI_BlockByHeightServer) error {
	s.c.mu.Lock()
	s.c.blockReqs = append(s.c.blockReqs, r.Height)
	s.c.mu.Unlock()
	msgs, err := s.c.block(r.Height)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if err := st.Send(m); err != nil {
			return err
		}
	}
	<-st.Context().Done()
	s.c.mu.Lock()
	s.c.cancelled++
	s.c.mu.Unlock()
	return st.Context().Err()
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
	coregrpc.RegisterBlockAPIServer(srv, &readBlocks{c: c})
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

func hash32(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// testHeader is a header that passes the basic checks of the consensus
// library.
func testHeader(h int64, dataHash []byte, app uint64) cmtproto.Header {
	return cmtproto.Header{
		Version:            cmtversion.Consensus{Block: 11, App: app},
		ChainID:            "mocha-4",
		Height:             h,
		Time:               time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC),
		DataHash:           dataHash,
		ValidatorsHash:     hash32("vals"),
		NextValidatorsHash: hash32("nextvals"),
		ConsensusHash:      hash32("cons"),
		LastResultsHash:    hash32("results"),
		ProposerAddress:    make([]byte, 20),
	}
}

// blockMsg is the first message of a block stream for hdr: block part 0 of
// the serialized block, proved into the part set hash that the commit names.
func blockMsg(t *testing.T, hdr cmtproto.Header) *coregrpc.BlockByHeightResponse {
	t.Helper()
	raw, err := (&cmtproto.Block{Header: hdr}).Marshal()
	require.NoError(t, err)
	ps, err := core.NewPartSetFromData(raw, core.BlockPartSizeBytes)
	require.NoError(t, err)
	pp, err := ps.GetPart(0).ToProto()
	require.NoError(t, err)
	ch, err := core.HeaderFromProto(&hdr)
	if err != nil {
		// A header the library refuses (a negative height) still gets a
		// well-formed answer around it.
		ch = core.Header{}
	}
	psh := ps.Header()
	return &coregrpc.BlockByHeightResponse{
		BlockPart: pp,
		Commit: &cmtproto.Commit{
			Height:  hdr.Height,
			BlockID: cmtproto.BlockID{Hash: ch.Hash(), PartSetHeader: psh.ToProto()},
		},
	}
}

func oneBlock(t *testing.T, hdr cmtproto.Header) func(int64) ([]*coregrpc.BlockByHeightResponse, error) {
	m := blockMsg(t, hdr)
	return func(int64) ([]*coregrpc.BlockByHeightResponse, error) {
		return []*coregrpc.BlockByHeightResponse{m}, nil
	}
}

func TestFibreHeader(t *testing.T) {
	dh := hash32("data")
	cases := []struct {
		name    string
		msgs    func(t *testing.T) []*coregrpc.BlockByHeightResponse
		err     error
		want    error
		flagged bool
	}{
		{name: "the requested height", msgs: msgs(testHeader(50, dh, 10))},
		{name: "another height", msgs: msgs(testHeader(51, dh, 10)), want: ErrUnavailable, flagged: true},
		{name: "negative height", msgs: msgs(testHeader(-1, dh, 10)), want: ErrUnavailable, flagged: true},
		{name: "no data hash", msgs: msgs(testHeader(50, nil, 10)), want: ErrUnavailable},
		{name: "no message", msgs: func(*testing.T) []*coregrpc.BlockByHeightResponse { return nil }, want: ErrUnavailable},
		{name: "empty message", msgs: func(*testing.T) []*coregrpc.BlockByHeightResponse {
			return []*coregrpc.BlockByHeightResponse{{}}
		}, want: ErrUnavailable},
		{name: "not found", err: status.Error(codes.NotFound, "no block"), want: ErrNotFound},
		{name: "node down", err: status.Error(codes.Unavailable, "down"), want: ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := startReadChain(t, &readChain{block: func(int64) ([]*coregrpc.BlockByHeightResponse, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return tc.msgs(t), nil
			}})
			h, err := c.Header(tctx(t), 50)
			assert.Equal(t, tc.flagged, c.HeightFlag().Ignoring())
			if tc.want == nil {
				require.NoError(t, err)
				assert.EqualValues(t, 50, h.Height)
				assert.Equal(t, dh, h.DataHash)
				assert.False(t, h.Time.IsZero())
				assert.EqualValues(t, 10, h.AppVersion)
				return
			}
			require.ErrorIs(t, err, tc.want)
			if tc.flagged {
				assert.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
			}
		})
	}
	t.Run("height zero is refused before the call", func(t *testing.T) {
		rc := &readChain{block: oneBlock(t, testHeader(1, dh, 10))}
		c := startReadChain(t, rc)
		_, err := c.Header(tctx(t), 0)
		require.ErrorIs(t, err, ErrUnavailable)
		assert.Empty(t, rc.blockReads())
	})
}

func msgs(hdr cmtproto.Header) func(*testing.T) []*coregrpc.BlockByHeightResponse {
	return func(t *testing.T) []*coregrpc.BlockByHeightResponse {
		return []*coregrpc.BlockByHeightResponse{blockMsg(t, hdr)}
	}
}

func TestFibreHeaderStopsAfterTheFirstMessage(t *testing.T) {
	rc := &readChain{block: oneBlock(t, testHeader(50, hash32("data"), 10))}
	c := startReadChain(t, rc)
	_, err := c.Header(tctx(t), 50)
	require.NoError(t, err)
	require.Eventually(t, func() bool { return rc.streamsCancelled() == 1 }, 5*time.Second, 5*time.Millisecond,
		"the stream is cancelled once the header is read")
}

func TestFibreHeaderStreamTampering(t *testing.T) {
	dh := hash32("data")
	good := func(t *testing.T) *coregrpc.BlockByHeightResponse { return blockMsg(t, testHeader(50, dh, 10)) }
	cases := []struct {
		name   string
		mutate func(t *testing.T, m *coregrpc.BlockByHeightResponse)
		flag   bool
	}{
		{name: "part does not prove into the part set header", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.Commit.BlockID.PartSetHeader.Hash = hash32("other part set")
		}},
		{name: "part bytes changed", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.BlockPart.Bytes = append([]byte(nil), m.BlockPart.Bytes...)
			m.BlockPart.Bytes[len(m.BlockPart.Bytes)-1] ^= 1
		}},
		{name: "header does not hash to the block id", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.Commit.BlockID.Hash = hash32("other header")
		}},
		{name: "no block id hash", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.Commit.BlockID.Hash = nil
		}},
		{name: "commit at another height", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.Commit.Height = 49
		}},
		{name: "no commit", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) { m.Commit = nil }},
		{name: "part index is not zero", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.BlockPart.Index = 1
		}},
		{name: "part is not a header", mutate: func(_ *testing.T, m *coregrpc.BlockByHeightResponse) {
			m.BlockPart.Bytes = []byte{0x12, 0x00}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := good(t)
			tc.mutate(t, m)
			c := startReadChain(t, &readChain{block: func(int64) ([]*coregrpc.BlockByHeightResponse, error) {
				return []*coregrpc.BlockByHeightResponse{m}, nil
			}})
			_, err := c.Header(tctx(t), 50)
			require.ErrorIs(t, err, ErrUnavailable)
			assert.NotErrorIs(t, err, ErrNotFound)
			assert.False(t, c.HeightFlag().Ignoring())
			_, err = c.SignedHeader(tctx(t), 50)
			require.ErrorIs(t, err, ErrUnavailable)
		})
	}
}

func TestFibreHeaderReportsTheAppVersion(t *testing.T) {
	c := startReadChain(t, &readChain{block: oneBlock(t, testHeader(50, hash32("data"), 9))})
	h, err := c.Header(tctx(t), 50)
	require.NoError(t, err)
	assert.EqualValues(t, 9, h.AppVersion, "the reader reports it; the anchor lookup refuses it")
}

func TestFibreSignedHeader(t *testing.T) {
	c := startReadChain(t, &readChain{block: func(h int64) ([]*coregrpc.BlockByHeightResponse, error) {
		hh := h
		if h == 60 {
			hh = 61
		}
		return []*coregrpc.BlockByHeightResponse{blockMsg(t, testHeader(hh, hash32("d"), 10))}, nil
	}})
	raw, err := c.SignedHeader(tctx(t), 50)
	require.NoError(t, err)
	var sh cmtproto.SignedHeader
	require.NoError(t, sh.Unmarshal(raw))
	require.NotNil(t, sh.Header)
	require.NotNil(t, sh.Commit)
	assert.EqualValues(t, 50, sh.Header.Height)
	assert.EqualValues(t, 10, sh.Header.Version.App)
	assert.EqualValues(t, 50, sh.Commit.Height)
	ch, err := core.HeaderFromProto(sh.Header)
	require.NoError(t, err)
	assert.Equal(t, ch.Hash().Bytes(), []byte(sh.Commit.BlockID.Hash), "the commit names the header")

	_, err = c.SignedHeader(tctx(t), 60)
	require.ErrorIs(t, err, ErrUnavailable)
	assert.True(t, c.HeightFlag().Ignoring())
}

func TestFibreHeaderCache(t *testing.T) {
	rc := &readChain{block: func(h int64) ([]*coregrpc.BlockByHeightResponse, error) {
		return []*coregrpc.BlockByHeightResponse{blockMsg(t, testHeader(h, hash32("d"), 10))}, nil
	}}
	c := startReadChain(t, rc)
	for range 3 {
		_, err := c.Header(tctx(t), 50)
		require.NoError(t, err)
		_, err = c.SignedHeader(tctx(t), 50)
		require.NoError(t, err)
	}
	assert.Equal(t, []int64{50}, rc.blockReads(), "one read per height, shared by both calls")

	_, err := c.Header(tctx(t), 51)
	require.NoError(t, err)
	assert.Equal(t, []int64{50, 51}, rc.blockReads())

	t.Run("failures are not cached", func(t *testing.T) {
		fail := true
		rc := &readChain{block: func(h int64) ([]*coregrpc.BlockByHeightResponse, error) {
			if fail {
				return nil, status.Error(codes.Unavailable, "down")
			}
			return []*coregrpc.BlockByHeightResponse{blockMsg(t, testHeader(h, hash32("d"), 10))}, nil
		}}
		c := startReadChain(t, rc)
		_, err := c.Header(tctx(t), 70)
		require.ErrorIs(t, err, ErrUnavailable)
		fail = false
		_, err = c.Header(tctx(t), 70)
		require.NoError(t, err)
		assert.Len(t, rc.blockReads(), 2)
	})

	t.Run("bounded", func(t *testing.T) {
		var hc headerCache
		for i := range 3 * headerCacheEntries {
			hc.put(uint64(i+1), cmtproto.Header{Height: int64(i + 1)})
		}
		assert.Len(t, hc.m, headerCacheEntries)
		_, ok := hc.get(1)
		assert.False(t, ok, "the oldest entry is evicted")
		_, ok = hc.get(uint64(3 * headerCacheEntries))
		assert.True(t, ok)
	})
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

func TestNewFibreBridgeRefusesABadAddress(t *testing.T) {
	_, err := NewFibreBridge(tctx(t), BridgeConfig{Addr: ""}, BridgeLimits{})
	require.Error(t, err)
}
