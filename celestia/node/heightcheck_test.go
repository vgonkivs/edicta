package node

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/header"
	headerapi "github.com/celestiaorg/celestia-node/nodebuilder/header"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

const echoKey = "x-cosmos-block-height"

// fibreHC is an x/fibre query service whose answer is chosen per call from
// the pinned height the client sent.
type fibreHC struct {
	fibretypes.UnimplementedQueryServer
	mu     sync.Mutex
	pinned []string
	fn     func(ctx context.Context, pinned uint64) (*fibretypes.QueryParamsResponse, error)
}

func (s *fibreHC) Params(ctx context.Context, _ *fibretypes.QueryParamsRequest) (*fibretypes.QueryParamsResponse, error) {
	var h uint64
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	s.pinned = append(s.pinned, md.Get(echoKey)...)
	s.mu.Unlock()
	if v := md.Get(echoKey); len(v) == 1 {
		h, _ = strconv.ParseUint(v[0], 10, 64)
	}
	return s.fn(ctx, h)
}

func paramsOK() *fibretypes.QueryParamsResponse {
	return &fibretypes.QueryParamsResponse{Params: fibretypes.Params{ShardRetention: 4 * time.Hour}}
}

func echo(ctx context.Context, h uint64) {
	_ = grpc.SetHeader(ctx, metadata.Pairs(echoKey, strconv.FormatUint(h, 10)))
}

func startHC(t *testing.T, f *fibreHC, f2 *fakeChain) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	fibretypes.RegisterQueryServer(srv, f)
	if f2 != nil {
		txtypes.RegisterServiceServer(srv, &txSvc{f: f2})
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	c := NewConsensusConn(conn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestFibreParamsAtPinsAndRequiresTheEcho(t *testing.T) {
	const h = 1234
	t.Run("exact echo is used", func(t *testing.T) {
		f := &fibreHC{fn: func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
			echo(ctx, p)
			return paramsOK(), nil
		}}
		c := startHC(t, f, nil)
		got, err := c.FibreParamsAt(tctx(t), h)
		require.NoError(t, err)
		assert.EqualValues(t, 4*3600, got.RetentionS)
		assert.Equal(t, []string{"1234"}, f.pinned, "the height travels in x-cosmos-block-height")
	})
	t.Run("missing echo is refused", func(t *testing.T) {
		f := &fibreHC{fn: func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) { return paramsOK(), nil }}
		_, err := startHC(t, f, nil).FibreParamsAt(tctx(t), h)
		require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
		assert.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("echo of another height is refused", func(t *testing.T) {
		f := &fibreHC{fn: func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
			echo(ctx, p+1)
			return paramsOK(), nil
		}}
		_, err := startHC(t, f, nil).FibreParamsAt(tctx(t), h)
		require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
		assert.ErrorIs(t, err, ErrUnavailable)
		assert.NotErrorIs(t, err, ErrNotFound)
	})
	t.Run("node error is not an echo problem", func(t *testing.T) {
		f := &fibreHC{fn: func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
			return nil, status.Error(codes.Internal, "failed to load state")
		}}
		_, err := startHC(t, f, nil).FibreParamsAt(tctx(t), h)
		require.Error(t, err)
		assert.NotErrorIs(t, err, heightcheck.ErrHeightIgnored)
	})
}

// honest answers every query pinned below activation with an error; quicknode
// answers the latest state with no height header, for any pinned height.
func honest(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
	return nil, status.Error(codes.Internal, "failed to load state")
}

func quicknode(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
	return paramsOK(), nil
}

func TestHeightCanaryClassification(t *testing.T) {
	cases := []struct {
		name string
		fn   func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error)
		want heightcheck.Status
	}{
		{"honest endpoint fails pinned queries", honest, heightcheck.Honoured},
		{"endpoint that drops the height answers", quicknode, heightcheck.Ignoring},
		{"endpoint that echoes nothing and fails only height 1", func(_ context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
			if p == 1 {
				return honest(context.Background(), p)
			}
			return paramsOK(), nil
		}, heightcheck.Ignoring},
		{"transport failure", func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
			return nil, status.Error(codes.Unavailable, "connection refused")
		}, heightcheck.Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := startHC(t, &fibreHC{fn: tc.fn}, nil)
			got, _ := c.HeightCanary(tctx(t))
			assert.Equal(t, tc.want, got)
		})
	}
}

type capture struct {
	mu   sync.Mutex
	msgs []string
	lvl  []slog.Level
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs, c.lvl = append(c.msgs, r.Message), append(c.lvl, r.Level)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func TestStartupWithHeightDroppingConsensusEndpoint(t *testing.T) {
	c := startHC(t, &fibreHC{fn: quicknode}, nil)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("quicknode-mocha", c))
	require.NoError(t, err)
	assert.True(t, obs, "observations-only mode")
	require.Len(t, cap.msgs, 1, "exactly one startup line for the endpoint")
	assert.Equal(t, "quicknode-mocha: height-ignoring, observations-only mode", cap.msgs[0])
	assert.Equal(t, slog.LevelWarn, cap.lvl[0])
}

func TestStartupWithHonestConsensusEndpoint(t *testing.T) {
	c := startHC(t, &fibreHC{fn: honest}, nil)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("own", c))
	require.NoError(t, err)
	assert.False(t, obs)
	require.Len(t, cap.msgs, 1)
	assert.Equal(t, "own: height honoured", cap.msgs[0])
}

func TestTxAtRequiresTheExpectedHeight(t *testing.T) {
	var hash [32]byte
	reply := func(height int64) *fakeChain {
		return &fakeChain{getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
			return &txtypes.GetTxResponse{TxResponse: &sdk.TxResponse{Height: height, Code: 0}}, nil
		}}
	}
	fibre := &fibreHC{fn: honest}
	t.Run("same height", func(t *testing.T) {
		st, err := startHC(t, fibre, reply(7)).TxAt(tctx(t), hash, 7)
		require.NoError(t, err)
		assert.True(t, st.Found)
		assert.EqualValues(t, 7, st.Height)
	})
	t.Run("other height is refused", func(t *testing.T) {
		_, err := startHC(t, fibre, reply(9)).TxAt(tctx(t), hash, 7)
		require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
		assert.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("unknown tx is not an error", func(t *testing.T) {
		f := &fakeChain{getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
			return nil, status.Error(codes.NotFound, "tx not found")
		}}
		st, err := startHC(t, fibre, f).TxAt(tctx(t), hash, 7)
		require.NoError(t, err)
		assert.False(t, st.Found)
	})
}

// fakeHeaders is the header module of a bridge node: only the calls the
// reader makes are implemented.
type fakeHeaders struct {
	headerapi.Module
	head  uint64
	byH   func(h uint64) (*header.ExtendedHeader, error)
	netEr error
}

func extHeader(h uint64) *header.ExtendedHeader {
	return &header.ExtendedHeader{RawHeader: header.RawHeader{ChainID: "mocha-4", Height: int64(h), Time: time.Unix(1_800_000_000, 0).UTC(), DataHash: []byte{byte(h)}}}
}

func (f *fakeHeaders) NetworkHead(context.Context) (*header.ExtendedHeader, error) {
	if f.netEr != nil {
		return nil, f.netEr
	}
	return extHeader(f.head), nil
}

func (f *fakeHeaders) GetByHeight(_ context.Context, h uint64) (*header.ExtendedHeader, error) {
	return f.byH(h)
}

func bridgeOver(t *testing.T, f *fakeHeaders) Reader {
	t.Helper()
	r, err := NewReader(&client.ReadClient{Header: f})
	require.NoError(t, err)
	return r
}

// A bridge that ignores heights answers the latest header for any request.
func TestBridgeHeaderAtRefusesAHeaderOfAnotherHeight(t *testing.T) {
	latest := &fakeHeaders{head: 500}
	latest.byH = func(uint64) (*header.ExtendedHeader, error) { return extHeader(latest.head), nil }
	r := bridgeOver(t, latest)

	_, err := r.HeaderAt(tctx(t), 120)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.ErrorIs(t, err, ErrUnavailable, "reaches the gate as chain unavailable")
	assert.NotErrorIs(t, err, ErrNotFound, "never an absent anchor")

	got, err := r.HeaderAt(tctx(t), 500)
	require.NoError(t, err)
	assert.EqualValues(t, 500, got.Height)
}

func TestBridgeHeaderAtHonest(t *testing.T) {
	f := &fakeHeaders{head: 500}
	f.byH = func(h uint64) (*header.ExtendedHeader, error) {
		if h > f.head {
			return nil, errors.New("header: not found")
		}
		return extHeader(h), nil
	}
	r := bridgeOver(t, f)
	got, err := r.HeaderAt(tctx(t), 120)
	require.NoError(t, err)
	assert.EqualValues(t, 120, got.Height)
	_, err = r.HeaderAt(tctx(t), 501)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestBridgeCanaryClassification(t *testing.T) {
	honestBridge := func() *fakeHeaders {
		f := &fakeHeaders{head: 500}
		f.byH = func(h uint64) (*header.ExtendedHeader, error) {
			if h > f.head {
				return nil, errors.New("header: not found")
			}
			return extHeader(h), nil
		}
		return f
	}
	ignoring := func() *fakeHeaders {
		f := &fakeHeaders{head: 500}
		f.byH = func(uint64) (*header.ExtendedHeader, error) { return extHeader(f.head), nil }
		return f
	}
	down := func() *fakeHeaders {
		f := honestBridge()
		f.byH = func(uint64) (*header.ExtendedHeader, error) { return nil, errors.New("dial tcp: connection refused") }
		return f
	}
	headDown := func() *fakeHeaders {
		f := honestBridge()
		f.netEr = errors.New("dial tcp: connection refused")
		return f
	}
	cases := []struct {
		name string
		f    *fakeHeaders
		want heightcheck.Status
	}{
		{"head plus 10^6 is not found", honestBridge(), heightcheck.Honoured},
		{"head plus 10^6 answers a header", ignoring(), heightcheck.Ignoring},
		{"lookup fails on transport", down(), heightcheck.Inconclusive},
		{"head cannot be read", headDown(), heightcheck.Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := BridgeEndpoint("bridge", bridgeOver(t, tc.f))
			assert.Equal(t, "bridge", ep.Name())
			got, _ := ep.Canary(tctx(t))
			assert.Equal(t, tc.want, got)
		})
	}
}
