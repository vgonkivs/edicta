package node

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
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

	cmtp2p "github.com/cometbft/cometbft/proto/tendermint/p2p"
	cmtservice "github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

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

// bankHC is the bank query service the canary reads at head - k.
type bankHC struct {
	banktypes.UnimplementedQueryServer
	mu     sync.Mutex
	pinned []uint64
	fn     func(ctx context.Context, pinned uint64) (*banktypes.QueryParamsResponse, error)
}

func (s *bankHC) Params(ctx context.Context, _ *banktypes.QueryParamsRequest) (*banktypes.QueryParamsResponse, error) {
	p := pinnedHeight(ctx)
	s.mu.Lock()
	s.pinned = append(s.pinned, p)
	s.mu.Unlock()
	return s.fn(ctx, p)
}

func (s *bankHC) heights() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.pinned...)
}

// statusHC is the node service the canary reads the head from.
type statusHC struct {
	nodeservice.UnimplementedServiceServer
	head atomic.Uint64
	err  error
}

func (s *statusHC) Status(context.Context, *nodeservice.StatusRequest) (*nodeservice.StatusResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &nodeservice.StatusResponse{Height: s.head.Load()}, nil
}

func pinnedHeight(ctx context.Context) uint64 {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get(echoKey); len(v) == 1 {
		h, _ := strconv.ParseUint(v[0], 10, 64)
		return h
	}
	return 0
}

func (s *fibreHC) heights() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.pinned...)
}

// infoHC answers GetNodeInfo with a fixed chain id, or fails.
type infoHC struct {
	cmtservice.UnimplementedServiceServer
	chainID string
	err     error
}

func (s *infoHC) GetNodeInfo(context.Context, *cmtservice.GetNodeInfoRequest) (*cmtservice.GetNodeInfoResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &cmtservice.GetNodeInfoResponse{DefaultNodeInfo: &cmtp2p.DefaultNodeInfo{Network: s.chainID}}, nil
}

type hcRig struct {
	fibre  *fibreHC
	bank   *bankHC
	status *statusHC
	chain  *fakeChain
	info   *infoHC
}

func (r *hcRig) start(t *testing.T) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	fibretypes.RegisterQueryServer(srv, r.fibre)
	if r.bank != nil {
		banktypes.RegisterQueryServer(srv, r.bank)
	}
	if r.status != nil {
		nodeservice.RegisterServiceServer(srv, r.status)
	}
	if r.info != nil {
		cmtservice.RegisterServiceServer(srv, r.info)
	}
	if r.chain != nil {
		txtypes.RegisterServiceServer(srv, &txSvc{f: r.chain})
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

func startHC(t *testing.T, f *fibreHC, f2 *fakeChain) *ConsensusClient {
	t.Helper()
	return (&hcRig{fibre: f, chain: f2}).start(t)
}

type (
	bankFn  = func(context.Context, uint64) (*banktypes.QueryParamsResponse, error)
	fibreFn = func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error)
)

const head0 = 2_000_000

func newRig(head uint64, bank bankFn, fibre fibreFn) *hcRig {
	r := &hcRig{fibre: &fibreHC{fn: fibre}, bank: &bankHC{fn: bank}, status: &statusHC{}, info: &infoHC{chainID: "mocha-5"}}
	r.status.head.Store(head)
	return r
}

func bankEcho(ctx context.Context, p uint64) (*banktypes.QueryParamsResponse, error) {
	echo(ctx, p)
	return &banktypes.QueryParamsResponse{}, nil
}

func bankNoEcho(context.Context, uint64) (*banktypes.QueryParamsResponse, error) {
	return &banktypes.QueryParamsResponse{}, nil
}

func bankErr(c codes.Code) bankFn {
	return func(context.Context, uint64) (*banktypes.QueryParamsResponse, error) {
		return nil, status.Error(c, "node error")
	}
}

func fibreErr(c codes.Code) fibreFn {
	return func(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
		return nil, status.Error(c, "node error")
	}
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

func honest(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
	return nil, status.Error(codes.Internal, "failed to load state")
}

func quicknode(context.Context, uint64) (*fibretypes.QueryParamsResponse, error) {
	return paramsOK(), nil
}

func TestHeightCanaryClassification(t *testing.T) {
	cases := []struct {
		name  string
		head  uint64
		bank  bankFn
		fibre fibreFn
		want  heightcheck.Status
	}{
		{"honest node echoes and fails the pre-activation read", head0, bankEcho, fibreErr(codes.Internal), heightcheck.Honoured},
		{"pre-activation not found", head0, bankEcho, fibreErr(codes.NotFound), heightcheck.Honoured},
		{"node that drops the height answers without the echo", head0, bankNoEcho, quicknode, heightcheck.Ignoring},
		{"no echo is Ignoring even when the pre-activation read fails", head0, bankNoEcho, fibreErr(codes.Internal), heightcheck.Ignoring},
		{"node that answers at the wrong height", head0, func(ctx context.Context, p uint64) (*banktypes.QueryParamsResponse, error) {
			echo(ctx, p+1)
			return &banktypes.QueryParamsResponse{}, nil
		}, fibreErr(codes.Internal), heightcheck.Ignoring},
		{"node that answers at the head instead", head0, func(ctx context.Context, _ uint64) (*banktypes.QueryParamsResponse, error) {
			echo(ctx, head0)
			return &banktypes.QueryParamsResponse{}, nil
		}, fibreErr(codes.Internal), heightcheck.Ignoring},
		{"pre-activation x/fibre read succeeds", head0, bankEcho, quicknode, heightcheck.Ignoring},
		{"recent read fails with unavailable", head0, bankErr(codes.Unavailable), fibreErr(codes.Internal), heightcheck.Inconclusive},
		{"head at the offset", 10, bankEcho, fibreErr(codes.Internal), heightcheck.Inconclusive},
		{"head below the offset", 3, bankEcho, quicknode, heightcheck.Inconclusive},
		{"pre-activation height not below the recent height", 11, bankEcho, quicknode, heightcheck.Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newRig(tc.head, tc.bank, tc.fibre).start(t)
			got, _ := c.HeightCanary(tctx(t))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestHeightCanaryAsksConfiguredHeights(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		r := newRig(head0, bankEcho, fibreErr(codes.Internal))
		got, err := r.start(t).HeightCanary(tctx(t))
		require.NoError(t, err)
		assert.Equal(t, heightcheck.Honoured, got)
		assert.Equal(t, []uint64{head0 - 10}, r.bank.heights())
		assert.Equal(t, []string{"1082619"}, r.fibre.heights())
	})
	t.Run("another chain id has no default and no pre-activation query", func(t *testing.T) {
		r := newRig(head0, bankEcho, quicknode)
		r.info.chainID = "mainnet-1"
		got, err := r.start(t).HeightCanary(tctx(t))
		require.NoError(t, err)
		assert.Equal(t, heightcheck.Honoured, got)
		assert.Equal(t, []uint64{head0 - 10}, r.bank.heights())
		assert.Empty(t, r.fibre.heights())
	})
	t.Run("configured", func(t *testing.T) {
		r := newRig(head0, bankEcho, fibreErr(codes.Internal))
		c := r.start(t)
		c.SetCanary(CanaryConfig{RecentOffset: 3, PreActivationHeight: 50})
		got, err := c.HeightCanary(tctx(t))
		require.NoError(t, err)
		assert.Equal(t, heightcheck.Honoured, got)
		assert.Equal(t, []uint64{head0 - 3}, r.bank.heights())
		assert.Equal(t, []string{"50"}, r.fibre.heights())
	})
	t.Run("zero fields keep the defaults", func(t *testing.T) {
		r := newRig(head0, bankEcho, fibreErr(codes.Internal))
		c := r.start(t)
		c.SetCanary(CanaryConfig{})
		_, err := c.HeightCanary(tctx(t))
		require.NoError(t, err)
		assert.Equal(t, []uint64{head0 - DefaultCanaryOffset}, r.bank.heights())
		assert.Equal(t, []string{strconv.Itoa(DefaultPreActivationHeight)}, r.fibre.heights())
	})
}

func TestHeightCanaryFailedRecentReadStillRunsThePreActivationQuery(t *testing.T) {
	t.Run("ignoring wins", func(t *testing.T) {
		r := newRig(head0, bankErr(codes.Unavailable), quicknode)
		got, err := r.start(t).HeightCanary(tctx(t))
		assert.Equal(t, heightcheck.Ignoring, got)
		require.NoError(t, err)
		assert.Equal(t, []string{"1082619"}, r.fibre.heights())
	})
	t.Run("otherwise inconclusive", func(t *testing.T) {
		r := newRig(head0, bankErr(codes.Unavailable), fibreErr(codes.Internal))
		got, err := r.start(t).HeightCanary(tctx(t))
		assert.Equal(t, heightcheck.Inconclusive, got)
		require.Error(t, err)
		assert.Equal(t, []string{"1082619"}, r.fibre.heights())
	})
}

func TestHeightCanaryPreActivationNotBelowRecentIsInconclusive(t *testing.T) {
	for _, pre := range []uint64{head0 - 10, head0 - 5, head0 + 1} {
		r := newRig(head0, bankEcho, quicknode)
		c := r.start(t)
		c.SetCanary(CanaryConfig{PreActivationHeight: pre})
		got, err := c.HeightCanary(tctx(t))
		assert.Equal(t, heightcheck.Inconclusive, got, "pre %d", pre)
		require.Error(t, err)
		assert.Empty(t, r.fibre.heights(), "no query at a height that may have the module")
		assert.False(t, c.HeightFlag().Ignoring())
	}
}

func TestHeightCanaryChainIDFailureIsInconclusive(t *testing.T) {
	r := newRig(head0, bankEcho, fibreErr(codes.Internal))
	r.info.err = status.Error(codes.Unavailable, "down")
	c := r.start(t)
	got, err := c.HeightCanary(tctx(t))
	assert.Equal(t, heightcheck.Inconclusive, got)
	require.Error(t, err)
	assert.Empty(t, r.fibre.heights())

	c.SetCanary(CanaryConfig{PreActivationHeight: 50})
	got, err = c.HeightCanary(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, heightcheck.Honoured, got, "a configured height needs no chain id")
}

func TestHeightCanaryKeepsAMarkMadeWhileItRuns(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	bank := func(ctx context.Context, p uint64) (*banktypes.QueryParamsResponse, error) {
		once.Do(func() { close(started) })
		<-release
		return bankEcho(ctx, p)
	}
	c := newRig(head0, bank, fibreErr(codes.Internal)).start(t)
	type res struct {
		st  heightcheck.Status
		err error
	}
	done := make(chan res, 1)
	go func() {
		st, err := c.HeightCanary(context.Background())
		done <- res{st, err}
	}()
	<-started
	c.HeightFlag().Mark()
	close(release)
	got := <-done
	require.NoError(t, got.err)
	assert.Equal(t, heightcheck.Honoured, got.st)
	assert.True(t, c.HeightFlag().Ignoring(), "the later mark survives the earlier canary")

	st, err := c.HeightCanary(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, heightcheck.Honoured, st)
	assert.False(t, c.HeightFlag().Ignoring(), "a canary that began after the mark clears it")
}

// An honest pruned node cannot serve old pinned state, and the codes it uses
// for that vary; only the recent echo decides.
func TestHeightCanaryPrunedHonestNodeIsHonoured(t *testing.T) {
	const prunedBelow = head0 - 100
	bank := func(ctx context.Context, p uint64) (*banktypes.QueryParamsResponse, error) {
		if p < prunedBelow {
			return nil, status.Error(codes.Unknown, "version does not exist")
		}
		return bankEcho(ctx, p)
	}
	c := newRig(head0, bank, fibreErr(codes.Unknown)).start(t)
	got, err := c.HeightCanary(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, heightcheck.Honoured, got)
}

// A proxy that answers HTTP 400 surfaces as codes.Internal; whatever the code,
// an error is never a pass.
func TestHeightCanaryProxyErrorsAreNeverHonoured(t *testing.T) {
	for _, code := range []codes.Code{codes.Internal, codes.Unknown, codes.Unavailable, codes.InvalidArgument, codes.PermissionDenied} {
		t.Run(code.String()+" on the recent read", func(t *testing.T) {
			c := newRig(head0, bankErr(code), fibreErr(code)).start(t)
			got, err := c.HeightCanary(tctx(t))
			assert.Equal(t, heightcheck.Inconclusive, got)
			require.Error(t, err)
			assert.False(t, c.HeightFlag().Ignoring(), "inconclusive does not mark the flag")
		})
		t.Run(code.String()+" on the head read", func(t *testing.T) {
			r := newRig(head0, bankEcho, fibreErr(code))
			r.status.err = status.Error(code, "bad request")
			got, err := r.start(t).HeightCanary(tctx(t))
			assert.Equal(t, heightcheck.Inconclusive, got)
			require.Error(t, err)
		})
	}
	t.Run("no node service at all", func(t *testing.T) {
		r := newRig(head0, bankEcho, fibreErr(codes.Internal))
		r.status = nil
		got, err := r.start(t).HeightCanary(tctx(t))
		assert.Equal(t, heightcheck.Inconclusive, got)
		require.Error(t, err)
	})
}

func TestHeightCanaryCancelledContext(t *testing.T) {
	r := newRig(head0, bankEcho, quicknode)
	c := r.start(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := c.HeightCanary(ctx)
	assert.Equal(t, heightcheck.Inconclusive, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Empty(t, r.bank.heights())
	assert.False(t, c.HeightFlag().Ignoring())
}

func TestHeightFlagFollowsTheCanary(t *testing.T) {
	var drop atomic.Bool
	bank := func(ctx context.Context, p uint64) (*banktypes.QueryParamsResponse, error) {
		if drop.Load() {
			return bankNoEcho(ctx, p)
		}
		return bankEcho(ctx, p)
	}
	fibre := func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
		echo(ctx, p)
		return paramsOK(), nil
	}
	r := newRig(head0, bank, fibre)
	c := r.start(t)
	pastActivation := uint64(head0 - 5)

	_, err := c.FibreParamsAt(tctx(t), pastActivation)
	require.NoError(t, err, "a node that has not been marked serves reads")

	drop.Store(true)
	st, _ := c.HeightCanary(tctx(t))
	require.Equal(t, heightcheck.Ignoring, st)
	assert.True(t, c.HeightFlag().Ignoring())
	before := len(r.fibre.heights())
	_, err = c.FibreParamsAt(tctx(t), pastActivation)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Len(t, r.fibre.heights(), before, "a marked endpoint is not queried")

	r.status.err = status.Error(codes.Unavailable, "down")
	st, _ = c.HeightCanary(tctx(t))
	require.Equal(t, heightcheck.Inconclusive, st)
	assert.True(t, c.HeightFlag().Ignoring(), "inconclusive leaves the mark")

	r.status.err = nil
	drop.Store(false)
	r.fibre.fn = func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
		if p < 1_100_000 {
			return nil, status.Error(codes.Internal, "no state")
		}
		echo(ctx, p)
		return paramsOK(), nil
	}
	st, err = c.HeightCanary(tctx(t))
	require.NoError(t, err)
	require.Equal(t, heightcheck.Honoured, st)
	assert.False(t, c.HeightFlag().Ignoring())
	_, err = c.FibreParamsAt(tctx(t), pastActivation)
	require.NoError(t, err)
}

func TestTxAtMismatchMarksTheFlagAndBlocksFibreParamsAt(t *testing.T) {
	var hash [32]byte
	chain := &fakeChain{getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
		return &txtypes.GetTxResponse{TxResponse: &sdk.TxResponse{Height: 9}}, nil
	}}
	fibre := func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
		echo(ctx, p)
		return paramsOK(), nil
	}
	c := (&hcRig{fibre: &fibreHC{fn: fibre}, chain: chain}).start(t)
	assert.False(t, c.HeightFlag().Ignoring())

	_, err := c.TxAt(tctx(t), hash, 7)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.True(t, c.HeightFlag().Ignoring())

	_, err = c.FibreParamsAt(tctx(t), 1234)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestTxAtMatchLeavesTheFlagAlone(t *testing.T) {
	var hash [32]byte
	chain := &fakeChain{getTx: func(*txtypes.GetTxRequest) (*txtypes.GetTxResponse, error) {
		return &txtypes.GetTxResponse{TxResponse: &sdk.TxResponse{Height: 7}}, nil
	}}
	c := (&hcRig{fibre: &fibreHC{fn: honest}, chain: chain}).start(t)
	_, err := c.TxAt(tctx(t), hash, 7)
	require.NoError(t, err)
	assert.False(t, c.HeightFlag().Ignoring())
}

type capture struct {
	mu    sync.Mutex
	msgs  []string
	lvl   []slog.Level
	attrs []map[string]any
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs, c.lvl = append(c.msgs, r.Message), append(c.lvl, r.Level)
	a := map[string]any{}
	r.Attrs(func(at slog.Attr) bool { a[at.Key] = at.Value.Any(); return true })
	c.attrs = append(c.attrs, a)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func TestEndpointRoles(t *testing.T) {
	c := newRig(head0, bankEcho, honest).start(t)
	assert.Equal(t, heightcheck.RoleConsensus, ConsensusEndpoint("c", c).Role())
	assert.Equal(t, heightcheck.RoleBridge, BridgeEndpoint("b", bridgeOver(t, &fakeHeaders{head: 500})).Role())
}

func TestStartupWithHeightDroppingConsensusEndpoint(t *testing.T) {
	c := newRig(head0, bankNoEcho, quicknode).start(t)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("quicknode-mocha", c))
	require.NoError(t, err)
	assert.True(t, obs, "observations-only mode")
	require.Len(t, cap.msgs, 1, "exactly one startup line for the endpoint")
	assert.Equal(t, "quicknode-mocha: height-ignoring, observations-only mode", cap.msgs[0])
	assert.Equal(t, slog.LevelWarn, cap.lvl[0])
}

func TestStartupWithHonestConsensusEndpoint(t *testing.T) {
	c := newRig(head0, bankEcho, honest).start(t)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("own", c))
	require.NoError(t, err)
	assert.False(t, obs)
	require.Len(t, cap.msgs, 1)
	assert.Equal(t, "own: height honoured", cap.msgs[0])
}

func TestStartupLogsTheCanaryHeights(t *testing.T) {
	c := newRig(head0, bankEcho, honest).start(t)
	cap := &capture{}
	_, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("own", c))
	require.NoError(t, err)
	require.Len(t, cap.attrs, 1)
	assert.EqualValues(t, DefaultCanaryOffset, cap.attrs[0]["canary_offset"])
	assert.EqualValues(t, DefaultPreActivationHeight, cap.attrs[0]["canary_pre_activation"])
	assert.Equal(t, "mocha-5", cap.attrs[0]["chain_id"])
}

func TestStartupWithInconclusiveConsensusEndpoint(t *testing.T) {
	c := newRig(head0, bankErr(codes.Internal), honest).start(t)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap), ConsensusEndpoint("proxy", c))
	require.NoError(t, err)
	assert.True(t, obs)
	require.Len(t, cap.msgs, 1)
	assert.Equal(t, slog.LevelWarn, cap.lvl[0])
}

func TestStartupIgnoringBridgeIsLoggedOnly(t *testing.T) {
	ignoring := &fakeHeaders{head: 500}
	ignoring.byH = func(uint64) (*header.ExtendedHeader, error) { return extHeader(ignoring.head), nil }
	cons := newRig(head0, bankEcho, honest).start(t)
	cap := &capture{}
	obs, err := heightcheck.Startup(tctx(t), slog.New(cap),
		ConsensusEndpoint("own", cons), BridgeEndpoint("bridge", bridgeOver(t, ignoring)))
	require.NoError(t, err)
	assert.False(t, obs, "the bridge result never drives observations-only")
	require.Len(t, cap.msgs, 2)
	assert.Equal(t, "own: height honoured", cap.msgs[0])
	assert.Contains(t, cap.msgs[1], "bridge")
	assert.Equal(t, slog.LevelWarn, cap.lvl[1])
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
	short := func() *fakeHeaders {
		f := honestBridge()
		f.head = 10
		return f
	}
	cases := []struct {
		name string
		f    *fakeHeaders
		want heightcheck.Status
	}{
		{"header at head - k has that height", honestBridge(), heightcheck.Honoured},
		{"header at head - k has another height", ignoring(), heightcheck.Ignoring},
		{"lookup fails on transport", down(), heightcheck.Inconclusive},
		{"head cannot be read", headDown(), heightcheck.Inconclusive},
		{"head not above the offset", short(), heightcheck.Inconclusive},
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

func TestBridgeCanaryReadsTheConfiguredOffset(t *testing.T) {
	var asked []uint64
	f := &fakeHeaders{head: 500}
	f.byH = func(h uint64) (*header.ExtendedHeader, error) {
		asked = append(asked, h)
		return extHeader(h), nil
	}
	got, err := BridgeEndpoint("bridge", bridgeOver(t, f), CanaryConfig{RecentOffset: 25}).Canary(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, heightcheck.Honoured, got)
	assert.Equal(t, []uint64{475}, asked)

	asked = nil
	_, err = BridgeEndpoint("bridge", bridgeOver(t, f)).Canary(tctx(t))
	require.NoError(t, err)
	assert.Equal(t, []uint64{490}, asked)
}

func TestBridgeCancelledContextIsInconclusive(t *testing.T) {
	f := &fakeHeaders{head: 500}
	f.byH = func(h uint64) (*header.ExtendedHeader, error) { return extHeader(h), nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.netEr = context.Canceled
	got, err := BridgeEndpoint("bridge", bridgeOver(t, f)).Canary(ctx)
	assert.Equal(t, heightcheck.Inconclusive, got)
	require.Error(t, err)
}

// A bridge mismatch discards that response only; the consensus flag is a
// different endpoint's state.
func TestBridgeHeaderAtMismatchDoesNotMarkTheConsensusFlag(t *testing.T) {
	c := newRig(head0, bankEcho, func(ctx context.Context, p uint64) (*fibretypes.QueryParamsResponse, error) {
		echo(ctx, p)
		return paramsOK(), nil
	}).start(t)
	f := &fakeHeaders{head: 500}
	f.byH = func(uint64) (*header.ExtendedHeader, error) { return extHeader(f.head), nil }
	r := bridgeOver(t, f)

	_, err := r.HeaderAt(tctx(t), 120)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.False(t, c.HeightFlag().Ignoring())
	_, err = c.FibreParamsAt(tctx(t), 1234)
	require.NoError(t, err)
}

func TestBridgeCanaryIgnoringDoesNotMarkTheConsensusFlag(t *testing.T) {
	c := newRig(head0, bankEcho, honest).start(t)
	f := &fakeHeaders{head: 500}
	f.byH = func(uint64) (*header.ExtendedHeader, error) { return extHeader(f.head), nil }
	got, _ := BridgeEndpoint("bridge", bridgeOver(t, f)).Canary(tctx(t))
	assert.Equal(t, heightcheck.Ignoring, got)
	assert.False(t, c.HeightFlag().Ignoring())
}
