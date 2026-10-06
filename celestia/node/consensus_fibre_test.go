package node

import (
	"context"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	apptx "github.com/celestiaorg/celestia-app/v10/app/grpc/tx"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// ownNode is a consensus node with the three services the own-node Recorder
// reads; every answer is a hook.
type ownNode struct {
	txStatus func(id string) (*apptx.TxStatusResponse, error)
	valset   func(h int64) (*coregrpc.ValidatorSetResponse, error)
	escrow   func(signer string) (*fibretypes.QueryEscrowAccountResponse, error)
	params   func() (*fibretypes.QueryParamsResponse, error)

	mu      sync.Mutex
	gotTxID string
	gotSet  int64
	gotSign string
}

type ownTxSvc struct {
	apptx.UnimplementedTxServer
	n *ownNode
}

func (s *ownTxSvc) TxStatus(_ context.Context, r *apptx.TxStatusRequest) (*apptx.TxStatusResponse, error) {
	s.n.mu.Lock()
	s.n.gotTxID = r.TxId
	s.n.mu.Unlock()
	return s.n.txStatus(r.TxId)
}

type ownBlocks struct {
	coregrpc.BlockAPIServer
	n *ownNode
}

func (s *ownBlocks) ValidatorSet(_ context.Context, r *coregrpc.ValidatorSetRequest) (*coregrpc.ValidatorSetResponse, error) {
	s.n.mu.Lock()
	s.n.gotSet = r.Height
	s.n.mu.Unlock()
	return s.n.valset(r.Height)
}

type ownFibre struct {
	fibretypes.UnimplementedQueryServer
	n *ownNode
}

func (s *ownFibre) EscrowAccount(_ context.Context, r *fibretypes.QueryEscrowAccountRequest) (*fibretypes.QueryEscrowAccountResponse, error) {
	s.n.mu.Lock()
	s.n.gotSign = r.Signer
	s.n.mu.Unlock()
	return s.n.escrow(r.Signer)
}

func (s *ownFibre) Params(context.Context, *fibretypes.QueryParamsRequest) (*fibretypes.QueryParamsResponse, error) {
	return s.n.params()
}

func startOwnNode(t *testing.T, n *ownNode) *ConsensusClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	apptx.RegisterTxServer(srv, &ownTxSvc{n: n})
	coregrpc.RegisterBlockAPIServer(srv, &ownBlocks{n: n})
	fibretypes.RegisterQueryServer(srv, &ownFibre{n: n})
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

func TestTxPlaceReadsTheCommittedPlacement(t *testing.T) {
	hash := [32]byte{1, 2, 3}
	n := &ownNode{txStatus: func(string) (*apptx.TxStatusResponse, error) {
		return &apptx.TxStatusResponse{Height: 1402819, Index: 4, ExecutionCode: 0, Status: "COMMITTED"}, nil
	}}
	c := startOwnNode(t, n)
	p, err := c.TxPlace(tctx(t), hash)
	require.NoError(t, err)
	assert.Equal(t, TxPlacement{Height: 1402819, Index: 4, Code: 0, Status: "COMMITTED"}, p)
	assert.True(t, strings.EqualFold(hex.EncodeToString(hash[:]), n.gotTxID), "the request names the tx by its hex hash, got %q", n.gotTxID)

	n.txStatus = func(string) (*apptx.TxStatusResponse, error) {
		return &apptx.TxStatusResponse{Height: 1402819, Index: 4, ExecutionCode: 11, Status: "COMMITTED"}, nil
	}
	p, err = c.TxPlace(tctx(t), hash)
	require.NoError(t, err)
	assert.EqualValues(t, 11, p.Code, "the code is reported, the caller decides")
}

func TestTxPlaceOfATxThatIsNotCommittedIsNotFound(t *testing.T) {
	for _, st := range []string{"PENDING", "EVICTED", "UNKNOWN", "REJECTED", ""} {
		t.Run(st, func(t *testing.T) {
			n := &ownNode{txStatus: func(string) (*apptx.TxStatusResponse, error) {
				return &apptx.TxStatusResponse{Status: st}, nil
			}}
			_, err := startOwnNode(t, n).TxPlace(tctx(t), [32]byte{1})
			require.ErrorIs(t, err, ErrNotFound)
		})
	}
}

func TestTxPlaceFailures(t *testing.T) {
	t.Run("committed at height zero", func(t *testing.T) {
		n := &ownNode{txStatus: func(string) (*apptx.TxStatusResponse, error) {
			return &apptx.TxStatusResponse{Status: "COMMITTED"}, nil
		}}
		_, err := startOwnNode(t, n).TxPlace(tctx(t), [32]byte{1})
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("node error", func(t *testing.T) {
		n := &ownNode{txStatus: func(string) (*apptx.TxStatusResponse, error) {
			return nil, status.Error(codes.Internal, "boom")
		}}
		_, err := startOwnNode(t, n).TxPlace(tctx(t), [32]byte{1})
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func testValidatorSet(t *testing.T) *cmtproto.ValidatorSet {
	t.Helper()
	v := core.NewValidator(ed25519.GenPrivKey().PubKey(), 10)
	vs := core.NewValidatorSet([]*core.Validator{v})
	p, err := vs.ToProto()
	require.NoError(t, err)
	return p
}

func TestValidatorSetReturnsTheProtobufSetAtTheHeight(t *testing.T) {
	want := testValidatorSet(t)
	n := &ownNode{valset: func(h int64) (*coregrpc.ValidatorSetResponse, error) {
		return &coregrpc.ValidatorSetResponse{ValidatorSet: want, Height: h}, nil
	}}
	c := startOwnNode(t, n)
	raw, err := c.ValidatorSet(tctx(t), 1402814)
	require.NoError(t, err)
	assert.EqualValues(t, 1402814, n.gotSet)
	var got cmtproto.ValidatorSet
	require.NoError(t, got.Unmarshal(raw))
	assert.Equal(t, want.Validators[0].Address, got.Validators[0].Address)
	assert.False(t, c.HeightFlag().Ignoring())
}

func TestValidatorSetAtAnotherHeightMarksTheEndpoint(t *testing.T) {
	n := &ownNode{valset: func(h int64) (*coregrpc.ValidatorSetResponse, error) {
		return &coregrpc.ValidatorSetResponse{ValidatorSet: testValidatorSet(t), Height: h + 1}, nil
	}}
	c := startOwnNode(t, n)
	_, err := c.ValidatorSet(tctx(t), 1402814)
	require.ErrorIs(t, err, ErrUnavailable)
	require.ErrorIs(t, err, heightcheck.ErrHeightIgnored)
	assert.True(t, c.HeightFlag().Ignoring(), "an endpoint that drops the requested height is marked")
}

func TestValidatorSetRefusals(t *testing.T) {
	t.Run("no set in the answer", func(t *testing.T) {
		n := &ownNode{valset: func(h int64) (*coregrpc.ValidatorSetResponse, error) {
			return &coregrpc.ValidatorSetResponse{Height: h}, nil
		}}
		_, err := startOwnNode(t, n).ValidatorSet(tctx(t), 5)
		require.Error(t, err)
	})
	t.Run("height zero is the latest set, not a height", func(t *testing.T) {
		n := &ownNode{valset: func(h int64) (*coregrpc.ValidatorSetResponse, error) {
			return &coregrpc.ValidatorSetResponse{ValidatorSet: testValidatorSet(t), Height: 9}, nil
		}}
		_, err := startOwnNode(t, n).ValidatorSet(tctx(t), 0)
		require.Error(t, err)
	})
	t.Run("node error", func(t *testing.T) {
		n := &ownNode{valset: func(int64) (*coregrpc.ValidatorSetResponse, error) {
			return nil, status.Error(codes.Unavailable, "down")
		}}
		_, err := startOwnNode(t, n).ValidatorSet(tctx(t), 5)
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func TestConsensusEscrowAccountIsAReadOnlyQuery(t *testing.T) {
	account := func(denomBal, denomAvail string, bal, avail int64) func(string) (*fibretypes.QueryEscrowAccountResponse, error) {
		return func(signer string) (*fibretypes.QueryEscrowAccountResponse, error) {
			return &fibretypes.QueryEscrowAccountResponse{Found: true, EscrowAccount: &fibretypes.EscrowAccount{
				Signer: signer, Balance: coin(bal, denomBal), AvailableBalance: coin(avail, denomAvail),
			}}, nil
		}
	}
	t.Run("found", func(t *testing.T) {
		n := &ownNode{escrow: account("utia", "utia", 100, 70)}
		e, err := startOwnNode(t, n).EscrowAccount(tctx(t), "celestia1abc")
		require.NoError(t, err)
		assert.Equal(t, Escrow{AvailableUtia: 70, PendingWithdrawalUtia: 30}, e)
		assert.Equal(t, "celestia1abc", n.gotSign)
	})
	t.Run("not found holds nothing", func(t *testing.T) {
		n := &ownNode{escrow: func(string) (*fibretypes.QueryEscrowAccountResponse, error) {
			return &fibretypes.QueryEscrowAccountResponse{}, nil
		}}
		e, err := startOwnNode(t, n).EscrowAccount(tctx(t), "celestia1abc")
		require.NoError(t, err)
		assert.Equal(t, Escrow{}, e)
	})
	t.Run("another denom", func(t *testing.T) {
		n := &ownNode{escrow: account("uother", "uother", 100, 70)}
		_, err := startOwnNode(t, n).EscrowAccount(tctx(t), "celestia1abc")
		require.ErrorIs(t, err, ErrUnsupported)
	})
	t.Run("node error", func(t *testing.T) {
		n := &ownNode{escrow: func(string) (*fibretypes.QueryEscrowAccountResponse, error) {
			return nil, status.Error(codes.Unavailable, "down")
		}}
		_, err := startOwnNode(t, n).EscrowAccount(tctx(t), "celestia1abc")
		require.ErrorIs(t, err, ErrUnavailable)
	})
}

func TestFibreParamsCarryThePromiseHeightWindow(t *testing.T) {
	n := &ownNode{params: func() (*fibretypes.QueryParamsResponse, error) {
		return &fibretypes.QueryParamsResponse{Params: fibretypes.Params{
			ShardRetention: 4 * time.Hour, PaymentPromiseHeightWindow: 1000,
		}}, nil
	}}
	p, err := startOwnNode(t, n).FibreParams(tctx(t))
	require.NoError(t, err)
	assert.EqualValues(t, 14400, p.RetentionS)
	assert.EqualValues(t, 1000, p.PromiseHeightWindow)
}

func TestConsensusAddrIsTheDialedAddress(t *testing.T) {
	c, err := NewConsensus(GRPCConfig{Addr: "127.0.0.1:9090"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	assert.Equal(t, "127.0.0.1:9090", c.Addr())
}
