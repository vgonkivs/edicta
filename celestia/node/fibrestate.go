package node

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-app/v10/fibre/validator"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	valtypes "github.com/celestiaorg/celestia-app/v10/x/valaddr/types"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	core "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const hostQueryTimeout = 15 * time.Second

// fibreState is a state.Client over a consensus gRPC connection that Edicta
// dialed itself, so it uses the same TLS and token as the rest of the traffic.
// The library's own client always dials plaintext.
type fibreState struct {
	conn    *grpc.ClientConn
	blocks  coregrpc.BlockAPIClient
	query   fibretypes.QueryClient
	vals    valtypes.QueryClient
	chainID string

	mu    sync.Mutex
	hosts map[string]validator.Host
}

var _ state.Client = (*fibreState)(nil)

func defaultDialStateClient(addr string, tls bool, token string) (state.Client, error) {
	conn, err := DialGRPC(GRPCConfig{Addr: addr, TLS: tls, Token: token, AllowInsecureToken: true})
	if err != nil {
		return nil, err
	}
	return &fibreState{
		conn: conn, blocks: coregrpc.NewBlockAPIClient(conn), query: fibretypes.NewQueryClient(conn),
		vals: valtypes.NewQueryClient(conn), hosts: map[string]validator.Host{},
	}, nil
}

// Start resolves the chain id and warms the validator host map.
func (s *fibreState) Start(ctx context.Context) error {
	r, err := cmtservice.NewServiceClient(s.conn).GetNodeInfo(ctx, &cmtservice.GetNodeInfoRequest{})
	if err != nil {
		return fmt.Errorf("detect chain ID: %w", err)
	}
	if r == nil || r.DefaultNodeInfo == nil || strings.TrimSpace(r.DefaultNodeInfo.Network) == "" {
		return errors.New("empty chain ID in node info response")
	}
	s.chainID = strings.TrimSpace(r.DefaultNodeInfo.Network)
	all, err := s.vals.AllBondedFibreProviders(ctx, &valtypes.QueryAllBondedFibreProvidersRequest{})
	if err != nil {
		// Hosts are also resolved lazily by GetHost; a chain without the
		// module must still be usable for plain blob submission.
		if status.Code(err) == codes.Unimplemented {
			return nil
		}
		return fmt.Errorf("start host registry: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range all.Providers {
		s.hosts[p.ValidatorConsensusAddress] = validator.Host(p.Info.Host)
	}
	return nil
}

func (s *fibreState) Stop(context.Context) error { return s.conn.Close() }

func (s *fibreState) ChainID() string { return s.chainID }

func (s *fibreState) Head(ctx context.Context) (validator.Set, error) { return s.valSet(ctx, 0) }

func (s *fibreState) GetByHeight(ctx context.Context, height uint64) (validator.Set, error) {
	if height == 0 {
		return validator.Set{}, errors.New("height must be greater than 0, use Head() for the latest validator set")
	}
	return s.valSet(ctx, height)
}

func (s *fibreState) valSet(ctx context.Context, height uint64) (validator.Set, error) {
	if height > math.MaxInt64 {
		return validator.Set{}, fmt.Errorf("height %d out of range", height)
	}
	r, err := s.blocks.ValidatorSet(ctx, &coregrpc.ValidatorSetRequest{Height: int64(height)})
	if err != nil {
		return validator.Set{}, fmt.Errorf("getting validator set at height %d: %w", height, err)
	}
	if r.ValidatorSet == nil {
		return validator.Set{}, fmt.Errorf("validator set is nil in response for height %d", height)
	}
	vs, err := core.ValidatorSetFromProto(r.ValidatorSet)
	if err != nil {
		return validator.Set{}, fmt.Errorf("converting validator set at height %d: %w", height, err)
	}
	return validator.Set{ValidatorSet: vs, Height: uint64(r.Height)}, nil
}

// GetHost asks the chain for the freshest host and falls back to the last one
// it knew when the query fails.
func (s *fibreState) GetHost(ctx context.Context, val *core.Validator) (validator.Host, error) {
	cons := sdk.ConsAddress(val.Address.Bytes()).String()
	qctx, cancel := context.WithTimeout(ctx, hostQueryTimeout)
	defer cancel()
	r, err := s.vals.FibreProviderInfo(qctx, &valtypes.QueryFibreProviderInfoRequest{ValidatorConsensusAddress: cons})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && r.Found {
		s.hosts[cons] = validator.Host(r.Info.Host)
	} else if _, ok := s.hosts[cons]; !ok {
		if err == nil {
			err = fmt.Errorf("host not found for validator %s", cons)
		}
		return "", err
	}
	host := s.hosts[cons]
	if err := valtypes.ValidateHost(host.String()); err != nil {
		return "", fmt.Errorf("got invalid host %s: %w", host, err)
	}
	return host, nil
}

func (s *fibreState) VerifyPromise(ctx context.Context, p *state.PaymentPromise) (state.VerifiedPromise, error) {
	r, err := s.query.ValidatePaymentPromise(ctx, &fibretypes.QueryValidatePaymentPromiseRequest{Promise: *p})
	if err != nil {
		return state.VerifiedPromise{}, err
	}
	if !r.IsValid {
		return state.VerifiedPromise{}, errors.New("payment promise is invalid")
	}
	if r.ExpirationTime == nil {
		return state.VerifiedPromise{}, errors.New("expiration time not provided in validation response")
	}
	return state.VerifiedPromise{ExpiresAt: *r.ExpirationTime, ShardRetention: r.ShardRetention}, nil
}

func (s *fibreState) FullStakeStorageBudget(ctx context.Context) (int64, error) {
	r, err := s.query.Params(ctx, &fibretypes.QueryParamsRequest{})
	if err != nil {
		return 0, err
	}
	if r.Params.FullStakeStorageBudget > math.MaxInt64 {
		return math.MaxInt64, nil
	}
	return int64(r.Params.FullStakeStorageBudget), nil
}
