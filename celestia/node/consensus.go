package node

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	coregrpc "github.com/cometbft/cometbft/rpc/grpc"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// GRPCConfig is one consensus gRPC endpoint.
type GRPCConfig struct {
	Addr string
	TLS  bool
	// Token is sent as the x-token header; empty sends none. It is refused
	// without TLS unless the address is passed through AllowInsecureToken.
	Token string
	// AllowInsecureToken permits a token over plain gRPC to a loopback
	// address (a local devnet).
	AllowInsecureToken bool
}

// LoopbackAddr reports whether addr names the local machine by a literal
// loopback IP: a plain host:port or an http(s) URL without userinfo or path.
// Host names, including localhost, are not trusted because a resolver
// decides where they point. Anything unrecognised is not loopback.
func LoopbackAddr(addr string) bool {
	host := addr
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return false
		}
		host = u.Hostname()
	} else {
		if strings.ContainsAny(addr, "@/?#\\") {
			return false
		}
		if h, port, err := net.SplitHostPort(addr); err == nil {
			if port == "" {
				return false
			}
			for _, r := range port {
				if r < '0' || r > '9' {
					return false
				}
			}
			host = h
		}
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkTokenTransport enforces that a bearer token only travels over TLS or,
// with the explicit opt-in, to a loopback address.
func checkTokenTransport(what, addr, token string, tls, allowInsecure bool) error {
	if allowInsecure && !LoopbackAddr(addr) {
		return fmt.Errorf("node: %s: insecure token opt-in for non-loopback address %q refused; only literal loopback IPs such as 127.0.0.1 qualify", what, addr)
	}
	if token != "" && !tls && !allowInsecure {
		return fmt.Errorf("node: %s token over plain connection refused", what)
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (c GRPCConfig) ValidateBasic() error {
	if c.Addr == "" {
		return errors.New("node: no consensus gRPC address")
	}
	return checkTokenTransport("consensus", c.Addr, c.Token, c.TLS, c.AllowInsecureToken)
}

const maxGRPCMessage = 64 << 20

// DialGRPC opens a lazy connection; nothing is sent until the first call.
func DialGRPC(c GRPCConfig) (*grpc.ClientConn, error) {
	if err := c.ValidateBasic(); err != nil {
		return nil, err
	}
	creds := insecure.NewCredentials()
	if c.TLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGRPCMessage), grpc.MaxCallSendMsgSize(maxGRPCMessage)),
	}
	if c.Token != "" {
		tok := c.Token
		opts = append(opts, grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, inv grpc.UnaryInvoker, o ...grpc.CallOption) error {
			return inv(metadata.AppendToOutgoingContext(ctx, "x-token", tok), method, req, reply, cc, o...)
		}))
	}
	return grpc.NewClient(c.Addr, opts...)
}

// ConsensusClient implements Consensus over a consensus node's gRPC.
type ConsensusClient struct {
	conn    *grpc.ClientConn
	cmt     cmtservice.ServiceClient
	auth    authtypes.QueryClient
	staking stakingtypes.QueryClient
	tx      txtypes.ServiceClient
	fibre   fibretypes.QueryClient
	cfg     nodeservice.ServiceClient
	bank    banktypes.QueryClient

	blocks coregrpc.BlockAPIClient
	hdrs   headerCache

	addr string

	canary CanaryConfig
	flag   heightcheck.Flag

	mu       sync.Mutex
	resolved canaryHeights
}

// canaryHeights are the heights the last canary run used.
type canaryHeights struct {
	chainID string
	recent  uint64
	pre     uint64
}

// DefaultCanaryOffset is the recent offset k. It must stay inside every node's
// retained state.
const DefaultCanaryOffset = 10

// DefaultPreActivationHeight is the last Mocha height before x/fibre existed.
const DefaultPreActivationHeight = 1_082_619

// defaultPreActivation holds the pre-activation heights known per chain id.
// Other chains have none unless configured.
var defaultPreActivation = map[string]uint64{"mocha-5": DefaultPreActivationHeight}

// CanaryConfig sets the heights the consensus canary asks for.
type CanaryConfig struct {
	// RecentOffset is k: the canary reads at head - k. Zero takes the default.
	RecentOffset uint64
	// PreActivationHeight is a height before x/fibre existed on the chain. Zero
	// takes the default for the node's chain id, and none when there is none.
	PreActivationHeight uint64
}

func (c CanaryConfig) withDefaults() CanaryConfig {
	if c.RecentOffset == 0 {
		c.RecentOffset = DefaultCanaryOffset
	}
	return c
}

// SetCanary sets the canary heights; call it before the client is shared.
func (c *ConsensusClient) SetCanary(cfg CanaryConfig) { c.canary = cfg.withDefaults() }

// HeightFlag is the flag the canary and TxAt set; the canary clears it.
func (c *ConsensusClient) HeightFlag() *heightcheck.Flag { return &c.flag }

var _ Consensus = (*ConsensusClient)(nil)

// NewConsensus dials c. Close releases the connection.
func NewConsensus(c GRPCConfig) (*ConsensusClient, error) {
	conn, err := DialGRPC(c)
	if err != nil {
		return nil, err
	}
	cc := NewConsensusConn(conn)
	cc.addr = c.Addr
	return cc, nil
}

// Addr is the address the client was dialled with; empty for a client built
// from a bare connection.
func (c *ConsensusClient) Addr() string { return c.addr }

// NewConsensusConn wraps an existing connection, which Close will close.
func NewConsensusConn(conn *grpc.ClientConn) *ConsensusClient {
	return &ConsensusClient{
		conn: conn, cmt: cmtservice.NewServiceClient(conn), auth: authtypes.NewQueryClient(conn),
		staking: stakingtypes.NewQueryClient(conn), tx: txtypes.NewServiceClient(conn),
		fibre: fibretypes.NewQueryClient(conn), cfg: nodeservice.NewServiceClient(conn),
		bank: banktypes.NewQueryClient(conn), blocks: coregrpc.NewBlockAPIClient(conn), canary: CanaryConfig{}.withDefaults(),
	}
}

// Close closes the connection.
func (c *ConsensusClient) Close() error { return c.conn.Close() }

func (c *ConsensusClient) Network(ctx context.Context) (string, error) {
	r, err := c.cmt.GetNodeInfo(ctx, &cmtservice.GetNodeInfoRequest{})
	if err != nil {
		return "", classifyGRPC(ctx, err)
	}
	if r.DefaultNodeInfo == nil || r.DefaultNodeInfo.Network == "" {
		return "", fmt.Errorf("%w: node info has no network", ErrUnsupported)
	}
	return r.DefaultNodeInfo.Network, nil
}

// ProviderChainIDs is empty: this build has no separate consensus RPC
// providers, only the gRPC endpoint Network already reports on.
func (c *ConsensusClient) ProviderChainIDs(context.Context) ([]string, error) { return nil, nil }

// FibreParams returns ErrNotFound when the chain has no x/fibre module.
func (c *ConsensusClient) FibreParams(ctx context.Context) (FibreParams, error) {
	r, err := c.fibre.Params(ctx, &fibretypes.QueryParamsRequest{})
	if err != nil {
		err = classifyGRPC(ctx, err)
		if errors.Is(err, ErrUnsupported) { // unknown service: the module is absent
			return FibreParams{}, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return FibreParams{}, err
	}
	return fibreParams(r)
}

func fibreParams(r *fibretypes.QueryParamsResponse) (FibreParams, error) {
	d := r.Params.ShardRetention
	if d <= 0 {
		return FibreParams{}, fmt.Errorf("%w: x/fibre shard retention is not positive", ErrUnsupported)
	}
	return FibreParams{RetentionS: uint64(d.Seconds()), PromiseHeightWindow: r.Params.PaymentPromiseHeightWindow}, nil
}

// pinned sends the height in x-cosmos-block-height and returns the response
// headers.
func pinned(ctx context.Context, height uint64) (context.Context, *metadata.MD) {
	return metadata.AppendToOutgoingContext(ctx, heightcheck.HeightHeader, strconv.FormatUint(height, 10)), &metadata.MD{}
}

func heightIgnored(err error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// FibreParamsAt reads x/fibre params at height and requires the node to echo
// that height.
func (c *ConsensusClient) FibreParamsAt(ctx context.Context, height uint64) (FibreParams, error) {
	if c.flag.Ignoring() {
		return FibreParams{}, heightIgnored(fmt.Errorf("%w: endpoint marked height-ignoring", heightcheck.ErrHeightIgnored))
	}
	pctx, md := pinned(ctx, height)
	r, err := c.fibre.Params(pctx, &fibretypes.QueryParamsRequest{}, grpc.Header(md))
	if err != nil {
		return FibreParams{}, classifyGRPC(ctx, err)
	}
	if err := heightcheck.EchoHeight(*md, height); err != nil {
		return FibreParams{}, heightIgnored(err)
	}
	return fibreParams(r)
}

// HeightCanary decides from the node's answers alone, never from error codes.
// A bank query at head - k must succeed and echo that height; success without
// the echo, or an x/fibre query that succeeds at a height before the module
// existed, means the node drops the height. Anything else proves nothing.
func (c *ConsensusClient) HeightCanary(ctx context.Context) (heightcheck.Status, error) {
	gen := c.flag.Generation()
	st, err := c.heightCanary(ctx)
	switch st {
	case heightcheck.Honoured:
		c.flag.ClearIf(gen)
	case heightcheck.Ignoring:
		c.flag.Mark()
	}
	return st, err
}

// preActivation returns the configured pre-activation height, else the default
// for the node's chain id; zero means there is none.
func (c *ConsensusClient) preActivation(ctx context.Context, cfg CanaryConfig) (uint64, error) {
	if cfg.PreActivationHeight != 0 {
		return cfg.PreActivationHeight, nil
	}
	id, err := c.Network(ctx)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.resolved.chainID = id
	c.mu.Unlock()
	return defaultPreActivation[id], nil
}

func (c *ConsensusClient) heightCanary(ctx context.Context) (heightcheck.Status, error) {
	cfg := c.canary.withDefaults()
	head, err := c.LatestHeight(ctx)
	if err != nil {
		return heightcheck.Inconclusive, fmt.Errorf("height canary: %w", err)
	}
	if head <= cfg.RecentOffset {
		return heightcheck.Inconclusive, fmt.Errorf("height canary: head %d is not above offset %d", head, cfg.RecentOffset)
	}
	recent := head - cfg.RecentOffset
	pre, preErr := c.preActivation(ctx, cfg)
	c.mu.Lock()
	c.resolved.recent, c.resolved.pre = cfg.RecentOffset, pre
	c.mu.Unlock()

	// A failed recent read must not hide a node that answers before activation:
	// Ignoring wins over Inconclusive.
	var recentErr error
	pctx, md := pinned(ctx, recent)
	if _, err := c.bank.Params(pctx, &banktypes.QueryParamsRequest{}, grpc.Header(md)); err != nil {
		recentErr = fmt.Errorf("height canary: recent read at %d: %w", recent, classifyGRPC(ctx, err))
	} else if heightcheck.EchoHeight(*md, recent) != nil {
		return heightcheck.Ignoring, nil
	}
	if preErr == nil && pre != 0 && pre < recent {
		pctx, md = pinned(ctx, pre)
		r, err := c.fibre.Params(pctx, &fibretypes.QueryParamsRequest{}, grpc.Header(md))
		if err == nil && r != nil {
			return heightcheck.Ignoring, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return heightcheck.Inconclusive, fmt.Errorf("height canary: %w", classifyGRPC(ctx, cerr))
		}
	}
	if recentErr != nil {
		return heightcheck.Inconclusive, recentErr
	}
	if preErr == nil && pre != 0 && pre >= recent {
		return heightcheck.Inconclusive, fmt.Errorf("height canary: pre-activation height %d is not below recent height %d", pre, recent)
	}
	if preErr != nil {
		return heightcheck.Inconclusive, fmt.Errorf("height canary: chain id: %w", preErr)
	}
	return heightcheck.Honoured, nil
}

// CanaryHeights reports the offset and pre-activation height the last canary
// run used, with the chain id when it was needed. Pre is zero when there is none.
func (c *ConsensusClient) CanaryHeights() (offset, pre uint64, chainID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resolved.recent, c.resolved.pre, c.resolved.chainID
}

func (c *ConsensusClient) BondDenom(ctx context.Context) (string, error) {
	r, err := c.staking.Params(ctx, &stakingtypes.QueryParamsRequest{})
	if err != nil {
		return "", classifyGRPC(ctx, err)
	}
	if r.Params.BondDenom == "" {
		return "", fmt.Errorf("%w: empty bond denom", ErrUnsupported)
	}
	return r.Params.BondDenom, nil
}

func (c *ConsensusClient) Bech32Prefix(ctx context.Context) (string, error) {
	r, err := c.auth.Bech32Prefix(ctx, &authtypes.Bech32PrefixRequest{})
	if err != nil {
		return "", classifyGRPC(ctx, err)
	}
	if r.Bech32Prefix == "" {
		return "", fmt.Errorf("%w: empty bech32 prefix", ErrUnsupported)
	}
	return r.Bech32Prefix, nil
}

func (c *ConsensusClient) Account(ctx context.Context, address string) (AccountInfo, error) {
	r, err := c.auth.AccountInfo(ctx, &authtypes.QueryAccountInfoRequest{Address: address})
	if err != nil {
		return AccountInfo{}, classifyGRPC(ctx, err)
	}
	if r.Info == nil {
		return AccountInfo{}, fmt.Errorf("%w: account %s", ErrNotFound, address)
	}
	return AccountInfo{Number: r.Info.AccountNumber, Sequence: r.Info.Sequence}, nil
}

// AccountAt is Account pinned to height. The node must echo that height, so a
// load-balanced endpoint that answers from a backend which has not reached it
// (or ignores the pin) fails with ErrUnavailable and heightcheck.ErrHeightIgnored
// instead of returning a state of another height.
func (c *ConsensusClient) AccountAt(ctx context.Context, address string, height uint64) (AccountInfo, error) {
	if height == 0 {
		return AccountInfo{}, errors.New("node: account at height zero")
	}
	if c.flag.Ignoring() {
		return AccountInfo{}, heightIgnored(fmt.Errorf("%w: endpoint marked height-ignoring", heightcheck.ErrHeightIgnored))
	}
	pctx, md := pinned(ctx, height)
	r, err := c.auth.AccountInfo(pctx, &authtypes.QueryAccountInfoRequest{Address: address}, grpc.Header(md))
	if err != nil {
		return AccountInfo{}, classifyGRPC(ctx, err)
	}
	if err := heightcheck.EchoHeight(*md, height); err != nil {
		return AccountInfo{}, heightIgnored(err)
	}
	if r.Info == nil {
		return AccountInfo{}, fmt.Errorf("%w: account %s", ErrNotFound, address)
	}
	return AccountInfo{Number: r.Info.AccountNumber, Sequence: r.Info.Sequence}, nil
}

// seqTxLimit bounds the answer: one signer cannot have two committed
// transactions at one sequence, so a few results are already more than honest.
const seqTxLimit = 5

// TxBySequence asks the node's index for the transactions of address signed
// with sequence, through the tx.acc_seq event.
func (c *ConsensusClient) TxBySequence(ctx context.Context, address string, sequence uint64) ([]SeqTx, error) {
	if address == "" || strings.ContainsAny(address, "'/ ") {
		return nil, errors.New("node: bad address for a sequence lookup")
	}
	r, err := c.tx.GetTxsEvent(ctx, &txtypes.GetTxsEventRequest{
		Query:   fmt.Sprintf("tx.acc_seq='%s/%d'", address, sequence),
		OrderBy: txtypes.OrderBy_ORDER_BY_ASC,
		Page:    1,
		Limit:   seqTxLimit,
	})
	if err != nil {
		return nil, classifyGRPC(ctx, err)
	}
	var out []SeqTx
	for _, tr := range r.GetTxResponses() {
		if tr == nil || tr.Height <= 0 {
			continue
		}
		h, err := hex.DecodeString(tr.TxHash)
		if err != nil || len(h) != 32 {
			return nil, fmt.Errorf("%w: sequence lookup returned tx hash %q", ErrUnavailable, tr.TxHash)
		}
		st := SeqTx{Height: uint64(tr.Height)}
		copy(st.Hash[:], h)
		out = append(out, st)
	}
	return out, nil
}

// Balance reads the bank balance of addr in denom at the node's latest state.
// An account the chain has never seen has balance zero. It is advisory, for
// funding decisions; nothing in the gate's checks depends on it, so the read is
// not pinned to a height.
func (c *ConsensusClient) Balance(ctx context.Context, addr, denom string) (uint64, error) {
	if addr == "" || denom == "" {
		return 0, errors.New("node: balance needs an address and a denom")
	}
	r, err := c.bank.Balance(ctx, &banktypes.QueryBalanceRequest{Address: addr, Denom: denom})
	if err != nil {
		return 0, classifyGRPC(ctx, err)
	}
	return balanceAmount(r.GetBalance(), denom)
}

// BalanceAt is Balance pinned to height. The node must echo that height, so a
// backend that has not reached it, or ignores the pin, fails with
// ErrUnavailable and heightcheck.ErrHeightIgnored instead of answering from
// another height.
func (c *ConsensusClient) BalanceAt(ctx context.Context, addr, denom string, height uint64) (uint64, error) {
	if addr == "" || denom == "" {
		return 0, errors.New("node: balance needs an address and a denom")
	}
	if height == 0 {
		return 0, errors.New("node: balance at height zero")
	}
	if c.flag.Ignoring() {
		return 0, heightIgnored(fmt.Errorf("%w: endpoint marked height-ignoring", heightcheck.ErrHeightIgnored))
	}
	pctx, md := pinned(ctx, height)
	r, err := c.bank.Balance(pctx, &banktypes.QueryBalanceRequest{Address: addr, Denom: denom}, grpc.Header(md))
	if err != nil {
		return 0, classifyGRPC(ctx, err)
	}
	if err := heightcheck.EchoHeight(*md, height); err != nil {
		return 0, heightIgnored(err)
	}
	return balanceAmount(r.GetBalance(), denom)
}

func balanceAmount(b *sdk.Coin, denom string) (uint64, error) {
	if b == nil {
		return 0, nil
	}
	if b.Denom != denom {
		return 0, fmt.Errorf("%w: balance answered for denom %q, asked %q", ErrUnsupported, b.Denom, denom)
	}
	if b.Amount.IsNil() || b.Amount.IsNegative() || !b.Amount.IsUint64() {
		return 0, fmt.Errorf("%w: balance amount out of range", ErrUnsupported)
	}
	return b.Amount.Uint64(), nil
}

// Cosmos SDK error codes in the "sdk" codespace.
const (
	sdkCodespace         = "sdk"
	codeWrongSequence    = 32
	codeTxInMempoolCache = 19
	codeMempoolFull      = 20
)

// Broadcast sends txRaw unchanged in sync mode and returns its hash, the
// SHA-256 of the bytes, which it checks against the node's answer.
func (c *ConsensusClient) Broadcast(ctx context.Context, txRaw []byte) ([32]byte, error) {
	want := sha256.Sum256(txRaw)
	r, err := c.tx.BroadcastTx(ctx, &txtypes.BroadcastTxRequest{TxBytes: txRaw, Mode: txtypes.BroadcastMode_BROADCAST_MODE_SYNC})
	if err != nil {
		err = classifyGRPC(ctx, err)
		if strings.Contains(err.Error(), "account sequence mismatch") {
			return [32]byte{}, fmt.Errorf("%w: %w", ErrSequenceMismatch, err)
		}
		if strings.Contains(err.Error(), "tx already exists in cache") {
			return want, fmt.Errorf("%w: %w", ErrAlreadyInMempool, err)
		}
		return [32]byte{}, err
	}
	tr := r.GetTxResponse()
	if tr == nil {
		return [32]byte{}, fmt.Errorf("%w: empty broadcast response", ErrUnavailable)
	}
	if tr.Code != 0 {
		switch {
		case tr.Codespace == sdkCodespace && tr.Code == codeTxInMempoolCache:
			return want, fmt.Errorf("%w: %s", ErrAlreadyInMempool, tr.RawLog)
		case tr.Codespace == sdkCodespace && tr.Code == codeWrongSequence:
			return [32]byte{}, fmt.Errorf("%w: %s", ErrSequenceMismatch, tr.RawLog)
		case tr.Codespace == sdkCodespace && tr.Code == codeMempoolFull:
			return [32]byte{}, fmt.Errorf("%w: codespace %q code %d: %s", ErrMempoolFull, tr.Codespace, tr.Code, tr.RawLog)
		}
		return [32]byte{}, fmt.Errorf("%w: codespace %q code %d: %s", ErrRejected, tr.Codespace, tr.Code, tr.RawLog)
	}
	if !strings.EqualFold(tr.TxHash, hex.EncodeToString(want[:])) {
		return [32]byte{}, fmt.Errorf("%w: node returned tx hash %q for a different transaction", ErrUnavailable, tr.TxHash)
	}
	return want, nil
}

// LatestHeight reads the latest committed height from the node service Status
// call, which is light: it carries no block data.
func (c *ConsensusClient) LatestHeight(ctx context.Context) (uint64, error) {
	r, err := c.cfg.Status(ctx, &nodeservice.StatusRequest{})
	if err != nil {
		return 0, classifyGRPC(ctx, err)
	}
	if r.GetHeight() == 0 {
		return 0, fmt.Errorf("%w: node reported no latest height", ErrUnavailable)
	}
	return r.GetHeight(), nil
}

// TxIndex requires default_node_info.other.tx_index to be exactly "on".
func (c *ConsensusClient) TxIndex(ctx context.Context) error {
	r, err := c.cmt.GetNodeInfo(ctx, &cmtservice.GetNodeInfoRequest{})
	if err != nil {
		return fmt.Errorf("%w: node info: %w", ErrTxIndexDisabled, classifyGRPC(ctx, err))
	}
	if r.DefaultNodeInfo == nil || r.DefaultNodeInfo.Other.TxIndex != "on" {
		return fmt.Errorf("%w: the node does not report tx_index on", ErrTxIndexDisabled)
	}
	return nil
}

// Tx reports a committed transaction; an unknown hash is Found false, not an
// error. The node's height is read first, so a transaction included at or
// before it is seen by the lookup.
func (c *ConsensusClient) Tx(ctx context.Context, hash [32]byte) (TxStatus, error) {
	nodeHeight, _ := c.LatestHeight(ctx)
	r, err := c.tx.GetTx(ctx, &txtypes.GetTxRequest{Hash: strings.ToUpper(hex.EncodeToString(hash[:]))})
	if err != nil {
		err = classifyGRPC(ctx, err)
		if errors.Is(err, ErrNotFound) {
			return TxStatus{NodeHeight: nodeHeight}, nil
		}
		return TxStatus{}, err
	}
	tr := r.GetTxResponse()
	if tr == nil {
		return TxStatus{NodeHeight: nodeHeight}, nil
	}
	return TxStatus{Found: true, Height: uint64(tr.Height), Code: tr.Code, NodeHeight: nodeHeight}, nil
}

// TxAt is Tx for a transaction expected at height.
func (c *ConsensusClient) TxAt(ctx context.Context, hash [32]byte, height uint64) (TxStatus, error) {
	st, err := c.Tx(ctx, hash)
	if err != nil {
		return TxStatus{}, err
	}
	if st.Found {
		if err := heightcheck.HeaderHeight(st.Height, height); err != nil {
			c.flag.Mark()
			return TxStatus{}, heightIgnored(err)
		}
	}
	return st, nil
}

// MinGasPrice reads minimum_gas_price from the node Config service, a decimal
// followed by the denom, and returns the decimal exactly.
func (c *ConsensusClient) MinGasPrice(ctx context.Context) (*big.Rat, error) {
	r, err := c.cfg.Config(ctx, &nodeservice.ConfigRequest{})
	if err != nil {
		return nil, classifyGRPC(ctx, err)
	}
	s := r.MinimumGasPrice
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	price, ok := new(big.Rat).SetString(s[:i])
	if i == 0 || !ok || price.Sign() < 0 {
		return nil, fmt.Errorf("%w: minimum gas price %q", ErrUnsupported, s)
	}
	return price, nil
}

type consensusEndpoint struct {
	name string
	c    Consensus
}

// ConsensusEndpoint exposes the height canary of c to heightcheck.Startup.
func ConsensusEndpoint(name string, c Consensus) heightcheck.Endpoint {
	return consensusEndpoint{name: name, c: c}
}

func (e consensusEndpoint) Name() string { return e.name }

// Details reports the canary heights when the client exposes them.
func (e consensusEndpoint) Details() []any {
	h, ok := e.c.(interface {
		CanaryHeights() (uint64, uint64, string)
	})
	if !ok {
		return nil
	}
	offset, pre, id := h.CanaryHeights()
	return []any{"canary_offset", offset, "canary_pre_activation", pre, "chain_id", id}
}

func (e consensusEndpoint) Role() heightcheck.Role { return heightcheck.RoleConsensus }

func (e consensusEndpoint) Canary(ctx context.Context) (heightcheck.Status, error) {
	return e.c.HeightCanary(ctx)
}
