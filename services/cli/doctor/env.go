package doctor

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/plugins/celestia/node"
)

// Response is an HTTP answer, body cut at a small limit.
type Response struct {
	Status int
	Body   []byte
}

// Net is the transport the checks probe with.
type Net interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	DialTCP(ctx context.Context, hostPort string) error
	// DialTLS completes a TLS handshake that verifies the certificate for
	// serverName.
	DialTLS(ctx context.Context, hostPort, serverName string) error
	// HTTPGet returns an error only when no HTTP answer came back.
	HTTPGet(ctx context.Context, url string) (Response, error)
}

// Chain is the Celestia node view of the checks: the consensus gRPC node and
// the bridge node of the config.
type Chain interface {
	ConsensusChainID(ctx context.Context) (string, error)
	BridgeHead(ctx context.Context) (node.Header, error)
	LatestHeight(ctx context.Context) (uint64, error)
	// FibreParams returns node.ErrNotFound when the chain has no x/fibre.
	FibreParams(ctx context.Context) (node.FibreParams, error)
	Escrow(ctx context.Context, bech string) (node.Escrow, error)
	MinGasPrice(ctx context.Context) (*big.Rat, error)
	Balance(ctx context.Context, addr, denom string) (uint64, error)
	Close() error
}

// EVM reads the settlement chain over one JSON-RPC provider.
type EVM interface {
	ChainID(ctx context.Context, rpcURL string) (uint64, error)
	// USDCBalance is the token balance of holder in base units.
	USDCBalance(ctx context.Context, rpcURL, token, holder string) (*big.Int, error)
}

// TimeSource reports the offset of the local clock against a reference:
// positive when the local clock is ahead.
type TimeSource interface {
	Name() string
	Offset(ctx context.Context) (time.Duration, error)
}

// Keyring opens a Celestia file keyring without ever prompting and returns
// the account address of the key. It returns node.ErrBadPassphrase when the
// passphrase does not open the store.
type Keyring interface {
	Address(ctx context.Context, dir, name, passphraseFile string) (string, error)
}

// SignerInfo is what a running signer reports about itself.
type SignerInfo struct {
	PinnedGateKeys []string
	ChainID        uint64
	USDC           string
	PayerAddress   string
}

// Signer asks a running signer service for its pins.
type Signer interface {
	Info(ctx context.Context, listen string) (SignerInfo, error)
}

// Sessions says what this build knows about gate sessions. A build without
// sessions returns Supported false.
type Sessions interface {
	Supported() bool
	// MinPublishSlackBlocks is the least slack, in blocks, a session payment
	// needs to publish.
	MinPublishSlackBlocks() uint64
	// MaxDelay is the mandate's session_max_delay; ok is false when the
	// mandate has none.
	MaxDelay(m *policy.Mandate) (delay uint64, ok bool)
}

// Env is everything the checks reach outside the process, plus the clock.
// Every field the config does not need may stay nil: a check that needs it
// then fails with a message, it does not panic.
type Env struct {
	Now func() time.Time
	Net Net
	// OpenChain opens the node connections. It is called at most once per
	// run, from the first check that needs it.
	OpenChain func(ctx context.Context, n config.Network) (Chain, error)
	EVM       EVM
	Clocks    []TimeSource
	Keyring   Keyring
	Signer    Signer
	Sessions  Sessions
	Presets   config.Presets

	mu       sync.Mutex
	chain    Chain
	chainErr error
	opened   bool
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) presets() config.Presets {
	if e.Presets != nil {
		return e.Presets
	}
	return config.Builtin{}
}

// chainFor opens the chain once and returns the same answer afterwards.
func (e *Env) chainFor(ctx context.Context, n config.Network) (Chain, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.opened {
		return e.chain, e.chainErr
	}
	e.opened = true
	if e.OpenChain == nil {
		e.chainErr = errNoProbe("chain")
		return nil, e.chainErr
	}
	e.chain, e.chainErr = e.OpenChain(ctx, n)
	return e.chain, e.chainErr
}

// Close releases the chain connections.
func (e *Env) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.chain != nil {
		err := e.chain.Close()
		e.chain = nil
		return err
	}
	return nil
}
