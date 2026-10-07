package railtx

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/celestia/node"
)

var (
	// ErrSendInFlight means the previous funding send could still land, so no
	// new one is built.
	ErrSendInFlight = errors.New("railtx: a funding send is still in flight")
	// ErrBadRecipient means the recipient is not a valid address of the
	// node's chain.
	ErrBadRecipient = errors.New("railtx: bad recipient address")
)

const (
	// DefaultFundingTimeoutBlocks is how many blocks past the head a funding
	// send stays includable.
	DefaultFundingTimeoutBlocks = 100
	// MaxFundingTimeoutBlocks caps FunderConfig.TimeoutBlocks.
	MaxFundingTimeoutBlocks = 10000
	// DefaultFundingMemo is the memo of a funding send.
	DefaultFundingMemo = "edicta-demo funding"
	// DefaultIndexerLagBlocks is how far past the timeout height the node must
	// be before an unseen send counts as lost.
	DefaultIndexerLagBlocks = 3
	maxMemoBytes            = 256
)

// FunderConfig configures a Funder.
type FunderConfig struct {
	Consensus node.Consensus
	Key       KeySource
	// Consent must be armed by the caller before the first Send.
	Consent *Consent
	// GasLimit and Fee are attached to every send, in base units of the bond
	// denom; GasLimit must be nonzero.
	GasLimit uint64
	Fee      uint64
	// TimeoutBlocks bounds inclusion: timeout_height is head + TimeoutBlocks.
	// Zero takes DefaultFundingTimeoutBlocks.
	TimeoutBlocks uint64
	// IndexerLagBlocks is the margin past timeout_height before a send that
	// is not found counts as lost. Zero takes DefaultIndexerLagBlocks.
	IndexerLagBlocks uint64
	// Memo is the memo of every send. Empty takes DefaultFundingMemo.
	Memo string
}

// WithDefaults fills the zero fields.
func (c FunderConfig) WithDefaults() FunderConfig {
	if c.TimeoutBlocks == 0 {
		c.TimeoutBlocks = DefaultFundingTimeoutBlocks
	}
	if c.IndexerLagBlocks == 0 {
		c.IndexerLagBlocks = DefaultIndexerLagBlocks
	}
	if c.Memo == "" {
		c.Memo = DefaultFundingMemo
	}
	return c
}

// ValidateBasic checks the stateless fields.
func (c FunderConfig) ValidateBasic() error {
	switch {
	case c.GasLimit == 0:
		return errors.New("railtx: zero gas limit")
	case c.TimeoutBlocks == 0 || c.TimeoutBlocks > MaxFundingTimeoutBlocks:
		return fmt.Errorf("railtx: timeout blocks %d outside 1..%d", c.TimeoutBlocks, MaxFundingTimeoutBlocks)
	case len(c.Memo) > maxMemoBytes:
		return errors.New("railtx: memo too long")
	}
	return nil
}

// Funder sends plain bank transfers from one key, one at a time. A send that
// might still be included blocks the next one: a lost send never gets a
// second transaction while it could still land.
type Funder struct {
	rail    *Rail
	cons    node.Consensus
	consent *Consent
	addr    string
	prefix  string
	cfg     FunderConfig

	mu      sync.Mutex
	pending *pendingSend
}

type pendingSend struct {
	hash          [32]byte
	timeoutHeight uint64
}

// NewFunder validates cfg, loads the key and reads the signer's address.
func NewFunder(ctx context.Context, cfg FunderConfig) (*Funder, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if cfg.Consensus == nil {
		return nil, errors.New("railtx: nil consensus")
	}
	if cfg.Consent == nil {
		return nil, errors.New("railtx: nil consent")
	}
	r, err := newRail(cfg.Consensus, nil, cfg.Key, cfg.GasLimit, cfg.Fee)
	if err != nil {
		return nil, err
	}
	prefix, err := cfg.Consensus.Bech32Prefix(ctx)
	if err != nil {
		return nil, fmt.Errorf("railtx: bech32 prefix: %w", err)
	}
	addr, err := bech32.ConvertAndEncode(prefix, r.key.PubKey().Address())
	if err != nil {
		return nil, fmt.Errorf("railtx: address: %w", err)
	}
	return &Funder{rail: r, cons: cfg.Consensus, consent: cfg.Consent, addr: addr, prefix: prefix, cfg: cfg}, nil
}

// String never shows the key.
func (*Funder) String() string { return "railtx.Funder" }

// GoString never shows the key.
func (*Funder) GoString() string { return "railtx.Funder" }

// Address is the funder's bech32 address.
func (f *Funder) Address() string { return f.addr }

// Pending reports the send that has not been seen resolved, if any.
func (f *Funder) Pending() (hash [32]byte, timeoutHeight uint64, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == nil {
		return [32]byte{}, 0, false
	}
	return f.pending.hash, f.pending.timeoutHeight, true
}

// Status is the node's view of hash.
func (f *Funder) Status(ctx context.Context, hash [32]byte) (node.TxStatus, error) {
	st, err := f.cons.Tx(ctx, hash)
	if err != nil {
		return node.TxStatus{}, fmt.Errorf("railtx: status: %w", err)
	}
	return st, nil
}

// Send broadcasts one MsgSend of amount in the bond denom to the address to,
// with timeout_height set, and returns its hash and timeout height. It fails
// with ErrNotStarted until the Consent is armed, before any read of the node,
// and with ErrSendInFlight while the previous send could still land.
func (f *Funder) Send(ctx context.Context, to string, amount uint64) (hash [32]byte, timeoutHeight uint64, err error) {
	if err := f.consent.Check(); err != nil {
		return hash, 0, err
	}
	if amount == 0 {
		return hash, 0, errors.New("railtx: zero amount")
	}
	if hrp, raw, derr := bech32.DecodeAndConvert(to); derr != nil || hrp != f.prefix || len(raw) != 20 {
		return hash, 0, fmt.Errorf("%w: %q", ErrBadRecipient, to)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.settlePending(ctx); err != nil {
		return hash, 0, err
	}
	chainID, err := f.cons.Network(ctx)
	if err != nil {
		return hash, 0, fmt.Errorf("railtx: network: %w", err)
	}
	denom, err := f.cons.BondDenom(ctx)
	if err != nil {
		return hash, 0, fmt.Errorf("railtx: bond denom: %w", err)
	}
	head, err := f.cons.LatestHeight(ctx)
	if err != nil {
		return hash, 0, fmt.Errorf("railtx: height: %w", err)
	}
	timeoutHeight = head + f.cfg.TimeoutBlocks
	body := fundingBody(f.addr, to, denom, amount, f.cfg.Memo, timeoutHeight)
	raw, err := f.rail.Sign(ctx, body, chainID, f.cfg.Fee)
	if err != nil {
		return hash, 0, err
	}
	hash = sha256.Sum256(raw)
	// Recorded before the broadcast: an unclear outcome (timeout, dropped
	// connection) may still have reached the mempool.
	f.pending = &pendingSend{hash: hash, timeoutHeight: timeoutHeight}
	if err := f.consent.Check(); err != nil {
		f.pending = nil
		return hash, 0, err
	}
	if err := f.rail.Broadcast(ctx, raw); err != nil {
		if errors.Is(err, ErrRejected) || errors.Is(err, ErrSequenceMismatch) {
			f.pending = nil
		}
		return hash, 0, err
	}
	return hash, timeoutHeight, nil
}

// settlePending clears the previous send if it is committed or can no longer
// be included, and refuses otherwise. The node's height is read before the
// lookup, so a send included at or before that height is seen.
func (f *Funder) settlePending(ctx context.Context) error {
	p := f.pending
	if p == nil {
		return nil
	}
	st, err := f.cons.Tx(ctx, p.hash)
	if err != nil {
		return fmt.Errorf("%w: status: %w", ErrSendInFlight, err)
	}
	if st.Found || st.NodeHeight > p.timeoutHeight+f.cfg.IndexerLagBlocks {
		f.pending = nil
		return nil
	}
	return fmt.Errorf("%w: %x, includable until height %d", ErrSendInFlight, p.hash, p.timeoutHeight)
}

// fundingBody encodes TxBody{messages: [MsgSend], memo, timeout_height}.
func fundingBody(from, to, denom string, amount uint64, memo string, timeoutHeight uint64) []byte {
	var coin []byte
	coin = appendBytes(coin, 1, []byte(denom))
	coin = appendBytes(coin, 2, []byte(strconv.FormatUint(amount, 10)))
	var msg []byte
	msg = appendBytes(msg, 1, []byte(from))
	msg = appendBytes(msg, 2, []byte(to))
	msg = appendBytes(msg, 3, coin)
	var a []byte
	a = appendBytes(a, 1, []byte(msgSendURL))
	a = appendBytes(a, 2, msg)
	var body []byte
	body = appendBytes(body, 1, a)
	if memo != "" {
		body = appendBytes(body, 2, []byte(memo))
	}
	body = protowire.AppendTag(body, 3, protowire.VarintType)
	return protowire.AppendVarint(body, timeoutHeight)
}
