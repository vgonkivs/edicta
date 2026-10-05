package railtx

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// Sentinel errors.
var (
	// ErrFeeAboveMax means the configured fee exceeds the caller's cap.
	ErrFeeAboveMax = errors.New("railtx: fee above max fee")
	// ErrChainMismatch means the action's chain id is empty or differs from the node's.
	ErrChainMismatch = errors.New("railtx: chain id mismatch")
	// ErrSignerMismatch means the signing key is not the MsgSend sender.
	ErrSignerMismatch = errors.New("railtx: signer is not the msg sender")
	// ErrBadBody means the body is not a TxBody carrying only MsgSend messages.
	ErrBadBody = errors.New("railtx: bad tx body")
	// ErrSequenceMismatch means the node refused the broadcast because the
	// account sequence differs; it is not a success.
	ErrSequenceMismatch = errors.New("railtx: account sequence mismatch")
	// ErrRejected means the node checked the transaction and refused it; the
	// message keeps the node's code and log. It is final, never indeterminate.
	ErrRejected = transfer.ErrRejected
	// ErrTxIndexDisabled means the status node does not report that it indexes
	// transactions; every lookup would answer "not found".
	ErrTxIndexDisabled = node.ErrTxIndexDisabled
	// ErrIndeterminate means the outcome is unknown (timeout, cancelled
	// context, unreachable node); callers must fail closed.
	ErrIndeterminate = errors.New("railtx: outcome indeterminate")
)

const (
	msgSendURL     = "/cosmos.bank.v1beta1.MsgSend"
	pubKeyURL      = "/cosmos.crypto.secp256k1.PubKey"
	signModeDirect = 1
	recentHeaders  = 10
)

// Config configures a Rail.
type Config struct {
	Consensus node.Consensus
	Reader    node.Reader
	Key       KeySource
	// GasLimit is attached to every transaction; it must be nonzero.
	GasLimit uint64
	// Fee is the fee in base units of the bond denom.
	Fee uint64
}

// Rail is a transfer.Rail over the node seam.
type Rail struct {
	cons node.Consensus
	rd   node.Reader
	key  *secp256k1.PrivKey
	pub  []byte
	gas  uint64
	fee  uint64
}

var _ transfer.Rail = (*Rail)(nil)

// New validates cfg and loads the key.
func New(cfg Config) (*Rail, error) {
	switch {
	case cfg.Consensus == nil:
		return nil, errors.New("railtx: nil consensus")
	case cfg.Reader == nil:
		return nil, errors.New("railtx: nil reader")
	case cfg.GasLimit == 0:
		return nil, errors.New("railtx: zero gas limit")
	}
	sk, err := cfg.Key.load()
	if err != nil {
		return nil, err
	}
	return &Rail{cons: cfg.Consensus, rd: cfg.Reader, key: sk, pub: sk.PubKey().Bytes(),
		gas: cfg.GasLimit, fee: cfg.Fee}, nil
}

// String never shows the key.
func (*Rail) String() string { return "railtx.Rail" }

// GoString never shows the key.
func (*Rail) GoString() string { return "railtx.Rail" }

func (r *Rail) address(ctx context.Context) (string, error) {
	hrp, err := r.cons.Bech32Prefix(ctx)
	if err != nil {
		return "", fmt.Errorf("railtx: bech32 prefix: %w", err)
	}
	a, err := bech32.ConvertAndEncode(hrp, r.key.PubKey().Address())
	if err != nil {
		return "", fmt.Errorf("railtx: address: %w", err)
	}
	return a, nil
}

// Address is the signer's bech32 address.
func (r *Rail) Address(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return r.address(ctx)
}

// Domain reports the node's chain id, bond denom and prefix, and the signer.
func (r *Rail) Domain(ctx context.Context) (transfer.Domain, error) {
	if err := ctx.Err(); err != nil {
		return transfer.Domain{}, err
	}
	id, err := r.cons.Network(ctx)
	if err != nil {
		return transfer.Domain{}, fmt.Errorf("railtx: network: %w", err)
	}
	denom, err := r.cons.BondDenom(ctx)
	if err != nil {
		return transfer.Domain{}, fmt.Errorf("railtx: bond denom: %w", err)
	}
	hrp, err := r.cons.Bech32Prefix(ctx)
	if err != nil {
		return transfer.Domain{}, fmt.Errorf("railtx: bech32 prefix: %w", err)
	}
	a, err := bech32.ConvertAndEncode(hrp, r.key.PubKey().Address())
	if err != nil {
		return transfer.Domain{}, fmt.Errorf("railtx: address: %w", err)
	}
	return transfer.Domain{ChainID: id, Denom: denom, HRP: hrp, Sender: a}, nil
}

// Head returns the head height, its Unix time and the largest block interval
// among the most recent headers.
func (r *Rail) Head(ctx context.Context) (uint64, uint64, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, 0, err
	}
	head, err := r.rd.Head(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("railtx: head: %w", err)
	}
	var largest time.Duration
	later := head
	for i := uint64(1); i <= recentHeaders && i < head.Height; i++ {
		h, err := r.rd.HeaderAt(ctx, head.Height-i)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("railtx: header %d: %w", head.Height-i, err)
		}
		largest = max(largest, later.Time.Sub(h.Time))
		later = h
	}
	if largest <= 0 {
		return 0, 0, 0, fmt.Errorf("railtx: block interval unknown at height %d: %w", head.Height, node.ErrNotFound)
	}
	return head.Height, uint64(head.Time.Unix()), largest, nil
}

// Height returns the latest height of the consensus node that answers Status.
func (r *Rail) Height(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	h, err := r.cons.LatestHeight(ctx)
	if err != nil {
		return 0, fmt.Errorf("railtx: height: %w", err)
	}
	return h, nil
}

// CheckTxIndex refuses a status node that does not report its transaction
// index as on. A node that cannot be asked counts as off.
func (r *Rail) CheckTxIndex(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := r.cons.TxIndex(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTxIndexDisabled):
		return fmt.Errorf("railtx: %w", err)
	default:
		return fmt.Errorf("railtx: %w: %w", ErrTxIndexDisabled, err)
	}
}

// Sign returns the TxRaw for body, whose bytes go into body_bytes unchanged.
// It refuses a fee above maxFee, a chain id other than the node's, a body that
// is not MsgSend-only and a sender other than the signing key.
func (r *Rail) Sign(ctx context.Context, body []byte, chainID string, maxFee uint64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.fee > maxFee {
		return nil, fmt.Errorf("%w: fee %d, max %d", ErrFeeAboveMax, r.fee, maxFee)
	}
	net, err := r.cons.Network(ctx)
	if err != nil {
		return nil, fmt.Errorf("railtx: network: %w", err)
	}
	if chainID == "" || chainID != net {
		return nil, fmt.Errorf("%w: action %q, node %q", ErrChainMismatch, chainID, net)
	}
	sender, err := msgSender(body)
	if err != nil {
		return nil, err
	}
	addr, err := r.address(ctx)
	if err != nil {
		return nil, err
	}
	if sender != addr {
		return nil, fmt.Errorf("%w: sender %q, signer %q", ErrSignerMismatch, sender, addr)
	}
	denom, err := r.cons.BondDenom(ctx)
	if err != nil {
		return nil, fmt.Errorf("railtx: bond denom: %w", err)
	}
	acc, err := r.cons.Account(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("railtx: account %s: %w", addr, err)
	}
	authInfo := r.authInfo(denom, acc.Sequence)

	var doc []byte
	doc = appendBytes(doc, 1, body)
	doc = appendBytes(doc, 2, authInfo)
	doc = appendBytes(doc, 3, []byte(chainID))
	doc = appendVarint(doc, 4, acc.Number)
	sig, err := r.key.Sign(doc)
	if err != nil {
		return nil, fmt.Errorf("railtx: sign: %w", err)
	}
	var raw []byte
	raw = appendBytes(raw, 1, body)
	raw = appendBytes(raw, 2, authInfo)
	raw = appendBytes(raw, 3, sig)
	return raw, nil
}

// authInfo encodes AuthInfo{signer_infos: [{public_key, DIRECT, sequence}],
// fee: {amount, gas_limit}} in field order, omitting proto3 zero values.
func (r *Rail) authInfo(denom string, sequence uint64) []byte {
	var pk []byte
	pk = appendBytes(pk, 1, r.pub)
	var any []byte
	any = appendBytes(any, 1, []byte(pubKeyURL))
	any = appendBytes(any, 2, pk)
	var single []byte
	single = appendVarint(single, 1, signModeDirect)
	var mode []byte
	mode = appendBytes(mode, 1, single)
	var si []byte
	si = appendBytes(si, 1, any)
	si = appendBytes(si, 2, mode)
	si = appendVarint(si, 3, sequence)

	var fee []byte
	if r.fee > 0 {
		var coin []byte
		coin = appendBytes(coin, 1, []byte(denom))
		coin = appendBytes(coin, 2, []byte(strconv.FormatUint(r.fee, 10)))
		fee = appendBytes(fee, 1, coin)
	}
	fee = appendVarint(fee, 2, r.gas)

	var ai []byte
	ai = appendBytes(ai, 1, si)
	ai = appendBytes(ai, 2, fee)
	return ai
}

func appendBytes(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func appendVarint(b []byte, num protowire.Number, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = protowire.AppendTag(b, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

// msgSender checks body is a TxBody (messages, memo, timeout_height only)
// whose messages are all MsgSend from one sender, and returns that sender.
func msgSender(body []byte) (string, error) {
	var sender string
	var nMsgs int
	var sawMemo, sawTimeout bool
	for rest := body; len(rest) > 0; {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return "", fmt.Errorf("%w: tag", ErrBadBody)
		}
		rest = rest[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(rest)
			if n < 0 {
				return "", fmt.Errorf("%w: message", ErrBadBody)
			}
			rest = rest[n:]
			s, err := anySender(v)
			if err != nil {
				return "", err
			}
			if nMsgs > 0 && s != sender {
				return "", fmt.Errorf("%w: messages with different senders", ErrBadBody)
			}
			sender, nMsgs = s, nMsgs+1
		case num == 2 && typ == protowire.BytesType && !sawMemo:
			_, n := protowire.ConsumeBytes(rest)
			if n < 0 {
				return "", fmt.Errorf("%w: memo", ErrBadBody)
			}
			rest, sawMemo = rest[n:], true
		case num == 3 && typ == protowire.VarintType && !sawTimeout:
			_, n := protowire.ConsumeVarint(rest)
			if n < 0 {
				return "", fmt.Errorf("%w: timeout_height", ErrBadBody)
			}
			rest, sawTimeout = rest[n:], true
		default:
			return "", fmt.Errorf("%w: unexpected field %d", ErrBadBody, num)
		}
	}
	if nMsgs == 0 {
		return "", fmt.Errorf("%w: no message", ErrBadBody)
	}
	return sender, nil
}

// anySender parses an Any holding a MsgSend and returns from_address.
func anySender(a []byte) (string, error) {
	var url string
	var val []byte
	var sawURL, sawVal bool
	for rest := a; len(rest) > 0; {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 || typ != protowire.BytesType || (num != 1 && num != 2) {
			return "", fmt.Errorf("%w: any", ErrBadBody)
		}
		v, m := protowire.ConsumeBytes(rest[n:])
		if m < 0 {
			return "", fmt.Errorf("%w: any", ErrBadBody)
		}
		rest = rest[n+m:]
		switch {
		case num == 1 && !sawURL:
			url, sawURL = string(v), true
		case num == 2 && !sawVal:
			val, sawVal = v, true
		default:
			return "", fmt.Errorf("%w: any repeats a field", ErrBadBody)
		}
	}
	if url != msgSendURL {
		return "", fmt.Errorf("%w: message type %q is not MsgSend", ErrBadBody, url)
	}
	var from string
	var sawFrom bool
	for rest := val; len(rest) > 0; {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return "", fmt.Errorf("%w: msg send", ErrBadBody)
		}
		rest = rest[n:]
		m := protowire.ConsumeFieldValue(num, typ, rest)
		if m < 0 {
			return "", fmt.Errorf("%w: msg send", ErrBadBody)
		}
		if num == 1 {
			if typ != protowire.BytesType || sawFrom {
				return "", fmt.Errorf("%w: from_address", ErrBadBody)
			}
			v, _ := protowire.ConsumeBytes(rest)
			from, sawFrom = string(v), true
		}
		rest = rest[m:]
	}
	if from == "" {
		return "", fmt.Errorf("%w: empty from_address", ErrBadBody)
	}
	return from, nil
}

// Broadcast sends txRaw unchanged. "Already in mempool" is success; a
// sequence mismatch is not.
func (r *Rail) Broadcast(ctx context.Context, txRaw []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrIndeterminate, err)
	}
	if len(txRaw) == 0 {
		return fmt.Errorf("%w: empty tx", ErrBadBody)
	}
	_, err := r.cons.Broadcast(ctx, txRaw)
	switch {
	case err == nil, errors.Is(err, node.ErrAlreadyInMempool):
		return nil
	case errors.Is(err, node.ErrSequenceMismatch):
		return fmt.Errorf("%w: %w", ErrSequenceMismatch, err)
	case errors.Is(err, node.ErrRejected):
		return fmt.Errorf("%w: %w", ErrRejected, err)
	default:
		return fmt.Errorf("%w: %w", ErrIndeterminate, err)
	}
}

// Status maps the node's view of hash. Errors are never "not found".
func (r *Rail) Status(ctx context.Context, hash [32]byte) (transfer.TxStatus, error) {
	if err := ctx.Err(); err != nil {
		return transfer.TxStatus{}, fmt.Errorf("%w: %w", ErrIndeterminate, err)
	}
	s, err := r.cons.Tx(ctx, hash)
	if err != nil {
		return transfer.TxStatus{}, fmt.Errorf("%w: %w", ErrIndeterminate, err)
	}
	switch {
	case !s.Found:
		return transfer.TxStatus{State: transfer.TxUnknown, NodeHeight: s.NodeHeight}, nil
	case s.Height == 0:
		return transfer.TxStatus{State: transfer.TxPending, NodeHeight: s.NodeHeight}, nil
	default:
		return transfer.TxStatus{State: transfer.TxCommitted, Height: s.Height, Code: s.Code, NodeHeight: s.NodeHeight}, nil
	}
}

// DefaultFeeMargin is the safety factor DeriveFee applies on the node's
// minimum gas price: 1.2.
var DefaultFeeMargin = big.NewRat(6, 5)

// GasPriceSource reports the node's minimum gas price in bond denom per gas
// unit. node.Consensus satisfies it.
type GasPriceSource interface {
	MinGasPrice(ctx context.Context) (*big.Rat, error)
}

// DeriveFee returns ceil(gasLimit x price x margin) in base units, with exact
// arithmetic. A nil or zero margin means DefaultFeeMargin.
func DeriveFee(ctx context.Context, src GasPriceSource, gasLimit uint64, margin *big.Rat) (uint64, error) {
	if gasLimit == 0 {
		return 0, errors.New("railtx: zero gas limit")
	}
	if margin == nil || margin.Sign() == 0 {
		margin = DefaultFeeMargin
	}
	if margin.Sign() < 0 {
		return 0, errors.New("railtx: negative fee margin")
	}
	price, err := src.MinGasPrice(ctx)
	if err != nil {
		return 0, fmt.Errorf("railtx: min gas price: %w", err)
	}
	if price == nil || price.Sign() < 0 {
		return 0, errors.New("railtx: invalid minimum gas price")
	}
	fee := new(big.Rat).SetInt(new(big.Int).SetUint64(gasLimit))
	fee.Mul(fee, price)
	fee.Mul(fee, margin)
	n := new(big.Int).Quo(new(big.Int).Add(fee.Num(), new(big.Int).Sub(fee.Denom(), big.NewInt(1))), fee.Denom())
	if !n.IsUint64() {
		return 0, errors.New("railtx: derived fee overflows")
	}
	return n.Uint64(), nil
}
