package railtx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	txtypes "github.com/cosmos/cosmos-sdk/types/tx"

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
	// ErrSelfSend means the recipient is the funder's own address.
	ErrSelfSend = errors.New("railtx: recipient is the funder")
	// ErrAmountAboveMax means the amount exceeds FunderConfig.MaxAmount.
	ErrAmountAboveMax = errors.New("railtx: amount above the per-send maximum")
	// ErrSequenceAdvanced means the funder's account sequence moved past the
	// pending send's, so the send may have been included even though no
	// lookup found it. It stays pending and the caller must decide.
	ErrSequenceAdvanced = errors.New("railtx: account sequence moved past the pending send")
	// ErrPendingState means the pending-send file cannot be read, trusted or
	// written; nothing is sent without it.
	ErrPendingState = errors.New("railtx: pending-send state")
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
	// MaxIndexerLagBlocks caps FunderConfig.IndexerLagBlocks.
	MaxIndexerLagBlocks = 100
	// DefaultConfirmDelay is the wait before the second lookup that must
	// agree before a send is cleared as lost.
	DefaultConfirmDelay = 2 * time.Second
	maxMemoBytes        = 256
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
	// MaxFee caps the fee of a send. The fee is the larger of Fee and the
	// node's minimum gas price times GasLimit, rounded up; a send whose fee
	// would exceed MaxFee is refused. Required, at least Fee.
	MaxFee uint64
	// MaxAmount is the largest amount of one send. Required.
	MaxAmount uint64
	// PendingPath is the file that holds the send between its signing and
	// its resolution, so a crash or a rerun cannot send the funds twice.
	// Required; the file is created with mode 0600 and its directory must
	// exist.
	PendingPath string
	// ConfirmDelay is the wait between the two lookups that must both show
	// a send as not landed. Zero takes DefaultConfirmDelay.
	ConfirmDelay time.Duration
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
	if c.ConfirmDelay == 0 {
		c.ConfirmDelay = DefaultConfirmDelay
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
	case c.IndexerLagBlocks > MaxIndexerLagBlocks:
		return fmt.Errorf("railtx: indexer lag %d above %d", c.IndexerLagBlocks, MaxIndexerLagBlocks)
	case c.ConfirmDelay < 0:
		return errors.New("railtx: negative confirm delay")
	case c.MaxAmount == 0:
		return errors.New("railtx: zero max amount")
	case c.MaxFee < c.Fee:
		return fmt.Errorf("railtx: max fee %d below fee %d", c.MaxFee, c.Fee)
	case c.PendingPath == "":
		return errors.New("railtx: no pending-send path")
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

// pendingSend is the part of a signed send needed to tell later whether it
// landed. sequence is the account sequence it was signed with.
type pendingSend struct {
	hash          [32]byte
	sequence      uint64
	timeoutHeight uint64
	to            string
	amount        uint64
}

type pendingFile struct {
	Hash          string `json:"hash"`
	From          string `json:"from"`
	To            string `json:"to"`
	Amount        uint64 `json:"amount"`
	Sequence      uint64 `json:"sequence"`
	TimeoutHeight uint64 `json:"timeout_height"`
}

// NewFunder validates cfg, loads the key, refuses a node that does not index
// transactions, reads the signer's address and reloads a send left pending
// by an earlier run. That send is resolved by the first Send.
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
	if err := r.CheckTxIndex(ctx); err != nil {
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
	f := &Funder{rail: r, cons: cfg.Consensus, consent: cfg.Consent, addr: addr, prefix: prefix, cfg: cfg}
	if f.pending, err = loadPending(cfg.PendingPath, addr); err != nil {
		return nil, err
	}
	return f, nil
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
//
// A nonzero timeout height returned with an error means the send may still
// land until that height; it stays pending and blocks the next Send until it
// is seen committed or provably cannot land.
func (f *Funder) Send(ctx context.Context, to string, amount uint64) (hash [32]byte, timeoutHeight uint64, err error) {
	if err := f.consent.Check(); err != nil {
		return hash, 0, err
	}
	if amount == 0 {
		return hash, 0, errors.New("railtx: zero amount")
	}
	if amount > f.cfg.MaxAmount {
		return hash, 0, fmt.Errorf("%w: %d > %d", ErrAmountAboveMax, amount, f.cfg.MaxAmount)
	}
	hrp, raw, derr := bech32.DecodeAndConvert(to)
	if derr != nil || hrp != f.prefix || len(raw) != 20 {
		return hash, 0, fmt.Errorf("%w: %q", ErrBadRecipient, to)
	}
	to, derr = bech32.ConvertAndEncode(f.prefix, raw)
	if derr != nil {
		return hash, 0, fmt.Errorf("%w: %q", ErrBadRecipient, to)
	}
	if to == f.addr {
		return hash, 0, ErrSelfSend
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
	fee, err := f.fee(ctx)
	if err != nil {
		return hash, 0, err
	}
	head, err := f.cons.LatestHeight(ctx)
	if err != nil {
		return hash, 0, fmt.Errorf("railtx: height: %w", err)
	}
	if head == 0 || head > math.MaxInt64-f.cfg.TimeoutBlocks {
		return hash, 0, fmt.Errorf("railtx: node height %d out of range", head)
	}
	th := head + f.cfg.TimeoutBlocks
	body := fundingBody(f.addr, to, denom, amount, f.cfg.Memo, th)
	rail := *f.rail
	rail.fee = fee
	txRaw, err := rail.Sign(ctx, body, chainID, f.cfg.MaxFee)
	if err != nil {
		return hash, 0, err
	}
	seq, err := signedSequence(txRaw)
	if err != nil {
		return hash, 0, err
	}
	hash = sha256.Sum256(txRaw)
	if err := f.consent.Check(); err != nil {
		return hash, 0, err
	}
	p := &pendingSend{hash: hash, sequence: seq, timeoutHeight: th, to: to, amount: amount}
	// Durable before the broadcast: an unclear outcome (timeout, dropped
	// connection, a crash) may still have reached the mempool.
	if err := savePending(f.cfg.PendingPath, f.addr, p); err != nil {
		return hash, 0, err
	}
	f.pending = p
	if err := f.rail.Broadcast(ctx, txRaw); err != nil {
		if errors.Is(err, ErrRejected) {
			if cerr := f.clearPending(); cerr != nil {
				return hash, th, errors.Join(err, cerr)
			}
			return hash, 0, err
		}
		return hash, th, err
	}
	return hash, th, nil
}

// fee is the larger of the configured fee and what the node's minimum gas
// price asks for the gas limit, refused above MaxFee.
func (f *Funder) fee(ctx context.Context) (uint64, error) {
	price, err := f.cons.MinGasPrice(ctx)
	if err != nil {
		return 0, fmt.Errorf("railtx: min gas price: %w", err)
	}
	need := new(big.Int).Mul(price.Num(), new(big.Int).SetUint64(f.cfg.GasLimit))
	q, m := new(big.Int).QuoRem(need, price.Denom(), new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() || q.Uint64() > f.cfg.MaxFee {
		return 0, fmt.Errorf("%w: the node asks %s, max %d", ErrFeeAboveMax, q, f.cfg.MaxFee)
	}
	return max(f.cfg.Fee, q.Uint64()), nil
}

// settlePending clears the previous send if it is committed or provably can no
// longer land, and refuses otherwise.
//
// Not found is never enough: the lookup may hit an index that lags or is off.
// The proof is the account sequence read at a height past the timeout. A
// transaction with the signed sequence cannot be included after its timeout
// height, so a sequence still equal to the signed one at such a height means
// the slot was never used. The read is pinned and must be echoed by the node,
// so a backend that has not reached the height cannot answer for it. The whole
// check must hold twice, ConfirmDelay apart.
func (f *Funder) settlePending(ctx context.Context) error {
	p := f.pending
	if p == nil {
		return nil
	}
	inFlight := func(err error) error {
		if err == nil {
			return fmt.Errorf("%w: %x, includable until height %d", ErrSendInFlight, p.hash, p.timeoutHeight)
		}
		return fmt.Errorf("%w: %x, includable until height %d: %w", ErrSendInFlight, p.hash, p.timeoutHeight, err)
	}
	if p.timeoutHeight == 0 || p.timeoutHeight > math.MaxInt64 {
		return inFlight(errors.New("timeout height out of range"))
	}
	proofHeight := p.timeoutHeight + f.cfg.IndexerLagBlocks + 1
	for round := 0; round < 2; round++ {
		if round > 0 {
			t := time.NewTimer(f.cfg.ConfirmDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				return inFlight(ctx.Err())
			case <-t.C:
			}
		}
		st, err := f.cons.Tx(ctx, p.hash)
		if err != nil {
			return inFlight(fmt.Errorf("status: %w", err))
		}
		if st.Found && st.Height > 0 {
			return f.clearPending()
		}
		if st.Found {
			return inFlight(errors.New("found without a block height"))
		}
		acc, err := f.cons.AccountAt(ctx, f.addr, proofHeight)
		if err != nil {
			return inFlight(fmt.Errorf("account at %d: %w", proofHeight, err))
		}
		switch {
		case acc.Sequence == p.sequence:
		case acc.Sequence > p.sequence:
			return fmt.Errorf("%w: %x, signed with sequence %d, account at %d is at %d: %w",
				ErrSendInFlight, p.hash, p.sequence, proofHeight, acc.Sequence, ErrSequenceAdvanced)
		default:
			return inFlight(fmt.Errorf("account sequence %d at %d is below the signed %d", acc.Sequence, proofHeight, p.sequence))
		}
	}
	return f.clearPending()
}

func (f *Funder) clearPending() error {
	if err := os.Remove(f.cfg.PendingPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: remove: %w", ErrPendingState, err)
	}
	if err := syncDir(filepath.Dir(f.cfg.PendingPath)); err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	f.pending = nil
	return nil
}

// signedSequence reads the sequence of the single signer of a TxRaw.
func signedSequence(txRaw []byte) (uint64, error) {
	var raw txtypes.TxRaw
	if err := raw.Unmarshal(txRaw); err != nil {
		return 0, fmt.Errorf("railtx: signed tx: %w", err)
	}
	var ai txtypes.AuthInfo
	if err := ai.Unmarshal(raw.AuthInfoBytes); err != nil {
		return 0, fmt.Errorf("railtx: signed auth info: %w", err)
	}
	if len(ai.SignerInfos) != 1 {
		return 0, fmt.Errorf("railtx: signed tx has %d signers", len(ai.SignerInfos))
	}
	return ai.SignerInfos[0].Sequence, nil
}

func savePending(path, from string, p *pendingSend) (err error) {
	data, err := json.Marshal(pendingFile{
		Hash: hex.EncodeToString(p.hash[:]), From: from, To: p.to, Amount: p.amount,
		Sequence: p.sequence, TimeoutHeight: p.timeoutHeight,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	tmp := path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = fh.Chmod(0o600); err == nil {
		_, err = fh.Write(data)
	}
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// loadPending reads the file left by an earlier run. A file that is
// unreadable, loose in mode, malformed or for another key is an error: the
// funder cannot know what it sent, so it sends nothing.
func loadPending(path, from string) (*pendingSend, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s must be a regular file with mode 0600", ErrPendingState, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	var pf pendingFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	h, err := hex.DecodeString(pf.Hash)
	switch {
	case err != nil || len(h) != 32:
		return nil, fmt.Errorf("%w: bad hash", ErrPendingState)
	case pf.From != from:
		return nil, fmt.Errorf("%w: the file is for %s, not %s", ErrPendingState, pf.From, from)
	case pf.TimeoutHeight == 0 || pf.TimeoutHeight > math.MaxInt64:
		return nil, fmt.Errorf("%w: timeout height out of range", ErrPendingState)
	}
	p := &pendingSend{sequence: pf.Sequence, timeoutHeight: pf.TimeoutHeight, to: pf.To, amount: pf.Amount}
	copy(p.hash[:], h)
	return p, nil
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
