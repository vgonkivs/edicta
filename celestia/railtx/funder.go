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
	// ErrSettled means Send cleared the previous send and sent nothing. The
	// amount the caller computed may predate that send's inclusion, so the
	// caller must read balances again and call Send again.
	ErrSettled = errors.New("railtx: previous send settled, nothing sent; re-read balances")
	// ErrStaleSequence means the node answered a sequence at or below one the
	// funder has already seen used; nothing was sent.
	ErrStaleSequence = errors.New("railtx: node reports a sequence already used")
	// ErrSequenceBound means a send cleared without proof must be followed by
	// one signed with the same sequence, and the node offered another.
	ErrSequenceBound = errors.New("railtx: next send must reuse the cleared sequence")
	// ErrNothingToAbandon means there is no pending send or sequence binding.
	ErrNothingToAbandon = errors.New("railtx: nothing to abandon")
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

	release func()

	mu      sync.Mutex
	pending *pendingSend
	// mustReuse is the sequence of a send cleared without being seen
	// committed. The next send must be signed with it, so at most one of the
	// two can ever be included, whatever the node said.
	mustReuse *uint64
	// lastCommitted is the highest sequence seen used on chain. A send is
	// never signed at or below it.
	lastCommitted *uint64
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

// pendingFile is the whole persisted state. The pending fields are empty when
// nothing is pending; the two sequence guards outlive the send they came from.
type pendingFile struct {
	Hash          string  `json:"hash,omitempty"`
	From          string  `json:"from"`
	To            string  `json:"to,omitempty"`
	Amount        uint64  `json:"amount,omitempty"`
	Sequence      uint64  `json:"sequence,omitempty"`
	TimeoutHeight uint64  `json:"timeout_height,omitempty"`
	MustReuse     *uint64 `json:"must_reuse_sequence,omitempty"`
	LastCommitted *uint64 `json:"last_committed_sequence,omitempty"`
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
	if err := checkStateDir(filepath.Dir(cfg.PendingPath)); err != nil {
		return nil, err
	}
	release, err := lockState(cfg.PendingPath)
	if err != nil {
		return nil, fmt.Errorf("%w: lock: %w", ErrPendingState, err)
	}
	f := &Funder{rail: r, cons: cfg.Consensus, consent: cfg.Consent, addr: addr, prefix: prefix, cfg: cfg, release: release}
	if f.pending, f.mustReuse, f.lastCommitted, err = loadState(cfg.PendingPath, addr); err != nil {
		release()
		return nil, err
	}
	return f, nil
}

// Close releases the lock on the state file. The Funder must not be used
// afterwards.
func (f *Funder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.release != nil {
		f.release()
		f.release = nil
	}
	return nil
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

// Settle resolves the previous send without sending anything. It reports
// whether a pending send was cleared; with an error the send stays pending.
// Callers should settle before reading the balances a send amount is
// computed from, so a send that has just committed is counted.
func (f *Funder) Settle(ctx context.Context) (cleared bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == nil {
		return false, nil
	}
	if err := f.settlePending(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Send broadcasts one MsgSend of amount in the bond denom to the address to,
// with timeout_height set, and returns its hash and timeout height. It fails
// with ErrNotStarted until the Consent is armed, before any read of the node,
// and with ErrSendInFlight while the previous send could still land. When
// this call clears the previous send it sends nothing and returns ErrSettled.
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
	if f.pending != nil {
		if err := f.settlePending(ctx); err != nil {
			return hash, 0, err
		}
		return hash, 0, ErrSettled
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
	switch {
	case f.lastCommitted != nil && seq <= *f.lastCommitted:
		return hash, 0, fmt.Errorf("%w: node says %d, %d is used", ErrStaleSequence, seq, *f.lastCommitted)
	case f.mustReuse != nil && seq != *f.mustReuse:
		return hash, 0, fmt.Errorf("%w: node says %d, need %d", ErrSequenceBound, seq, *f.mustReuse)
	}
	hash = sha256.Sum256(txRaw)
	if err := f.consent.Check(); err != nil {
		return hash, 0, err
	}
	p := &pendingSend{hash: hash, sequence: seq, timeoutHeight: th, to: to, amount: amount}
	// Durable before the broadcast: an unclear outcome (timeout, dropped
	// connection, a crash) may still have reached the mempool. The pending
	// record covers the sequence, so the binding is dropped with it.
	if err := saveState(f.cfg.PendingPath, f.addr, p, nil, f.lastCommitted); err != nil {
		return hash, 0, err
	}
	f.pending, f.mustReuse = p, nil
	if err := f.rail.Broadcast(ctx, txRaw); err != nil {
		if errors.Is(err, ErrRejected) {
			if cerr := f.resolve(false); cerr != nil {
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
//
// A sequence that moved past the signed one is resolved only by finding the
// transaction that used the slot: our own means committed, another means ours
// can never be included.
func (f *Funder) settlePending(ctx context.Context) error {
	p := f.pending
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
			return f.resolve(true)
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
			return f.slotUsed(ctx, p, proofHeight, acc.Sequence)
		default:
			return inFlight(fmt.Errorf("account sequence %d at %d is below the signed %d", acc.Sequence, proofHeight, p.sequence))
		}
	}
	return f.resolve(false)
}

// slotUsed handles a pending send whose sequence was used by some transaction.
func (f *Funder) slotUsed(ctx context.Context, p *pendingSend, proofHeight, now uint64) error {
	advanced := func(detail string) error {
		return fmt.Errorf("%w: %x, signed with sequence %d, account at %d is at %d%s: %w",
			ErrSendInFlight, p.hash, p.sequence, proofHeight, now, detail, ErrSequenceAdvanced)
	}
	txs, err := f.cons.TxBySequence(ctx, f.addr, p.sequence)
	if err != nil {
		return advanced(fmt.Sprintf(" (sequence lookup: %v)", err))
	}
	for _, t := range txs {
		// Ours means committed; any other holds the slot, and there is one
		// transaction per sequence, so ours can never be included.
		if t.Height > 0 {
			return f.resolve(true)
		}
	}
	return advanced("")
}

// resolve drops the pending send and records what the next send must respect.
// A send seen committed, or whose slot another transaction holds, raises the
// floor under later sequences. A send cleared without that evidence binds the
// next one to the same sequence. The state is written before memory changes.
func (f *Funder) resolve(used bool) error {
	p := f.pending
	last, must := f.lastCommitted, f.mustReuse
	s := p.sequence
	if used {
		if last == nil || *last < s {
			last = &s
		}
		must = nil
	} else {
		must = &s
	}
	if err := saveState(f.cfg.PendingPath, f.addr, nil, must, last); err != nil {
		return err
	}
	f.pending, f.mustReuse, f.lastCommitted = nil, must, last
	return nil
}

// Abandon is the operator's decision to stop waiting for a send that cannot be
// resolved by evidence. It needs an armed Consent and is appended to
// PendingPath + ".log". It works in two cases only: the pending send's
// sequence has moved on past its timeout (the slot is used, perhaps by this
// very send), or a sequence binding is left while the chain has moved past
// it. Anything that can still land, or that settles by itself, is refused.
func (f *Funder) Abandon(ctx context.Context) error {
	if err := f.consent.Check(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.pending != nil:
		p := f.pending
		err := f.settlePending(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrSequenceAdvanced) {
			return err
		}
		if lerr := f.logAbandon(fmt.Sprintf("pending hash=%x sequence=%d timeout_height=%d to=%s amount=%d", p.hash, p.sequence, p.timeoutHeight, p.to, p.amount)); lerr != nil {
			return lerr
		}
		return f.resolve(true)
	case f.mustReuse != nil:
		head, err := f.cons.LatestHeight(ctx)
		if err != nil {
			return fmt.Errorf("railtx: height: %w", err)
		}
		acc, err := f.cons.AccountAt(ctx, f.addr, head)
		if err != nil {
			return fmt.Errorf("railtx: account at %d: %w", head, err)
		}
		if acc.Sequence <= *f.mustReuse {
			return fmt.Errorf("%w: the bound sequence %d is still free", ErrNothingToAbandon, *f.mustReuse)
		}
		s := *f.mustReuse
		if lerr := f.logAbandon(fmt.Sprintf("binding sequence=%d account_sequence=%d", s, acc.Sequence)); lerr != nil {
			return lerr
		}
		last := f.lastCommitted
		if last == nil || *last < s {
			last = &s
		}
		if err := saveState(f.cfg.PendingPath, f.addr, nil, nil, last); err != nil {
			return err
		}
		f.mustReuse, f.lastCommitted = nil, last
		return nil
	}
	return ErrNothingToAbandon
}

func (f *Funder) logAbandon(what string) error {
	fh, err := os.OpenFile(f.cfg.PendingPath+".log", os.O_WRONLY|os.O_APPEND|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return fmt.Errorf("%w: log: %w", ErrPendingState, err)
	}
	_, err = fmt.Fprintf(fh, "%s abandon %s\n", time.Now().UTC().Format(time.RFC3339), what)
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%w: log: %w", ErrPendingState, err)
	}
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

func saveState(path, from string, p *pendingSend, mustReuse, lastCommitted *uint64) (err error) {
	pf := pendingFile{From: from, MustReuse: mustReuse, LastCommitted: lastCommitted}
	if p != nil {
		pf.Hash, pf.To, pf.Amount = hex.EncodeToString(p.hash[:]), p.to, p.amount
		pf.Sequence, pf.TimeoutHeight = p.sequence, p.timeoutHeight
	}
	data, err := json.Marshal(pf)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	fh, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	tmp := fh.Name()
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

// checkStateDir refuses a directory another user could write to or swap
// files in.
func checkStateDir(dir string) error {
	fi, err := os.Stat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", ErrPendingState, err)
	case !fi.IsDir():
		return fmt.Errorf("%w: %s is not a directory", ErrPendingState, dir)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%w: %s is writable by others", ErrPendingState, dir)
	case !ownedByCaller(fi):
		return fmt.Errorf("%w: %s belongs to another user", ErrPendingState, dir)
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

// loadState reads the file left by an earlier run. A file that is
// unreadable, loose in mode, foreign, malformed or for another key is an
// error: the funder cannot know what it sent, so it sends nothing.
func loadState(path, from string) (p *pendingSend, mustReuse, lastCommitted *uint64, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ownedByCaller(fi) {
		return nil, nil, nil, fmt.Errorf("%w: %s must be a regular file of this user with mode 0600", ErrPendingState, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	var pf pendingFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrPendingState, err)
	}
	if pf.From != from {
		return nil, nil, nil, fmt.Errorf("%w: the file is for %s, not %s", ErrPendingState, pf.From, from)
	}
	if pf.Hash == "" {
		if pf.TimeoutHeight != 0 {
			return nil, nil, nil, fmt.Errorf("%w: timeout height without a send", ErrPendingState)
		}
		return nil, pf.MustReuse, pf.LastCommitted, nil
	}
	h, err := hex.DecodeString(pf.Hash)
	switch {
	case err != nil || len(h) != 32:
		return nil, nil, nil, fmt.Errorf("%w: bad hash", ErrPendingState)
	case pf.TimeoutHeight == 0 || pf.TimeoutHeight > math.MaxInt64:
		return nil, nil, nil, fmt.Errorf("%w: timeout height out of range", ErrPendingState)
	}
	p = &pendingSend{sequence: pf.Sequence, timeoutHeight: pf.TimeoutHeight, to: pf.To, amount: pf.Amount}
	copy(p.hash[:], h)
	return p, pf.MustReuse, pf.LastCommitted, nil
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
