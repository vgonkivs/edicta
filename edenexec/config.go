// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/edenescrow"
)

// Profile names the profile that defines the settlement report.
const Profile = "eden-escrow-v1"

// Level is how much of the settlement the report establishes; each includes
// the ones below. The zero Level is unset, so that a configuration that
// names none gets the default and L0 is only ever chosen explicitly.
type Level uint8

const (
	// LevelNodeAttested: one source's word.
	LevelNodeAttested Level = iota + 1
	// LevelMultiSource: MinSources distinct operators agree.
	LevelMultiSource
	// LevelReceiptProven: the block's transactions and receipts rebuild the
	// roots of a header the L1 operators attest.
	LevelReceiptProven
)

func (l Level) String() string {
	switch l {
	case LevelNodeAttested:
		return "L0"
	case LevelMultiSource:
		return "L1"
	case LevelReceiptProven:
		return "L2"
	}
	return fmt.Sprintf("L?%d", uint8(l))
}

// ParseLevel reads L0, L1 or L2.
func ParseLevel(s string) (Level, error) {
	for l := LevelNodeAttested; l <= LevelReceiptProven; l++ {
		if l.String() == s {
			return l, nil
		}
	}
	return 0, fmt.Errorf("edenexec: level %q is not L0, L1 or L2", s)
}

// SourceClass is who answers for a source.
type SourceClass uint8

const (
	// ClassPublicRPC: an RPC operator's word.
	ClassPublicRPC SourceClass = iota
	// ClassOwnNode: the operator's own node, which checks the sequencer's
	// signatures and re-executes the blocks.
	ClassOwnNode
)

func (c SourceClass) String() string {
	switch c {
	case ClassPublicRPC:
		return "public-rpc"
	case ClassOwnNode:
		return "own-node"
	}
	return fmt.Sprintf("class-%d", uint8(c))
}

// Source is one Eden JSON-RPC endpoint. A lookup of something the source
// does not have is ErrNotFound; any other failure is a source fault.
type Source interface {
	// Name is the normalized host. No two sources share one.
	Name() string
	Class() SourceClass
	ChainID(ctx context.Context) (uint64, error)
	Head(ctx context.Context) (uint64, error)
	Transaction(ctx context.Context, hash [32]byte) (TxView, error)
	Receipt(ctx context.Context, hash [32]byte) (ReceiptView, error)
	Header(ctx context.Context, blockHash [32]byte) (HeaderView, error)
	// BlockTransactions are the block's transactions, each as its EIP-2718
	// bytes, in block order.
	BlockTransactions(ctx context.Context, blockHash [32]byte) ([][]byte, error)
	// BlockReceipts are the consensus encodings of the block's receipts, in
	// block order.
	BlockReceipts(ctx context.Context, blockHash [32]byte) ([][]byte, error)
	// CodeHash is keccak256 of the code at addr in the latest block. Code
	// cannot change after creation, and pruned nodes keep only latest state.
	CodeHash(ctx context.Context, addr [20]byte) ([32]byte, error)
}

// Operated is a Source that names its operator. Two sources with one
// operator count once toward L1. The label is the configuration's
// statement; nothing here can check that two operators are independent.
type Operated interface {
	Operator() string
}

// OperatorOf is the source's operator label, or its host when it has none.
func OperatorOf(s Source) string {
	if o, ok := s.(Operated); ok {
		if op := o.Operator(); op != "" {
			return op
		}
	}
	return s.Name()
}

// DAStatus is the operator's own ev-node: whether a block's data is in
// Celestia. Report only; nothing proves it.
type DAStatus interface {
	Name() string
	DataDAHeight(ctx context.Context, height uint64) (celestiaHeight uint64, included bool, err error)
}

// Target is one decision's claim to check.
type Target struct {
	// Action is the decoded form T action whose bytes the decision committed.
	Action edenescrow.TxAction
	// RailRef is the receipt's rail_ref, as signed.
	RailRef string
	// Expires is the Authorization's expiry and TRef the decision's reference
	// time, unix seconds; TRef 0 is unknown.
	Expires uint64
	TRef    uint64
}

// NewTarget decodes the committed action bytes with this build's table. A
// failure is ErrActionRefused: nothing can be compared without the decoded
// action, and the bytes alone prove no executor fault.
func NewTarget(action []byte, railRef string, expires, tRef uint64) (Target, error) {
	a, err := edenescrow.DecodeTxAction(action)
	if err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrActionRefused, err)
	}
	return Target{Action: a, RailRef: railRef, Expires: expires, TRef: tRef}, nil
}

// Defaults.
const (
	DefaultMinLevel     = LevelMultiSource
	DefaultMinSources   = 2
	DefaultConfirmDepth = 20 // about 2 s of 100 ms blocks
	DefaultPollInterval = 500 * time.Millisecond
	DefaultAwaitGrace   = 300 * time.Second
)

// Bounds of the configuration.
const (
	MaxSources      = 16
	MaxConfirmDepth = 1_000_000
	MaxPollInterval = time.Minute
	MaxAwaitGrace   = 24 * time.Hour
)

// Config sets what a settlement report requires and how Await polls.
type Config struct {
	// MinLevel is the level a pass needs, and Await's level. Unset is L1:
	// one RPC operator's word is enough only when L0 is configured.
	MinLevel Level
	// MinSources is how many agreeing operators make L1, and how many
	// operators must answer not found before Await calls a transaction not
	// executed.
	MinSources int
	// ConfirmDepth is how many blocks must follow the transaction's. Eden's
	// safe and finalized tags equal the head, so they carry no weight.
	ConfirmDepth uint64
	PollInterval time.Duration
	// AwaitGrace is added to the deposit's expiresAt to bound Await.
	AwaitGrace time.Duration
}

// ApplyDefaults fills the zero fields.
func (c *Config) ApplyDefaults() {
	if c.MinLevel == 0 {
		c.MinLevel = DefaultMinLevel
	}
	if c.MinSources == 0 {
		c.MinSources = DefaultMinSources
	}
	if c.ConfirmDepth == 0 {
		c.ConfirmDepth = DefaultConfirmDepth
	}
	if c.PollInterval == 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.AwaitGrace == 0 {
		c.AwaitGrace = DefaultAwaitGrace
	}
}

// ValidateBasic checks the fields alone.
func (c Config) ValidateBasic() error {
	switch {
	case c.MinLevel < LevelNodeAttested || c.MinLevel > LevelReceiptProven:
		return fmt.Errorf("edenexec: config: level %d", c.MinLevel)
	case c.MinSources < 2 || c.MinSources > MaxSources:
		return fmt.Errorf("edenexec: config: MinSources %d is not in 2..%d", c.MinSources, MaxSources)
	case c.ConfirmDepth < 1 || c.ConfirmDepth > MaxConfirmDepth:
		return fmt.Errorf("edenexec: config: ConfirmDepth %d is not in 1..%d", c.ConfirmDepth, MaxConfirmDepth)
	case c.PollInterval <= 0 || c.PollInterval > MaxPollInterval:
		return fmt.Errorf("edenexec: config: PollInterval %v is not in (0, %v]", c.PollInterval, MaxPollInterval)
	case c.AwaitGrace <= 0 || c.AwaitGrace > MaxAwaitGrace:
		return fmt.Errorf("edenexec: config: AwaitGrace %v is not in (0, %v]", c.AwaitGrace, MaxAwaitGrace)
	}
	return nil
}

// AwaitUntil is the chain time after which a transaction not found is not
// executed: the deposit's expiresAt plus AwaitGrace. Past expiresAt the
// escrow refuses the deposit, so a later landing reverts.
func (c Config) AwaitUntil(t Target) time.Time {
	return time.Unix(int64(t.Action.Deposit.ExpiresAt), 0).Add(c.AwaitGrace)
}

// Operators is the number of distinct operators among srcs.
func Operators(srcs []Source) int {
	ops := map[string]bool{}
	for _, s := range srcs {
		if s != nil {
			ops[OperatorOf(s)] = true
		}
	}
	return len(ops)
}

// Checker runs the settlement rules against its sources.
type Checker struct {
	cfg  Config
	srcs []Source
	da   DAStatus

	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// NewChecker checks the configuration against the sources: at least one,
// each named and distinct by host. Fewer operators than the level needs is
// no error: such a checker still finds a wrong transaction, and its reports
// say the level was not reached.
func NewChecker(cfg Config, srcs []Source, da DAStatus) (*Checker, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if len(srcs) == 0 {
		return nil, errors.New("edenexec: no source")
	}
	if len(srcs) > MaxSources {
		return nil, fmt.Errorf("edenexec: %d sources, at most %d", len(srcs), MaxSources)
	}
	seen := map[string]bool{}
	for i, s := range srcs {
		if s == nil {
			return nil, fmt.Errorf("edenexec: source %d is nil", i)
		}
		if s.Name() == "" {
			return nil, fmt.Errorf("edenexec: source %d has no name", i)
		}
		if seen[s.Name()] {
			return nil, fmt.Errorf("edenexec: two sources on host %s", s.Name())
		}
		seen[s.Name()] = true
	}
	return &Checker{
		cfg: cfg, srcs: append([]Source(nil), srcs...), da: da,
		now: time.Now, sleep: sleepCtx,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
