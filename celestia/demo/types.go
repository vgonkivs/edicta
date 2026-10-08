package demo

import (
	"context"
	"math/big"
	"time"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
)

// Funding is the part of *railtx.Funder the funding loop uses. It has no
// abandon method on purpose.
type Funding interface {
	Address() string
	Settle(ctx context.Context) (cleared bool, err error)
	Send(ctx context.Context, to string, amount uint64) (hash [32]byte, timeoutHeight uint64, err error)
	Status(ctx context.Context, hash [32]byte) (node.TxStatus, error)
	Pending() (hash [32]byte, timeoutHeight uint64, ok bool)
	Guards() (floor, binding *uint64)
	Close() error
}

// Abandoner is held only by offerAbandon, which calls it only after the
// operator typed the exact target.
type Abandoner interface {
	Abandon(ctx context.Context, hash [32]byte) error
	AbandonBinding(ctx context.Context, seq uint64) error
}

// Chain is the read side, all on the single funding node.
type Chain interface {
	ChainID(ctx context.Context) (string, error)
	// Head is the node's height and the time of its latest block.
	Head(ctx context.Context) (height uint64, t time.Time, err error)
	// BalanceAt reads at max(minHeight, head), pinned and echoed by the node.
	BalanceAt(ctx context.Context, addr, denom string, minHeight uint64) (amount, height uint64, err error)
	MinGasPrice(ctx context.Context) (gasPrice *big.Rat, err error)
	TxIndex(ctx context.Context) error
}

// Answer is what the operator chose at a prompt.
type Answer int

const (
	AnswerContinue Answer = iota + 1
	AnswerQuit
)

// Console is the operator's keyboard.
type Console interface {
	// Flush drops pending input. It is called before the cap and start
	// prompts so that a queued Enter cannot answer them.
	Flush() error
	// WaitEnter returns on an Enter or on q. Nothing else answers it.
	WaitEnter(ctx context.Context, prompt string) (Answer, error)
	// Passphrase reads without echo.
	Passphrase(prompt string) (secret.Secret, error)
	// Confirm is true only if the operator typed want exactly.
	Confirm(ctx context.Context, prompt, want string) (bool, error)
	// ReadLine reads one echoed line.
	ReadLine(ctx context.Context, prompt string) (string, error)
}

// Screen is what the operator sees.
type Screen interface {
	Step(n, of int, title string)
	OK(line string, kv ...any)
	Info(line string, kv ...any)
	Warn(line string, kv ...any)
	Fail(line string, err error)
	Wait(line, progress string)
	TrustRoot(t TrustRootInfo)
	Check(c CheckLine)
	Verdict(v VerifyResult)
	Attempt(a AttemptResult)
	Layer(n int, title string)
	// Mandate shows the rendered mandate text the gate enforces.
	Mandate(text string)
}

// TrustRootInfo is the header the verifier is anchored to.
type TrustRootInfo struct {
	Height uint64
	Hash   []byte
	Source string // the trust-root name, "--trusted-header" or "manual input"
	Link   string
}

// Verdict is the verifier's overall result.
type Verdict string

const (
	VerdictValid         Verdict = "valid"
	VerdictInvalid       Verdict = "invalid"
	VerdictInconclusive  Verdict = "inconclusive"
	VerdictNotAuthorized Verdict = "not_authorized"
	// VerdictGateIntegrity is the verifier exit 5: the gate signed
	// contradicting verdicts.
	VerdictGateIntegrity Verdict = "gate_integrity_violated"
)

// CheckLine is one verifier check.
type CheckLine struct {
	Check  string
	Status string // pass | fail | unchecked
	Reason string
	Source string
	Detail string
	Advice string
}

// VerifyResult is one run of the verifier.
type VerifyResult struct {
	Code        int
	Verdict     Verdict
	Checks      []CheckLine
	TrustRoot   TrustRootInfo
	Assumptions []string
	Command     []string
	Retries     int
}

// AttemptResult is one cheating attempt.
type AttemptResult struct {
	Layer      int
	Name       string
	Expected   string
	Got        string
	AsExpected bool
	Why        string
	Skipped    bool
}

// FundingSend is one funding send the run made.
type FundingSend struct {
	Hash          string `json:"hash"`
	To            string `json:"to"`
	Amount        uint64 `json:"amount"`
	TimeoutHeight uint64 `json:"timeout_height"`
	Height        uint64 `json:"height,omitempty"`
}

// Outcome is everything a run produced.
type Outcome struct {
	Code           int
	RunDir         string
	CommitmentHash commitment.Hash
	AnchorHeight   uint64
	TxHash         string
	TxHeight       uint64
	Verify         VerifyResult
	Attempts       []AttemptResult
	Funding        []FundingSend
}
