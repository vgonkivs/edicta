// Package verifier re-checks an archived decision without trusting the
// archive: the envelope, the action bytes, the Authorization, the payload,
// the anchor evidence and the headers it hangs from. It reports what it
// checked and what it could not; a missing header trust is never "valid".
//
// The package has no chain dependency. The DA-specific anchor proof and the
// header trust come in through AnchorVerifier and HeaderTrust.
package verifier

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

var (
	ErrInvalidConfig        = errors.New("verifier: invalid config")
	ErrDecisionNotFound     = errors.New("verifier: decision not found")
	ErrEnvelopeInvalid      = errors.New("verifier: envelope invalid")
	ErrActionInvalid        = errors.New("verifier: action bytes are not the committed ones")
	ErrAuthorizationInvalid = errors.New("verifier: authorization invalid")
	ErrGateKeyNotTrusted    = errors.New("verifier: authorization signature verifies under no configured gate key")
	ErrPayloadInvalid       = errors.New("verifier: payload invalid")
	ErrAnchorInvalid        = errors.New("verifier: anchor invalid")
	ErrArchiveIncomplete    = errors.New("verifier: archive record missing or unreadable")
	ErrHeaderTrust          = errors.New("verifier: header trust failed")
	ErrReceiptInvalid       = errors.New("verifier: receipt invalid")
	ErrAnchorUnsupported    = errors.New("verifier: no anchor verifier for this da")
	ErrGateInconsistent     = errors.New("verifier: gate result contradicts the recorded inputs")
	// ErrTrustInput marks a header trust that could not run for lack of
	// auditor input (checkpoint too low, chain too long, headers not
	// available). The decision is then unchecked, not invalid.
	ErrTrustInput = errors.New("verifier: header trust input is insufficient")

	ErrExecutionInvalid = errors.New("verifier: on-chain execution does not match the authorized action")
	// ErrExecutionUnchecked marks a checker error that means no fact was
	// established, as opposed to one that proves a violation.
	ErrExecutionUnchecked = errors.New("verifier: execution could not be checked")
	// ErrExecutionViolation marks a checker error that proves a violation from
	// verified facts. Any other checker error is a source problem.
	ErrExecutionViolation = errors.New("verifier: proven violation of the authorized action")

	// The proven violations the outcome rule itself finds.
	ErrExecutionChain        = errors.New("verifier: chain id mismatch")
	ErrExecutionBeforeAnchor = errors.New("verifier: the transaction is not after the anchor")
	ErrExecutionFailed       = errors.New("verifier: transaction failed on chain")
	// ErrExecutionResultUnconfirmed is the cause of an unchecked execution
	// with a nonzero code that no result proof confirms.
	ErrExecutionResultUnconfirmed = fmt.Errorf("verifier: nonzero result code is not confirmed: %w", ErrExecutionUnchecked)
)

// Inclusion, result and cross-check levels of the execution facts.
const (
	InclusionProven       = "proven"
	InclusionNodeAttested = "node-attested"

	OutcomeSuccess = "success"
	OutcomeFailure = "failure"

	ResultProven         = "proven"
	ResultCrossConfirmed = "cross-confirmed"
	ResultNodeAttested   = "node-attested"

	CrossPass        = "pass"
	CrossMismatch    = "mismatch"
	CrossUnavailable = "unavailable"
	CrossOff         = "off"
)

// Roles and results of one tx source in the execution report.
const (
	RolePrimary   = "primary"
	RoleAlternate = "alternate"
	RoleCross     = "cross"

	SourceUsed     = "used"
	SourceSetAside = "set_aside"
	SourceAgree    = "agree"
	SourceDisagree = "disagree"
	SourceFault    = "fault"
)

// ExecutionInput is what a rail checker is given. Action is the archived
// action bytes, the ones the action check matched.
type ExecutionInput struct {
	CommitmentHash commitment.Hash
	ActionType     string
	Action         []byte
	RailRef        string
	// AnchorHeight is payload_ref.height, so that a checker can classify the
	// order of the anchor and the transaction.
	AnchorHeight uint64
}

// ExecutionSource is one tx source a checker asked: its role, what became of
// its answer and why.
type ExecutionSource struct {
	Name   string
	Role   string
	Result string
	Reason Reason
	Detail string
}

// ExecutionFacts are what a checker established about the rail transaction.
// A checker that has a used answer returns the facts together with an error
// when the answer itself shows a problem; the report then still carries what
// was learned.
type ExecutionFacts struct {
	Height     uint64
	HeaderHash []byte
	BlockTime  uint64
	// Inclusion is InclusionProven or InclusionNodeAttested.
	Inclusion string
	// Outcome is the result code as success or failure. Result says what
	// binds it: ResultProven (a result proof against the trusted chain),
	// ResultCrossConfirmed or ResultNodeAttested.
	Outcome string
	Result  string
	// ResultProblem says why the result proof failed although the inclusion
	// is proven (root mismatch, index unbound, header unreachable); nil when
	// it holds or could not be tried.
	ResultProblem error
	// ChainMismatch: the block at Height belongs to another chain than the
	// one the action names.
	ChainMismatch bool
	CrossCheck    string
	Sources       []ExecutionSource
}

// ExecutionChecker is a rail profile's check of the transaction named by a
// receipt. An error wrapping ErrExecutionViolation proves a violation; every
// other error is a source problem and gives at most an unchecked result. An
// error may carry a ReasonError.
type ExecutionChecker interface {
	CheckExecution(ctx context.Context, in ExecutionInput) (ExecutionFacts, error)
}

// Config is what the verifier needs to know about the gate it audits.
type Config struct {
	Params   commitment.Params
	GateKeys []ed25519.PublicKey
}

// ValidateBasic checks the fields that need no dependency.
func (c Config) ValidateBasic() error {
	if err := c.Params.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if len(c.GateKeys) == 0 {
		return fmt.Errorf("%w: no gate keys", ErrInvalidConfig)
	}
	for i, k := range c.GateKeys {
		if err := commitment.CheckPublicKey(k); err != nil {
			return fmt.Errorf("%w: gate key %d: %w", ErrInvalidConfig, i, err)
		}
		for _, o := range c.GateKeys[:i] {
			if string(o) == string(k) {
				return fmt.Errorf("%w: gate key %d repeats an earlier key", ErrInvalidConfig, i)
			}
		}
	}
	return nil
}

// AnchorFacts are what an anchor verifier established from the evidence
// alone. The certificate and settlement fields are set for da = 1.
type AnchorFacts struct {
	BlockTime      uint64
	RetentionStart uint64
	// AnchorHeaderHash is the hash of the header at the decision's height.
	AnchorHeaderHash []byte
	// PromiseHeaderHash, PromiseHeight and PromiseBlobSize describe the
	// payment promise (da = 1). The promise height never exceeds the anchor
	// height; the two headers are checked through header trust separately.
	PromiseHeaderHash  []byte
	PromiseHeight      uint64
	PromiseBlobSize    uint64
	CertSignedPower    int64
	CertTotalPower     int64
	CertTokenPrecision string
	CertValsetHeader   string
	Settlement         string
	// ProofForm is the form of the archived anchor proof (da = 1): 1 for
	// namespace data and DAH, 0 for the system blob commitment proof.
	ProofForm int
	// CandidatesEarlier counts the other candidates with an earlier promise
	// creation time than the archived anchor (da = 1, form 1).
	CandidatesEarlier int
	// EarlierCreations are the promise creation times of those candidates.
	EarlierCreations []uint64
}

// AnchorVerifier checks the anchor evidence of one da against the headers
// inside the evidence. It does not decide whether those headers are the
// chain's; header trust does.
type AnchorVerifier interface {
	VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (AnchorFacts, error)
}

// HeaderTrust ties a header hash to the chain.
type HeaderTrust interface {
	Trusted(ctx context.Context, height uint64, hash []byte) (TrustResult, error)
}

// TrustResult says what was established. CrossCheck is "pass", "mismatch",
// "unavailable" or "off".
type TrustResult struct {
	Checked        bool
	CheckpointH    uint64
	CheckpointHash []byte
	CrossCheck     string
}

// Reader is the read side of an archive.
type Reader interface {
	Payload(ctx context.Context, da commitment.DA, commit []byte) (*archive.PayloadRecord, error)
	Evidence(ctx context.Context, da commitment.DA, commit []byte) (*archive.EvidenceRecord, error)
	Decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error)
	Authorization(ctx context.Context, h commitment.Hash) (*archive.AuthorizationRecord, error)
	State(ctx context.Context, h commitment.Hash) (archive.DecisionState, error)
}

// Deps are the verifier's collaborators. A nil Trust means header trust is
// not checked.
type Deps struct {
	Config     Config
	Archive    Reader
	Committers map[commitment.DA]gate.DACommitter
	Anchors    map[commitment.DA]AnchorVerifier
	Trust      HeaderTrust
	// Executions are the rail checkers by action type.
	Executions map[string]ExecutionChecker
}

type Verifier struct {
	cfg        Config
	archive    Reader
	committers map[commitment.DA]gate.DACommitter
	anchors    map[commitment.DA]AnchorVerifier
	trust      HeaderTrust
	executions map[string]ExecutionChecker
}

func New(d Deps) (*Verifier, error) {
	if err := d.Config.ValidateBasic(); err != nil {
		return nil, err
	}
	if d.Archive == nil {
		return nil, fmt.Errorf("%w: no archive", ErrInvalidConfig)
	}
	if len(d.Committers) == 0 {
		return nil, fmt.Errorf("%w: no DA committers", ErrInvalidConfig)
	}
	if len(d.Anchors) == 0 {
		return nil, fmt.Errorf("%w: no anchor verifiers", ErrInvalidConfig)
	}
	v := &Verifier{
		cfg:        Config{Params: d.Config.Params},
		archive:    d.Archive,
		committers: make(map[commitment.DA]gate.DACommitter, len(d.Committers)),
		anchors:    make(map[commitment.DA]AnchorVerifier, len(d.Anchors)),
		trust:      d.Trust,
	}
	for da, c := range d.Committers {
		if c == nil {
			return nil, fmt.Errorf("%w: nil committer for da %d", ErrInvalidConfig, da)
		}
		v.committers[da] = c
	}
	for da, a := range d.Anchors {
		if a == nil {
			return nil, fmt.Errorf("%w: nil anchor verifier for da %d", ErrInvalidConfig, da)
		}
		v.anchors[da] = a
	}
	v.executions = make(map[string]ExecutionChecker, len(d.Executions))
	for t, c := range d.Executions {
		if c == nil {
			return nil, fmt.Errorf("%w: nil execution checker for %q", ErrInvalidConfig, t)
		}
		v.executions[t] = c
	}
	for _, k := range d.Config.GateKeys {
		v.cfg.GateKeys = append(v.cfg.GateKeys, append(ed25519.PublicKey(nil), k...))
	}
	return v, nil
}
