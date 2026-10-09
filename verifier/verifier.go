// Package verifier re-checks an archived decision without trusting the
// archive: the envelope, the action bytes, the Authorization, the payload,
// the anchor evidence and the headers it hangs from. It reports what it
// checked and what it could not; a missing header trust is never "valid".
//
// The package has no chain dependency. The DA-specific anchor proof and the
// header trust come in through AnchorVerifier and HeaderTrust.
package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
	"github.com/vgonkivs/edicta/sdk/blob"
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

// SupportedPrincipalSchemes are the principal signature schemes this build
// verifies.
func SupportedPrincipalSchemes() []principalsig.Scheme {
	return []principalsig.Scheme{principalsig.Ed25519, principalsig.CosmosADR036, principalsig.EIP712}
}

// Config is what the verifier needs to know about the gate it audits.
type Config struct {
	Params   commitment.Params
	GateKeys []ed25519.PublicKey
	// PrincipalKeys are the mandate principals the auditor trusts, typed by
	// scheme (policy.ParsePrincipal); a pin matches only its own scheme.
	PrincipalKeys []policy.PrincipalID
	// PrincipalSchemes are the mandate signature schemes this verifier
	// accepts; empty means every scheme the build implements
	// (SupportedPrincipalSchemes). A mandate under another scheme leaves the
	// policy check unchecked with principal_scheme_unsupported.
	PrincipalSchemes []principalsig.Scheme
	// RequirePolicy states that the gate had a mandate: the policy check then
	// runs for every authorized decision, also when the archive holds no
	// allow record.
	RequirePolicy bool
	// PolicyFull also walks the verdict chain and searches for forks.
	PolicyFull bool
	// MaxWalkSteps caps the walk in steps; 0 means DefaultMaxWalkSteps. A
	// walk that takes the cap before genesis leaves gate_integrity unchecked.
	MaxWalkSteps int
	// Evidence are extra signed verdicts held by the auditor, for example
	// those agents received. They only ever serve as fork evidence.
	Evidence [][]byte
	// PayloadKeys are payload recipient keys the auditor holds. With one
	// that opens the payload, the payload check also checks the plaintext
	// hash and that the payload's action matches the committed one, and the
	// payload's action salt is compared with the archive copy's.
	PayloadKeys []blob.RecipientKey
	// AuditorKeys are X25519 keys of auditors of private mandates. With one
	// that opens the private records, the policy and action checks run on
	// the opened records exactly as in public mode.
	AuditorKeys []blob.RecipientKey
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
	for i, k := range c.PrincipalKeys {
		if err := k.Validate(); err != nil {
			return fmt.Errorf("%w: principal key %d: %w", ErrInvalidConfig, i, err)
		}
		if k.SigType != 0 {
			continue
		}
		for _, g := range c.GateKeys {
			if string(g) == string(k.Principal) {
				return fmt.Errorf("%w: principal key %d is a gate key", ErrInvalidConfig, i)
			}
		}
	}
	for i, s := range c.PrincipalSchemes {
		if !slices.Contains(SupportedPrincipalSchemes(), s) {
			return fmt.Errorf("%w: principal scheme %d (%s) is not in this build", ErrInvalidConfig, i, s)
		}
		if slices.Contains(c.PrincipalSchemes[:i], s) {
			return fmt.Errorf("%w: principal scheme %d repeats an earlier one", ErrInvalidConfig, i)
		}
	}
	for i, k := range c.AuditorKeys {
		pub := k.PublicKey()
		if pub == nil {
			return fmt.Errorf("%w: auditor key %d is not an X25519 private key", ErrInvalidConfig, i)
		}
		for _, o := range c.AuditorKeys[:i] {
			if bytes.Equal(o.PublicKey().Bytes(), pub.Bytes()) {
				return fmt.Errorf("%w: auditor key %d repeats an earlier key", ErrInvalidConfig, i)
			}
		}
	}
	if c.MaxWalkSteps < 0 {
		return fmt.Errorf("%w: negative walk step cap", ErrInvalidConfig)
	}
	for i, e := range c.Evidence {
		if len(e) == 0 || len(e) > 16384 {
			return fmt.Errorf("%w: evidence %d has %d bytes", ErrInvalidConfig, i, len(e))
		}
	}
	return nil
}

func (c Config) principalSchemeAccepted(s principalsig.Scheme) bool {
	if len(c.PrincipalSchemes) == 0 {
		return slices.Contains(SupportedPrincipalSchemes(), s)
	}
	return slices.Contains(c.PrincipalSchemes, s)
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
	// ProofForm is the form of the archived anchor proof (da = 1), always 1:
	// namespace data and DAH.
	ProofForm int
	// CandidatesEarlier counts the other candidates with an earlier promise
	// creation time than the archived anchor (da = 1).
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
	// Extractors serve the policy check. Without one for an action type,
	// the policy check of such a decision is unchecked.
	Extractors *policy.Extractors
}

type Verifier struct {
	cfg        Config
	archive    Reader
	committers map[commitment.DA]gate.DACommitter
	anchors    map[commitment.DA]AnchorVerifier
	trust      HeaderTrust
	executions map[string]ExecutionChecker
	extractors *policy.Extractors
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
		cfg: Config{
			Params: d.Config.Params, RequirePolicy: d.Config.RequirePolicy,
			PolicyFull: d.Config.PolicyFull, MaxWalkSteps: d.Config.MaxWalkSteps,
		},
		extractors: d.Extractors,
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
	for _, k := range d.Config.PrincipalKeys {
		v.cfg.PrincipalKeys = append(v.cfg.PrincipalKeys, policy.PrincipalID{SigType: k.SigType, Principal: bytes.Clone(k.Principal)})
	}
	v.cfg.PrincipalSchemes = slices.Clone(d.Config.PrincipalSchemes)
	for _, e := range d.Config.Evidence {
		v.cfg.Evidence = append(v.cfg.Evidence, bytes.Clone(e))
	}
	for _, k := range d.Config.PayloadKeys {
		k.KID = bytes.Clone(k.KID)
		v.cfg.PayloadKeys = append(v.cfg.PayloadKeys, k)
	}
	for _, k := range d.Config.AuditorKeys {
		k.KID = bytes.Clone(k.KID)
		v.cfg.AuditorKeys = append(v.cfg.AuditorKeys, k)
	}
	return v, nil
}
