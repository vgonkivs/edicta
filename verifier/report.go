package verifier

import (
	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

type Verdict string

const (
	VerdictValid         Verdict = "valid"
	VerdictInvalid       Verdict = "invalid"
	VerdictUnchecked     Verdict = "unchecked"
	VerdictNotAuthorized Verdict = "not_authorized"
)

type Status string

const (
	StatusPass      Status = "pass"
	StatusFail      Status = "fail"
	StatusUnchecked Status = "unchecked"
)

type CheckName string

const (
	CheckDecision      CheckName = "decision"
	CheckEnvelope      CheckName = "envelope"
	CheckAction        CheckName = "action"
	CheckAuthorization CheckName = "authorization"
	CheckPayload       CheckName = "payload"
	CheckAnchor        CheckName = "anchor"
	CheckAnchorTime    CheckName = "anchor_time"
	CheckHeaderTrust   CheckName = "header_trust"
	CheckReceipt       CheckName = "receipt"
	CheckRetention     CheckName = "retention_replay"
	CheckExecution     CheckName = "execution"
	CheckPolicy        CheckName = "policy"
)

// Check is one named step. Err is set for a failed step and, for an
// unchecked one, says why it was not done. An unchecked step carries one
// Reason of the closed set, and the sources it blames, if any.
type Check struct {
	Name    CheckName
	Status  Status
	Err     error
	Reason  Reason
	Sources []string
}

type TrustStatus string

const (
	TrustValid     TrustStatus = "valid"
	TrustUnchecked TrustStatus = "unchecked"
	TrustFailed    TrustStatus = "failed"
)

// HeaderTrustReport carries the trusted header and the cross-check result
// whatever the status is, also when the trust failed or could not run.
type HeaderTrustReport struct {
	Status         TrustStatus
	CheckpointH    uint64
	CheckpointHash []byte
	CrossCheck     string
	// Hashes are the header hashes the anchor relied on, by height.
	Hashes map[uint64][]byte
}

type AuthorizationInfo struct {
	Version      uint64
	Mode         uint64 // v1 only: strict or fast
	Path         commitment.PayloadPath
	Expires      uint64
	AuthorizedAt uint64
}

// CertReport is the availability certificate of a da = 1 anchor.
type CertReport struct {
	SignedPower    int64
	TotalPower     int64
	SignedShare    float64
	QuorumWarning  bool
	TokenPrecision string
	ValsetHeader   string
}

// ReceiptInfo is the gate's attestation of a rail reference. The gate
// attests the integrator's claim; execution is not proven.
type ReceiptInfo struct {
	RailRef         string
	RecordedAt      uint64
	GateAttested    bool
	ProvenExecution bool
}

// ExecutionInfo is what the rail checker established about the transaction
// the receipt names.
type ExecutionInfo struct {
	RailRef    string
	Height     uint64
	HeaderHash []byte
	BlockTime  uint64
	Inclusion  string
	Outcome    string
	Result     string
	CrossCheck string
	Sources    []ExecutionSource
}

// IntegrityStatus says whether the gate contradicted itself.
type IntegrityStatus string

const (
	IntegrityOK         IntegrityStatus = "ok"
	IntegrityViolated   IntegrityStatus = "violated"
	IntegrityNotChecked IntegrityStatus = "not_checked"
	IntegrityUnchecked  IntegrityStatus = "unchecked"
)

// GateIntegrity is not a check: it records whether gate-signed verdicts
// contradict each other. Reason is ReasonGateEquivocation when violated and
// the reason of the missing data when unchecked. Evidence holds the
// contradicting SignedPolicyVerdict bytes, EvidenceHashes their verdict hashes.
type GateIntegrity struct {
	Status         IntegrityStatus
	Reason         Reason
	Evidence       [][]byte
	EvidenceHashes []commitment.Hash
	// Walk is set when the integrity walk ran, whatever the status.
	Walk *WalkInfo
}

// WalkEnd says why the integrity walk stopped.
type WalkEnd string

const (
	WalkEndGenesis  WalkEnd = "genesis"
	WalkEndMaxSteps WalkEnd = "max_steps"
	WalkEndFinding  WalkEnd = "finding"
)

// WalkInfo describes what the integrity walk read. Steps counts the verdicts
// before the target that were read and passed every check, so
// ToSeq-FromSeq == Steps. Total is the chain length the target's signed
// state claims.
type WalkInfo struct {
	MaxSteps, Steps uint64
	FromSeq, ToSeq  uint64
	Total           uint64
	End             WalkEnd
	// SeqPrivate: the walk read private verdicts without the key, so the
	// sequence numbers and FromSeq, ToSeq and Total are unknown.
	SeqPrivate bool
}

// PolicyInfo is what the policy check learned about the allow.
type PolicyInfo struct {
	MandateHash          commitment.Hash
	MandateID            []byte
	Version, Seq         uint64
	Principal            []byte
	AnchorTime, EvalTime uint64
	Facts                policy.Facts
	ExtractorID          string
	PrevStateHash        commitment.Hash
	NewStateHash         commitment.Hash
	// Denials are the reasons of the policy deny records of this decision;
	// ErrDecisionAge is marked gate-attested.
	Denials []string
	// MandateRef compares a v1 decision's mandate_ref with the allow's
	// mandate hash: match or absent, empty for a v0 decision and on a
	// mismatch, which the check reports as its fail.
	MandateRef MandateRefStatus
	// Mode is public or private; AuditorKid is the kid of the auditor key
	// that opened a private mandate, printed as its fingerprint.
	Mode       PolicyMode
	AuditorKid []byte
}

// PolicyMode says whether the mandate publishes its rules.
type PolicyMode string

const (
	PolicyModePublic  PolicyMode = "public"
	PolicyModePrivate PolicyMode = "private"
)

// ActionSource is the record the verified action bytes were read from.
type ActionSource string

const (
	ActionSourceDecisionRecord ActionSource = "decision_record"
	ActionSourcePrivateBlob    ActionSource = "private_blob"
	ActionSourceReveal         ActionSource = "reveal"
)

// MandateRefStatus is how a v1 decision's mandate_ref relates to the mandate
// the gate allowed it under.
type MandateRefStatus string

const (
	MandateRefMatch    MandateRefStatus = "match"
	MandateRefMismatch MandateRefStatus = "mismatch"
	MandateRefAbsent   MandateRefStatus = "absent"
)

type Report struct {
	Verdict        Verdict
	CommitmentHash commitment.Hash
	State          archive.State
	Rejections     []string
	// AuthorizationVerified is true only for an authorized record whose
	// Authorization verified. It says nothing about the other checks; the
	// verdict does.
	AuthorizationVerified bool
	// Params are the retention and skew parameters the verification used.
	Params         commitment.Params
	DA             commitment.DA
	Height         uint64
	BlockTime      uint64
	RetentionStart uint64
	GateID         string
	ActionType     string
	// ActionSource names the record the action bytes came from; empty when
	// the action check did not pass.
	ActionSource ActionSource
	Settlement   string
	// AnchorProofForm and AnchorCandidatesEarlier are set for da = 1.
	AnchorProofForm         int
	AnchorCandidatesEarlier int
	Authorization           *AuthorizationInfo
	Cert                    *CertReport
	Receipt                 *ReceiptInfo
	Execution               *ExecutionInfo
	Policy                  *PolicyInfo
	GateIntegrity           GateIntegrity
	HeaderTrust             HeaderTrustReport
	Checks                  []Check
	Warnings                []string
}

// Check returns the step with this name.
func (r Report) Check(name CheckName) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

// K2Replay is the retention rule recomputed from the archived inputs.
type K2Replay struct {
	Replayable     bool
	Reason         string
	R              uint64
	Start          uint64
	Margin         uint64
	Within         bool
	Route          commitment.PayloadPath
	AuthorizedPath commitment.PayloadPath
	Consistent     bool
	Err            error
}

type ReplayReport struct {
	Report Report
	K2     K2Replay
}
