package verifier

import (
	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
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
)

// Check is one named step. Err is set for a failed step and, for an
// unchecked one, says why it was not done.
type Check struct {
	Name   CheckName
	Status Status
	Err    error
}

type TrustStatus string

const (
	TrustValid     TrustStatus = "valid"
	TrustUnchecked TrustStatus = "unchecked"
	TrustFailed    TrustStatus = "failed"
)

// HeaderTrustReport carries the trusted header and the cross-check result
// whatever the status is.
type HeaderTrustReport struct {
	Status         TrustStatus
	CheckpointH    uint64
	CheckpointHash []byte
	CrossCheck     string
	// Hashes are the header hashes the anchor relied on, by height.
	Hashes map[uint64][]byte
}

type AuthorizationInfo struct {
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

type Report struct {
	Verdict        Verdict
	CommitmentHash commitment.Hash
	State          archive.State
	Rejections     []string
	// Authorized is true only for an authorized record whose Authorization
	// verified.
	Authorized     bool
	DA             commitment.DA
	Height         uint64
	BlockTime      uint64
	RetentionStart uint64
	GateID         string
	ActionType     string
	Settlement     string
	Authorization  *AuthorizationInfo
	Cert           *CertReport
	Receipt        *ReceiptInfo
	HeaderTrust    HeaderTrustReport
	Checks         []Check
	Warnings       []string
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
