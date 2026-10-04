// Package sdk is the agent side of Edicta: it turns a decision into a sealed,
// published payload and a signed DecisionCommitment that the gate accepts, and
// lets a recipient open a payload again.
//
// The SDK never imports the gate. Its Clock, ChainParams and Committer
// interfaces have the gate's method sets, so one node client or one committer
// can serve both.
package sdk

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk/blob"
)

var (
	ErrInvalidConfig         = errors.New("sdk: invalid configuration")
	ErrPublishResult         = errors.New("sdk: publisher returned an unusable result")
	ErrClockBehindAnchor     = errors.New("sdk: local clock behind the anchor block by more than skew")
	ErrValidityWindow        = errors.New("sdk: no usable validity window")
	ErrDACommitmentMismatch  = errors.New("sdk: DA commitment does not match the blob")
	ErrDACheckUnavailable    = errors.New("sdk: no DA commitment check for this da and no opt-out")
	ErrAlreadyFinalized      = errors.New("sdk: sealed payload already finalized")
	ErrSignerClosed          = errors.New("sdk: signer closed")
	ErrPlaintextHashMismatch = errors.New("sdk: plaintext_hash mismatch")
	ErrPayloadMismatch       = errors.New("sdk: payload action or constraints differ from the commitment")
)

type Publisher interface {
	// Publish submits blob byte-exact and returns after the anchor is included.
	// It never modifies blob.
	Publish(ctx context.Context, blob []byte) (Published, error)
}

type Published struct {
	Ref            commitment.PayloadRef // da, namespace, commitment, height, signer (da = 2)
	BlockTime      uint64                // header time of Ref.Height, Unix seconds
	RetentionStart uint64                // da = 1: payment promise creation time; 0 for da = 2
}

type Signer interface {
	PublicKey() ed25519.PublicKey
	// SignCommitment signs commitment.SigningMessage(h) and nothing else.
	SignCommitment(ctx context.Context, h commitment.Hash) ([]byte, error)
}

type Clock interface{ Now() time.Time }

type ChainParams interface {
	// FibreRetention has the contract of the gate's ChainParams: height 0 is
	// the latest value; for height > 0 it returns the value in force at that
	// height or an error, never the latest as a substitute.
	FibreRetention(ctx context.Context, height uint64) (uint64, error)
}

// Committer recomputes the DA commitment of blob and compares it with
// ref.Commitment.
type Committer interface {
	Check(ctx context.Context, ref commitment.PayloadRef, blob []byte) error
}

type shareV1Committer struct{}

func (shareV1Committer) Check(_ context.Context, ref commitment.PayloadRef, b []byte) error {
	return sharev1.Check(ref, b)
}

// ShareV1Committer is the default check for da = 2.
func ShareV1Committer() Committer { return shareV1Committer{} }

type Config struct {
	AgentID        string
	Scope          commitment.Scope
	Recipients     []blob.Recipient // 1..16
	TTLS           uint64           // an upper bound, never extended
	MinValidityS   uint64           // less remaining validity is refused; at least 60, zero means 60
	SkewS          uint64           // must equal the gate's
	BlobRetentionS uint64           // must equal the gate's
	MaxBlobSize    uint64

	// CallTimeout bounds every call to the Publisher, ChainParams, Committer
	// and Signer, on top of the caller's own context. Zero means the default;
	// negative is invalid. It is a context deadline: it only ends calls to
	// dependencies that honour their context.
	CallTimeout time.Duration

	// UnsafeSkipDACheck lists the da values for which Finalize signs WITHOUT
	// recomputing the DA commitment from the blob. Empty by default.
	UnsafeSkipDACheck []commitment.DA
}

const (
	minValidityFloorS  = 60
	defaultCallTimeout = 60 * time.Second
)

// OpenerParams are the commitment parameters OpenPayload checks against. An
// opener works after the fact and has no chain view, so only the absolute ttl
// cap applies, whatever retention a gate had at the time.
func OpenerParams() commitment.Params {
	return commitment.Params{FibreRetentionS: math.MaxInt64, BlobRetentionS: math.MaxInt64, SkewS: 30}
}

func DefaultConfig() Config {
	return Config{
		TTLS:           900,
		MinValidityS:   60,
		SkewS:          30,
		BlobRetentionS: 14400,
		MaxBlobSize:    blob.MaxSealSize,
		CallTimeout:    defaultCallTimeout,
	}
}

type Deps struct {
	Publisher Publisher
	Signer    Signer
	Clock     Clock
	// Chain is required when the publisher may return da = 1.
	Chain ChainParams
	// Committers adds checks per da. For da 2 the built-in recompute always
	// runs first and cannot be replaced; UnsafeSkipDACheck switches it off.
	Committers map[commitment.DA]Committer
}
