package policy

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	OutcomeAllow = 1
	OutcomeDeny  = 2
)

type Verdict struct {
	Format             uint64 `cbor:"1,keyasint"`
	GateID             string `cbor:"2,keyasint"`
	MandateHash        []byte `cbor:"3,keyasint"`
	CommitmentHash     []byte `cbor:"4,keyasint"`
	ActionHash         []byte `cbor:"5,keyasint"`
	AgentPubKey        []byte `cbor:"6,keyasint"`
	Outcome            uint64 `cbor:"7,keyasint"`
	Reason             string `cbor:"8,keyasint,omitempty"`
	Extractor          string `cbor:"9,keyasint,omitempty"`
	Facts              *Facts `cbor:"10,keyasint,omitempty"`
	AnchorTime         uint64 `cbor:"11,keyasint,omitempty"`
	EvalTime           uint64 `cbor:"12,keyasint,omitempty"`
	PrevState          *State `cbor:"13,keyasint,omitempty"`
	NewStateHash       []byte `cbor:"14,keyasint,omitempty"`
	PrevCommitmentHash []byte `cbor:"15,keyasint,omitempty"`
	PrevVerdictHash    []byte `cbor:"16,keyasint,omitempty"`
	DecidedAt          uint64 `cbor:"17,keyasint,omitempty"`
	GateClock          uint64 `cbor:"18,keyasint,omitempty"`
	// PrivateHash is present iff the verdict is in private form: keys 8 to
	// 13, 17 and 18 are then in the PrivatePart it hashes.
	PrivateHash []byte `cbor:"19,keyasint,omitempty"`
	// BlindPrevStateHash is the blinded hash of the state an allow read,
	// private form only; the public form derives it from key 13.
	BlindPrevStateHash []byte `cbor:"20,keyasint,omitempty"`
}

type SignedVerdict struct {
	Verdict   Verdict `cbor:"1,keyasint"`
	Signature []byte  `cbor:"2,keyasint"`
}

func badVerdict(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerdictInvalid, fmt.Sprintf(format, a...))
}

// presence flags: which optional keys a verdict row carries.
type rowSpec struct{ extractor, facts, anchor, eval, prev bool }

func rowOf(v *Verdict) (rowSpec, error) {
	switch v.Reason {
	case "ErrAgentNotCovered", "ErrFastModeNotAllowed", "ErrNoExtractor":
		return rowSpec{}, nil
	case "ErrFactsInvalid":
		return rowSpec{extractor: true}, nil
	case "ErrOutsideMandate":
		if v.AnchorTime == 0 {
			return rowSpec{extractor: true, facts: true}, nil
		}
		return rowSpec{extractor: true, facts: true, anchor: true, prev: true}, nil
	case "ErrKindNotAllowed", "ErrAssetNotAllowed", "ErrRecipientNotAllowed", "ErrAmountAboveMax":
		return rowSpec{extractor: true, facts: true}, nil
	case "ErrDecisionAge":
		return rowSpec{extractor: true, facts: true, anchor: true}, nil
	case "ErrMinSpacing", "ErrPeriodLimit", "ErrCountLimit", "ErrHistoryFull":
		return rowSpec{extractor: true, facts: true, anchor: true, eval: true, prev: true}, nil
	}
	return rowSpec{}, badVerdict("reason %q", v.Reason)
}

// Validate checks the value and presence rules.
func (v *Verdict) Validate() error {
	if v == nil {
		return errNil
	}
	if v.Format != 1 {
		return fmt.Errorf("%w: format %d: %w", ErrVerdictInvalid, v.Format, commitment.ErrUnsupportedVersion)
	}
	if !validGateID(v.GateID) {
		return badVerdict("gate_id")
	}
	for name, h := range map[string][]byte{"mandate_hash": v.MandateHash, "commitment_hash": v.CommitmentHash,
		"action_hash": v.ActionHash, "agent_pubkey": v.AgentPubKey} {
		if err := checkHash(h, name); err != nil {
			return fmt.Errorf("%w: %w", ErrVerdictInvalid, err)
		}
	}
	for name, u := range map[string]uint64{"anchor_time": v.AnchorTime, "eval_time": v.EvalTime, "decided_at": v.DecidedAt} {
		if u > maxInt {
			return fmt.Errorf("%w: %s: %w", ErrVerdictInvalid, name, commitment.ErrIntRange)
		}
	}
	if v.Facts != nil {
		if err := v.Facts.Validate(); err != nil {
			return badVerdict("facts: %v", err)
		}
	}
	if v.PrevState != nil {
		if err := v.PrevState.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrVerdictInvalid, err)
		}
	}
	if v.Extractor != "" && (len(v.Extractor) > 64 || !extractorID.MatchString(v.Extractor)) {
		return badVerdict("extractor id")
	}
	hashes := map[string][]byte{"new_state_hash": v.NewStateHash, "prev_commitment_hash": v.PrevCommitmentHash,
		"prev_verdict_hash": v.PrevVerdictHash, "private_hash": v.PrivateHash, "prev_state_hash": v.BlindPrevStateHash}
	for name, h := range hashes {
		if h != nil {
			if err := checkHash(h, name); err != nil {
				return fmt.Errorf("%w: %w", ErrVerdictInvalid, err)
			}
		}
	}
	if v.Outcome != OutcomeAllow && v.Outcome != OutcomeDeny {
		return fmt.Errorf("%w: outcome %d: %w", ErrVerdictInvalid, v.Outcome, commitment.ErrInvalidEnum)
	}
	if v.PrivateHash != nil {
		return v.validatePrivateForm()
	}
	if v.BlindPrevStateHash != nil {
		return fmt.Errorf("%w: prev_state_hash in public form: %w", ErrVerdictInvalid, commitment.ErrUnknownKey)
	}
	if v.DecidedAt == 0 {
		return fmt.Errorf("%w: decided_at: %w", ErrVerdictInvalid, commitment.ErrMissingField)
	}
	switch v.Outcome {
	case OutcomeAllow:
		if v.Reason != "" || v.GateClock != 0 {
			return badVerdict("allow with a reason or gate_clock")
		}
		if v.Extractor == "" || v.Facts == nil || v.AnchorTime == 0 || v.EvalTime == 0 || v.PrevState == nil || v.NewStateHash == nil {
			return fmt.Errorf("%w: allow is missing a field: %w", ErrVerdictInvalid, commitment.ErrMissingField)
		}
		linked := v.PrevState.Seq >= 1
		if linked != (v.PrevCommitmentHash != nil) || linked != (v.PrevVerdictHash != nil) {
			return badVerdict("chain links and prev_state.seq disagree")
		}
	case OutcomeDeny:
		row, err := rowOf(v)
		if err != nil {
			return err
		}
		if (v.Extractor != "") != row.extractor || (v.Facts != nil) != row.facts || (v.AnchorTime != 0) != row.anchor ||
			(v.EvalTime != 0) != row.eval || (v.PrevState != nil) != row.prev {
			return badVerdict("presence of optional keys does not match reason %s", v.Reason)
		}
		if v.NewStateHash != nil || v.PrevCommitmentHash != nil || v.PrevVerdictHash != nil {
			return badVerdict("deny with allow-only keys")
		}
		if (v.Reason == "ErrDecisionAge") != (v.GateClock == 1) || (v.GateClock != 0 && v.GateClock != 1) {
			return badVerdict("gate_clock")
		}
	}
	return nil
}

// validatePrivateForm is the presence rule of the public part: every deny has
// keys 1 to 7 and 19 only, so no deny shows its reason, stage or state; an
// allow adds its blinded hashes and the chain links iff it did not read
// genesis.
func (v *Verdict) validatePrivateForm() error {
	if v.Reason != "" || v.Extractor != "" || v.Facts != nil || v.AnchorTime != 0 || v.EvalTime != 0 ||
		v.PrevState != nil || v.DecidedAt != 0 || v.GateClock != 0 {
		return fmt.Errorf("%w: private form with a key of the private part: %w", ErrVerdictInvalid, commitment.ErrUnknownKey)
	}
	if v.Outcome == OutcomeDeny {
		if v.NewStateHash != nil || v.PrevCommitmentHash != nil || v.PrevVerdictHash != nil || v.BlindPrevStateHash != nil {
			return fmt.Errorf("%w: private deny with allow-only keys: %w", ErrVerdictInvalid, commitment.ErrUnknownKey)
		}
		return nil
	}
	g := GenesisStateHash()
	linked := v.BlindPrevStateHash != nil && !bytes.Equal(v.BlindPrevStateHash, g[:])
	if !linked && (v.PrevCommitmentHash != nil || v.PrevVerdictHash != nil) {
		return fmt.Errorf("%w: chain links without a non-genesis prev_state_hash: %w", ErrVerdictInvalid, commitment.ErrUnknownKey)
	}
	if v.NewStateHash == nil || v.BlindPrevStateHash == nil || linked && (v.PrevCommitmentHash == nil || v.PrevVerdictHash == nil) {
		return fmt.Errorf("%w: private allow is missing a key: %w", ErrVerdictInvalid, commitment.ErrMissingField)
	}
	return nil
}

// Private reports whether the verdict is in private form.
func (v *Verdict) Private() bool { return v.PrivateHash != nil }

// ReadsGenesis reports whether an allow read the genesis state; in private
// form it compares key 20 with the genesis hash, which blinding keeps.
func (v *Verdict) ReadsGenesis() bool {
	if v.PrivateHash != nil {
		g := GenesisStateHash()
		return bytes.Equal(v.BlindPrevStateHash, g[:])
	}
	return v.PrevState != nil && v.PrevState.Seq == 0
}

// EncodeVerdict returns the canonical bytes of a validated verdict.
func EncodeVerdict(v *Verdict) ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return marshal(v)
}

func HashVerdict(canon []byte) commitment.Hash { return hashTagged(TagVerdict, canon) }

func VerdictSigningMessage(h commitment.Hash) []byte { return signingMessage(TagVerdictSig, h) }

// EncodeSignedVerdict encodes a verdict with its signature.
func EncodeSignedVerdict(sv *SignedVerdict) ([]byte, error) {
	if len(sv.Signature) != 64 {
		return nil, fmt.Errorf("%w: signature has %d bytes", ErrVerdictInvalid, len(sv.Signature))
	}
	if err := sv.Verdict.Validate(); err != nil {
		return nil, err
	}
	return marshal(sv)
}

// DecodeSignedVerdict strictly decodes a SignedPolicyVerdict without checking
// the signature and returns the verdict hash.
func DecodeSignedVerdict(b []byte) (*SignedVerdict, commitment.Hash, error) {
	var sv SignedVerdict
	if err := decodeStrict(b, maxSignedSize, &sv, ErrVerdictInvalid); err != nil {
		return nil, commitment.Hash{}, err
	}
	if len(sv.Signature) != 64 {
		return nil, commitment.Hash{}, fmt.Errorf("%w: signature has %d bytes: %w", ErrVerdictInvalid, len(sv.Signature), commitment.ErrFieldSize)
	}
	if err := sv.Verdict.Validate(); err != nil {
		return nil, commitment.Hash{}, err
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(&sv) }, ErrVerdictInvalid); err != nil {
		return nil, commitment.Hash{}, err
	}
	canon, err := marshal(&sv.Verdict)
	if err != nil {
		return nil, commitment.Hash{}, fmt.Errorf("%w: %v", ErrVerdictInvalid, err)
	}
	return &sv, HashVerdict(canon), nil
}

// VerifyVerdict decodes and checks the gate signature.
func VerifyVerdict(b []byte, gatePub ed25519.PublicKey) (*SignedVerdict, commitment.Hash, error) {
	sv, h, err := DecodeSignedVerdict(b)
	if err != nil {
		return nil, commitment.Hash{}, err
	}
	if len(gatePub) != ed25519.PublicKeySize || !ed25519.Verify(gatePub, VerdictSigningMessage(h), sv.Signature) {
		return nil, commitment.Hash{}, ErrVerdictSignature
	}
	return sv, h, nil
}

// Delta is the state change an allow verdict records.
func (v *Verdict) Delta() (Delta, bool) {
	if v.Outcome != OutcomeAllow || v.Facts == nil {
		return Delta{}, false
	}
	return Delta{Asset: v.Facts.Asset, Scale: v.Facts.Scale, Amount: v.Facts.Amount, TH: v.AnchorTime}, true
}

// PrevStateHash is the hash of the state the verdict was evaluated on: key 20
// in private form, else the public hash of prev_state. A merged private
// verdict needs the blinded hash of its mandate's StateHasher instead.
func (v *Verdict) PrevStateHash() (commitment.Hash, bool) {
	if v.PrivateHash != nil {
		var h commitment.Hash
		return h, copy(h[:], v.BlindPrevStateHash) == len(h)
	}
	if v.PrevState == nil {
		return commitment.Hash{}, false
	}
	h, err := HashState(v.PrevState)
	return h, err == nil
}

// SuccessorKey is the archive key of the policy_successor record.
func SuccessorKey(gateID string, counterKey [32]byte, stateHash commitment.Hash) commitment.Hash {
	return hashRaw(tagged(TagSuccessor, []byte{byte(len(gateID))}, []byte(gateID), counterKey[:], stateHash[:]))
}
