// Package fibrecert checks a Fibre PayForFibre transaction offline: it
// parses the promise, rebuilds the exact bytes the owner and the validators
// signed, and applies the network's quorum rule to the positional signatures.
package fibrecert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/celestiaorg/celestia-app/v10/fibre"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

var (
	ErrPromiseInvalid          = errors.New("fibrecert: payment promise invalid")
	ErrCertificateInvalid      = errors.New("fibrecert: validator signature invalid")
	ErrCertificateInsufficient = errors.New("fibrecert: signed power below the network threshold")
	ErrCertificateMalformed    = errors.New("fibrecert: certificate malformed")
	ErrValsetMismatch          = errors.New("fibrecert: validator set does not match any header")
	ErrBindingMismatch         = errors.New("fibrecert: promise does not match the payload reference")
)

const (
	ed25519PubKeyURL = "/cosmos.crypto.ed25519.PubKey"
	// powerReduction converts staking tokens to CometBFT consensus power.
	powerReduction = 1_000_000
)

// Promise is the signed part of a PayForFibre message.
type Promise struct {
	ChainID      string
	Height       uint64 // validator set height
	Namespace    []byte
	BlobSize     uint32
	BlobVersion  uint32
	Commitment   [32]byte
	CreationTime time.Time
	SignerKey    []byte // secp256k1, 33 bytes
}

// PFF is a parsed PayForFibre transaction.
type PFF struct {
	Promise    Promise
	OwnerSig   []byte
	Signatures [][]byte // positional, in the keeper's validator order
	Signer     string
}

// Validator is one entry of the archived validator list; Power is the staking
// token amount, which is what the keeper counts.
type Validator struct {
	PubKey ed25519.PublicKey
	Power  int64
}

// Report is the outcome of the full walk over the signatures.
type Report struct {
	SignedPower, TotalPower, Required int64
	Valid, Invalid, Empty             int
	// InvalidAfterStop counts bad signatures past the point where the
	// network stops checking; they do not change the verdict.
	InvalidAfterStop int
	// AtMostTwoThirds is set when 3*signed <= 2*total: accepted, but a warning.
	// SignedPower and this flag count every valid signature, including those
	// after the stop point.
	AtMostTwoThirds bool
}

// Share is the signed fraction of the total power.
func (r Report) Share() float64 {
	if r.TotalPower <= 0 {
		return 0
	}
	return float64(r.SignedPower) / float64(r.TotalPower)
}

// Threshold is the single quorum rule: required = floor(2*total/3), accepted
// when signed >= required. atMostTwoThirds reports 3*signed <= 2*total, which
// for integers is signed <= required. It avoids 2*total so that it cannot
// overflow.
func Threshold(signed, total int64) (required int64, accept, atMostTwoThirds bool) {
	if total < 0 {
		total = 0
	}
	q, r := total/3, total%3
	required = 2*q + 2*r/3
	return required, signed >= required, signed <= required
}

// ParsePFF decodes a transaction. ok is false only when the upstream
// classifier says it is not a Fibre transaction; an error with ok true means
// it claims to be one but is broken.
func ParsePFF(rawTx []byte) (pff PFF, ok bool, err error) {
	_, ok, err = fibretypes.TryParseFibreTx(rawTx)
	if !ok {
		return PFF{}, false, err
	}
	if err != nil {
		return PFF{}, true, fmt.Errorf("%w: %w", ErrCertificateMalformed, err)
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(rawTx); err != nil {
		return PFF{}, true, fmt.Errorf("%w: decoding tx: %w", ErrCertificateMalformed, err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return PFF{}, true, fmt.Errorf("%w: decoding tx body: %w", ErrCertificateMalformed, err)
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil {
		return PFF{}, true, fmt.Errorf("%w: expected exactly one message", ErrCertificateMalformed)
	}
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return PFF{}, true, fmt.Errorf("%w: unmarshalling MsgPayForFibre: %w", ErrCertificateMalformed, err)
	}
	var pp fibre.PaymentPromise
	if err := pp.FromProto(&msg.PaymentPromise); err != nil {
		return PFF{}, true, fmt.Errorf("%w: decoding payment promise: %w", ErrPromiseInvalid, err)
	}
	p := Promise{
		ChainID:      pp.ChainID,
		Height:       pp.Height,
		Namespace:    pp.Namespace.Bytes(),
		BlobSize:     pp.UploadSize,
		BlobVersion:  pp.BlobVersion,
		Commitment:   pp.Commitment,
		CreationTime: pp.CreationTimestamp,
	}
	if pp.SignerKey != nil {
		p.SignerKey = bytes.Clone(pp.SignerKey.Key)
	}
	sigs := make([][]byte, len(msg.ValidatorSignatures))
	for i, s := range msg.ValidatorSignatures {
		sigs[i] = bytes.Clone(s)
	}
	return PFF{
		Promise:    p,
		OwnerSig:   bytes.Clone(msg.PaymentPromise.Signature),
		Signatures: sigs,
		Signer:     msg.Signer,
	}, true, nil
}

func (p Promise) payment(ownerSig []byte) (*fibre.PaymentPromise, error) {
	var pp fibre.PaymentPromise
	err := pp.FromProto(&fibretypes.PaymentPromise{
		ChainId:           p.ChainID,
		Height:            int64(p.Height),
		Namespace:         p.Namespace,
		BlobSize:          p.BlobSize,
		BlobVersion:       p.BlobVersion,
		Commitment:        p.Commitment[:],
		CreationTimestamp: p.CreationTime,
		SignerPublicKey:   secp256k1.PubKey{Key: p.SignerKey},
		Signature:         ownerSig,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPromiseInvalid, err)
	}
	return &pp, nil
}

// SignBytes returns the exact bytes the owner and every validator signed.
func SignBytes(p Promise) ([]byte, error) {
	pp, err := p.payment(nil)
	if err != nil {
		return nil, err
	}
	sb, err := pp.SignBytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPromiseInvalid, err)
	}
	return sb, nil
}

// VerifyOwner checks the promise is well formed and owner-signed.
func VerifyOwner(f PFF) error {
	pp, err := f.Promise.payment(f.OwnerSig)
	if err != nil {
		return err
	}
	if err := pp.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrPromiseInvalid, err)
	}
	return nil
}

// Binding is what the payload reference says the promise must be for.
type Binding struct {
	ChainID    string
	Namespace  []byte
	Commitment [32]byte
	BlobSize   uint32
}

// CheckBinding ties the promise to the payload reference. Blob version must
// be 0.
func CheckBinding(p Promise, b Binding) error {
	switch {
	case p.ChainID != b.ChainID:
		return fmt.Errorf("%w: chain id", ErrBindingMismatch)
	case !bytes.Equal(p.Namespace, b.Namespace):
		return fmt.Errorf("%w: namespace", ErrBindingMismatch)
	case p.Commitment != b.Commitment:
		return fmt.Errorf("%w: commitment", ErrBindingMismatch)
	case p.BlobVersion != 0:
		return fmt.Errorf("%w: blob version %d", ErrBindingMismatch, p.BlobVersion)
	case p.BlobSize != b.BlobSize:
		return fmt.Errorf("%w: blob size", ErrBindingMismatch)
	}
	return nil
}

// VerifyCertificate walks the signatures in the keeper's order and stops at
// the first point where the signed power reaches the threshold, as the
// network does. A bad signature before that point is an error; one after it
// is only counted. The report is filled whenever the walk completed.
func VerifyCertificate(f PFF, vals []Validator) (Report, error) {
	var rep Report
	total, err := validateValidators(vals)
	if err != nil {
		return rep, err
	}
	rep.TotalPower = total
	if len(f.Signatures) > len(vals) {
		return rep, fmt.Errorf("%w: %d signatures for %d validators", ErrCertificateMalformed, len(f.Signatures), len(vals))
	}
	signBytes, err := SignBytes(f.Promise)
	if err != nil {
		return rep, err
	}
	rep.Required, _, _ = Threshold(0, rep.TotalPower)

	var running int64
	stopped := false
	for i, s := range f.Signatures {
		switch {
		case len(s) == 0:
			rep.Empty++
		case len(vals[i].PubKey) != ed25519.PublicKeySize || !ed25519.Verify(vals[i].PubKey, signBytes, s):
			rep.Invalid++
			if stopped {
				rep.InvalidAfterStop++
			}
		default:
			rep.Valid++
			rep.SignedPower += vals[i].Power
			if !stopped {
				running += vals[i].Power
				stopped = running >= rep.Required
			}
		}
	}
	_, accept, atMost := Threshold(rep.SignedPower, rep.TotalPower)
	rep.AtMostTwoThirds = atMost
	if rep.Invalid > rep.InvalidAfterStop {
		return rep, fmt.Errorf("%w: %d before the stop point", ErrCertificateInvalid, rep.Invalid-rep.InvalidAfterStop)
	}
	if !accept {
		return rep, fmt.Errorf("%w: signed %d of %d, required %d", ErrCertificateInsufficient, rep.SignedPower, rep.TotalPower, rep.Required)
	}
	return rep, nil
}

// maxTotalPower is CometBFT's MaxTotalVotingPower; NewValidatorSet panics
// above it.
const maxTotalPower = int64(1<<63-1) / 8

// validateValidators rejects, for the whole list, everything CometBFT's
// NewValidatorSet would panic on, and returns the total power. All failures
// are ErrCertificateMalformed.
func validateValidators(vals []Validator) (int64, error) {
	var total int64
	keys := make(map[string]struct{}, len(vals))
	addrs := make(map[[20]byte]struct{}, len(vals))
	for _, v := range vals {
		if len(v.PubKey) != ed25519.PublicKeySize {
			return 0, fmt.Errorf("%w: validator key of %d bytes", ErrCertificateMalformed, len(v.PubKey))
		}
		if v.Power <= 0 || total > maxTotalPower-v.Power {
			return 0, fmt.Errorf("%w: validator power out of range", ErrCertificateMalformed)
		}
		total += v.Power
		h := sha256.Sum256(v.PubKey)
		addr := [20]byte(h[:20])
		if _, dup := keys[string(v.PubKey)]; dup {
			return 0, fmt.Errorf("%w: duplicate validator key", ErrCertificateMalformed)
		}
		if _, dup := addrs[addr]; dup {
			return 0, fmt.Errorf("%w: duplicate validator address", ErrCertificateMalformed)
		}
		keys[string(v.PubKey)] = struct{}{}
		addrs[addr] = struct{}{}
	}
	return total, nil
}

// ParseHistoricalInfo decodes a staking HistoricalInfo into the validator
// list in stored order, with token amounts as power.
func ParseHistoricalInfo(b []byte) ([]Validator, error) {
	vals, _, err := parseHistoricalInfo(b)
	return vals, err
}

func parseHistoricalInfo(b []byte) ([]Validator, int64, error) {
	var hi stakingtypes.HistoricalInfo
	if err := hi.Unmarshal(b); err != nil {
		return nil, 0, fmt.Errorf("%w: decoding historical info: %w", ErrCertificateMalformed, err)
	}
	if len(hi.Valset) == 0 {
		return nil, 0, fmt.Errorf("%w: historical info has an empty validator set", ErrCertificateMalformed)
	}
	out := make([]Validator, 0, len(hi.Valset))
	for _, v := range hi.Valset {
		key, err := ed25519FromAny(v.ConsensusPubkey)
		if err != nil {
			return nil, 0, err
		}
		if !v.Tokens.IsInt64() || v.Tokens.Sign() <= 0 {
			return nil, 0, fmt.Errorf("%w: validator tokens out of range", ErrCertificateMalformed)
		}
		out = append(out, Validator{PubKey: key, Power: v.Tokens.Int64()})
	}
	if _, err := validateValidators(out); err != nil {
		return nil, 0, err
	}
	return out, hi.Header.Height, nil
}

func ed25519FromAny(a *codectypes.Any) (ed25519.PublicKey, error) {
	if a == nil || a.TypeUrl != ed25519PubKeyURL {
		return nil, fmt.Errorf("%w: consensus key is not an ed25519 key", ErrCertificateMalformed)
	}
	var pk sdked25519.PubKey
	if err := pk.Unmarshal(a.Value); err != nil {
		return nil, fmt.Errorf("%w: decoding consensus key: %w", ErrCertificateMalformed, err)
	}
	if len(pk.Key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: ed25519 key of the wrong size", ErrCertificateMalformed)
	}
	return pk.Key, nil
}

// ValsetEvidence is the header that ties the archived list to the chain.
type ValsetEvidence struct {
	PromiseHeader []byte // header at the promise height
}

// checkValset requires the CometBFT validator set built from the archived keys
// with consensus power floor(tokens/10^6) to hash to the promise header's
// next_validators_hash, and the archived list to be in that set's order: the
// keeper reads signatures positionally against the stored order. It returns
// which header field matched.
func checkValset(vals []Validator, e ValsetEvidence) (matched string, err error) {
	// NewValidatorSet panics on inputs it rejects, such as a total consensus
	// power above its limit.
	defer func() {
		if r := recover(); r != nil {
			matched, err = "", fmt.Errorf("%w: invalid validator set", ErrValsetMismatch)
		}
	}()
	if _, err := validateValidators(vals); err != nil {
		return "", err
	}
	h, err := decodeHeader(e.PromiseHeader)
	if err != nil {
		return "", fmt.Errorf("%w: decoding promise header: %w", ErrValsetMismatch, err)
	}
	cv := make([]*core.Validator, 0, len(vals))
	for _, v := range vals {
		p := v.Power / powerReduction
		if p < 1 {
			return "", fmt.Errorf("%w: consensus power below 1", ErrValsetMismatch)
		}
		cv = append(cv, core.NewValidator(cmted25519.PubKey(v.PubKey), p))
	}
	set := core.NewValidatorSet(cv)
	for i, v := range set.Validators {
		if !bytes.Equal(v.PubKey.Bytes(), vals[i].PubKey) {
			return "", fmt.Errorf("%w: archived list is not in validator set order", ErrValsetMismatch)
		}
	}
	if !bytes.Equal(h.NextValidatorsHash, set.Hash()) {
		return "", fmt.Errorf("%w: promise header does not commit to the set", ErrValsetMismatch)
	}
	return fmt.Sprintf("next_validators_hash@%d", h.Height), nil
}

func decodeHeader(b []byte) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	return core.HeaderFromProto(&ph)
}

// checkListHeight requires the archived list to be recorded at the promise
// height.
func checkListHeight(p Promise, listHeight int64) error {
	if p.Height > uint64(1<<63-1) || listHeight != int64(p.Height) {
		return fmt.Errorf("%w: historical info at height %d, promise at %d", ErrCertificateMalformed, listHeight, p.Height)
	}
	return nil
}

// checkPromiseHeader requires the promise header to sit at the promise height
// and chain.
func checkPromiseHeader(p Promise, e ValsetEvidence) error {
	h, err := decodeHeader(e.PromiseHeader)
	if err != nil {
		return fmt.Errorf("%w: decoding promise header: %w", ErrValsetMismatch, err)
	}
	switch {
	case p.Height > uint64(1<<63-1) || h.Height != int64(p.Height):
		return fmt.Errorf("%w: promise header at %d, promise at %d", ErrValsetMismatch, h.Height, p.Height)
	case h.ChainID != p.ChainID:
		return fmt.Errorf("%w: promise header chain id differs", ErrValsetMismatch)
	}
	return nil
}

// ValidatorsFor decodes the archived list, requires it to be recorded at the
// promise height on the promise chain, and requires evidence for it.
func ValidatorsFor(historicalInfo []byte, p Promise, e ValsetEvidence) ([]Validator, string, error) {
	vals, height, err := parseHistoricalInfo(historicalInfo)
	if err != nil {
		return nil, "", err
	}
	if err := checkListHeight(p, height); err != nil {
		return nil, "", err
	}
	if err := checkPromiseHeader(p, e); err != nil {
		return nil, "", err
	}
	matched, err := checkValset(vals, e)
	if err != nil {
		return nil, "", err
	}
	return vals, matched, nil
}

// Verify runs the whole check in order: classification, binding, owner
// signature, validator list, quorum, then the chain evidence for the list. It
// returns the first failure. The report is filled whenever the quorum walk
// completed; matched names the header that committed to the list.
func Verify(rawTx []byte, b Binding, historicalInfo []byte, e ValsetEvidence) (rep Report, matched string, err error) {
	f, ok, err := ParsePFF(rawTx)
	if err != nil {
		return rep, "", err
	}
	if !ok {
		return rep, "", fmt.Errorf("%w: not a Fibre transaction", ErrCertificateMalformed)
	}
	if err := CheckBinding(f.Promise, b); err != nil {
		return rep, "", err
	}
	if err := VerifyOwner(f); err != nil {
		return rep, "", err
	}
	vals, height, err := parseHistoricalInfo(historicalInfo)
	if err != nil {
		return rep, "", err
	}
	if err := checkListHeight(f.Promise, height); err != nil {
		return rep, "", err
	}
	if err := checkPromiseHeader(f.Promise, e); err != nil {
		return rep, "", err
	}
	rep, err = VerifyCertificate(f, vals)
	if err != nil {
		return rep, "", err
	}
	matched, err = checkValset(vals, e)
	if err != nil {
		return rep, "", err
	}
	return rep, matched, nil
}

// TokensRobust reports whether the quorum verdict of the walk is the same for
// every assignment of staking tokens that keeps each validator's consensus
// power: accepted even when the signers hold the fewest and the others the
// most tokens of their power bucket, or rejected even in the opposite
// assignment. No header commits to exact tokens, only to the consensus power,
// so a verdict that is not robust rests on the archived amounts.
func TokensRobust(f PFF, vals []Validator) (bool, error) {
	if _, err := validateValidators(vals); err != nil {
		return false, err
	}
	if len(f.Signatures) > len(vals) {
		return false, fmt.Errorf("%w: %d signatures for %d validators", ErrCertificateMalformed, len(f.Signatures), len(vals))
	}
	signBytes, err := SignBytes(f.Promise)
	if err != nil {
		return false, err
	}
	const (
		empty = iota
		valid
		invalid
	)
	state := make([]int, len(vals))
	for i, s := range f.Signatures {
		switch {
		case len(s) == 0:
		case ed25519.Verify(vals[i].PubKey, signBytes, s):
			state[i] = valid
		default:
			state[i] = invalid
		}
	}
	accepts := func(signersLow bool) bool {
		powers := make([]int64, len(vals))
		var total int64
		for i, v := range vals {
			low := v.Power / powerReduction * powerReduction
			if (state[i] == valid) == signersLow {
				powers[i] = low
			} else {
				powers[i] = low + powerReduction - 1
			}
			total += powers[i]
		}
		required, _, _ := Threshold(0, total)
		var running, signed int64
		stopped := false
		invalidBefore := 0
		for i, st := range state {
			switch st {
			case invalid:
				if !stopped {
					invalidBefore++
				}
			case valid:
				signed += powers[i]
				if !stopped {
					running += powers[i]
					stopped = running >= required
				}
			}
		}
		return invalidBefore == 0 && signed >= required
	}
	return accepts(true) || !accepts(false), nil
}
