// Package fibrecert checks a Fibre PayForFibre transaction offline: it
// parses the promise, rebuilds the exact bytes the owner and the validators
// signed, and applies the network's quorum rule to the positional signatures.
package fibrecert

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/celestiaorg/celestia-app/v10/fibre"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
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

// ParsePFF decodes a transaction. ok is false when it is not a Fibre
// transaction; an error with ok true means it claims to be one but is broken.
func ParsePFF(rawTx []byte) (pff PFF, ok bool, err error) {
	_, ok, err = fibretypes.TryParseFibreTx(rawTx)
	if !ok || err != nil {
		return PFF{}, ok, err
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(rawTx); err != nil {
		return PFF{}, false, nil
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return PFF{}, false, nil
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil {
		return PFF{}, false, nil
	}
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return PFF{}, true, fmt.Errorf("unmarshalling MsgPayForFibre: %w", err)
	}
	var pp fibre.PaymentPromise
	if err := pp.FromProto(&msg.PaymentPromise); err != nil {
		return PFF{}, true, fmt.Errorf("decoding payment promise: %w", err)
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
	if len(f.Signatures) > len(vals) {
		return rep, fmt.Errorf("%w: %d signatures for %d validators", ErrCertificateMalformed, len(f.Signatures), len(vals))
	}
	for _, v := range vals {
		if v.Power < 0 || rep.TotalPower > maxPower-v.Power {
			return rep, fmt.Errorf("%w: validator power out of range", ErrCertificateMalformed)
		}
		rep.TotalPower += v.Power
	}
	signBytes, err := SignBytes(f.Promise)
	if err != nil {
		return rep, err
	}
	rep.Required, _, _ = Threshold(0, rep.TotalPower)

	var running int64
	stopped := rep.Required <= 0
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

const maxPower = int64(1<<63 - 1)

// ParseHistoricalInfo decodes a staking HistoricalInfo into the validator
// list in stored order, with token amounts as power.
func ParseHistoricalInfo(b []byte) ([]Validator, error) {
	vals, _, err := parseHistoricalInfo(b)
	return vals, err
}

func parseHistoricalInfo(b []byte) ([]Validator, int64, error) {
	var hi stakingtypes.HistoricalInfo
	if err := hi.Unmarshal(b); err != nil {
		return nil, 0, fmt.Errorf("decoding historical info: %w", err)
	}
	if len(hi.Valset) == 0 {
		return nil, 0, errors.New("historical info has an empty validator set")
	}
	out := make([]Validator, 0, len(hi.Valset))
	for _, v := range hi.Valset {
		key, err := ed25519FromAny(v.ConsensusPubkey)
		if err != nil {
			return nil, 0, err
		}
		if !v.Tokens.IsInt64() || v.Tokens.Sign() <= 0 {
			return nil, 0, errors.New("validator tokens out of range")
		}
		out = append(out, Validator{PubKey: key, Power: v.Tokens.Int64()})
	}
	return out, hi.Header.Height, nil
}

func ed25519FromAny(a *codectypes.Any) (ed25519.PublicKey, error) {
	if a == nil || a.TypeUrl != ed25519PubKeyURL {
		return nil, errors.New("consensus key is not an ed25519 key")
	}
	var pk sdked25519.PubKey
	if err := pk.Unmarshal(a.Value); err != nil {
		return nil, fmt.Errorf("decoding consensus key: %w", err)
	}
	if len(pk.Key) != ed25519.PublicKeySize {
		return nil, errors.New("ed25519 key of the wrong size")
	}
	return pk.Key, nil
}

// ValsetEvidence is the header and CometBFT validator set bytes that tie the
// archived list to the chain.
type ValsetEvidence struct {
	PromiseHeader []byte // header at the promise height
	NextHeader    []byte // header at the promise height + 1
	NextValset    []byte // CometBFT validator set behind NextHeader
}

// CheckValset requires the CometBFT set to hold exactly the archived keys with
// consensus power floor(tokens/10^6), and a header to commit to it. It returns
// which header field matched.
func CheckValset(vals []Validator, e ValsetEvidence) (matched string, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched, err = "", fmt.Errorf("%w: undecodable evidence", ErrValsetMismatch)
		}
	}()
	var pv cmtproto.ValidatorSet
	if err := pv.Unmarshal(e.NextValset); err != nil {
		return "", fmt.Errorf("%w: decoding validator set: %w", ErrValsetMismatch, err)
	}
	vs, err := core.ValidatorSetFromProto(&pv)
	if err != nil {
		return "", fmt.Errorf("%w: decoding validator set: %w", ErrValsetMismatch, err)
	}
	want := make(map[string]int64, len(vals))
	for _, v := range vals {
		want[string(v.PubKey)] = v.Power / powerReduction
	}
	if len(vs.Validators) != len(want) {
		return "", fmt.Errorf("%w: %d validators, archived list has %d", ErrValsetMismatch, len(vs.Validators), len(want))
	}
	for _, v := range vs.Validators {
		p, ok := want[string(v.PubKey.Bytes())]
		if !ok || p != v.VotingPower {
			return "", fmt.Errorf("%w: key or power differs", ErrValsetMismatch)
		}
	}
	hash := vs.Hash()
	if h, err := decodeHeader(e.PromiseHeader); err == nil && bytes.Equal(h.NextValidatorsHash, hash) {
		return fmt.Sprintf("next_validators_hash@%d", h.Height), nil
	}
	if h, err := decodeHeader(e.NextHeader); err == nil && bytes.Equal(h.ValidatorsHash, hash) {
		return fmt.Sprintf("validators_hash@%d", h.Height), nil
	}
	return "", fmt.Errorf("%w: no header commits to the set", ErrValsetMismatch)
}

func decodeHeader(b []byte) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	return core.HeaderFromProto(&ph)
}

// ValidatorsFor decodes the archived list, requires it to be recorded at the
// promise header's height, and requires evidence for it. The caller must
// still compare that height with the PFF promise height.
func ValidatorsFor(historicalInfo []byte, e ValsetEvidence) ([]Validator, string, error) {
	vals, height, err := parseHistoricalInfo(historicalInfo)
	if err != nil {
		return nil, "", err
	}
	h, err := decodeHeader(e.PromiseHeader)
	if err != nil {
		return nil, "", fmt.Errorf("%w: decoding promise header: %w", ErrValsetMismatch, err)
	}
	if h.Height != height {
		return nil, "", fmt.Errorf("%w: historical info at height %d, promise header at %d", ErrValsetMismatch, height, h.Height)
	}
	matched, err := CheckValset(vals, e)
	if err != nil {
		return nil, "", err
	}
	return vals, matched, nil
}
