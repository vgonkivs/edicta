package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/validator"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtmath "github.com/cometbft/cometbft/libs/math"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

const (
	ed25519PubKeyURL = "/cosmos.crypto.ed25519.PubKey"
	powerReduction   = 1_000_000
)

func ed25519FromAny(a *codectypes.Any) ([]byte, error) {
	if a == nil || a.TypeUrl != ed25519PubKeyURL {
		return nil, errors.New("consensus key is not an ed25519 key")
	}
	var pk sdked25519.PubKey
	if err := pk.Unmarshal(a.Value); err != nil {
		return nil, err
	}
	if len(pk.Key) != ed25519.PublicKeySize {
		return nil, errors.New("ed25519 key of the wrong size")
	}
	return pk.Key, nil
}

// inputs are the byte strings a verifier holds; mutations flip bytes in them.
type inputs struct {
	tx            []byte
	hist          []byte
	valsets       map[int64][]byte
	headers       map[int64][]byte
	trustedHeight int64
	trustedHash   []byte
}

func decodeInputs(r liveRaw) (inputs, error) {
	in := inputs{valsets: map[int64][]byte{}, headers: map[int64][]byte{}}
	var err error
	if in.tx, err = hex.DecodeString(r.PFFTxHex); err != nil {
		return in, err
	}
	if in.hist, err = hex.DecodeString(r.HistoricalInfo.Hex); err != nil {
		return in, err
	}
	for _, v := range r.CometValsets {
		h, err := strconv.ParseInt(v.Height, 10, 64)
		if err != nil {
			return in, err
		}
		if in.valsets[h], err = hex.DecodeString(v.Hex); err != nil {
			return in, err
		}
	}
	for _, v := range r.Headers {
		h, err := strconv.ParseInt(v.Height, 10, 64)
		if err != nil {
			return in, err
		}
		if in.headers[h], err = hex.DecodeString(v.HeaderHex); err != nil {
			return in, err
		}
	}
	if in.trustedHeight, err = strconv.ParseInt(r.Trusted.Height, 10, 64); err != nil {
		return in, err
	}
	in.trustedHash, err = hex.DecodeString(r.Trusted.HashHex)
	return in, err
}

func (in inputs) clone() inputs {
	out := inputs{tx: bytes.Clone(in.tx), hist: bytes.Clone(in.hist), valsets: map[int64][]byte{},
		headers: map[int64][]byte{}, trustedHeight: in.trustedHeight, trustedHash: bytes.Clone(in.trustedHash)}
	for k, v := range in.valsets {
		out.valsets[k] = bytes.Clone(v)
	}
	for k, v := range in.headers {
		out.headers[k] = bytes.Clone(v)
	}
	return out
}

type parsedPFF struct {
	msg       fibretypes.MsgPayForFibre
	pp        *fibre.PaymentPromise
	stripped  []byte
	signBytes []byte
}

// parsePFF accepts exactly what the chain's classifier accepts, then decodes
// the message the same way (TxRaw, TxBody, the single Any).
func parsePFF(tx []byte) (parsedPFF, error) {
	var p parsedPFF
	_, ok, err := fibretypes.TryParseFibreTx(tx)
	if err != nil || !ok {
		return p, fmt.Errorf("not a Fibre tx (ok=%v): %v", ok, err)
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return p, err
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return p, err
	}
	if err := p.msg.Unmarshal(body.Messages[0].Value); err != nil {
		return p, err
	}
	p.pp = &fibre.PaymentPromise{}
	if err := p.pp.FromProto(&p.msg.PaymentPromise); err != nil {
		return p, err
	}
	sb, err := p.pp.SignBytes()
	if err != nil {
		return p, err
	}
	p.signBytes = sb
	ts, err := p.pp.CreationTimestamp.UTC().MarshalBinary()
	if err != nil {
		return p, err
	}
	var st []byte
	st = append(st, p.pp.SignerKey.Bytes()...)
	st = append(st, p.pp.Namespace.Bytes()...)
	st = be32(st, p.pp.UploadSize)
	st = append(st, p.pp.Commitment[:]...)
	st = be32(st, p.pp.BlobVersion)
	st = be64(st, p.pp.Height)
	p.stripped = append(st, ts...)
	return p, nil
}

func be32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func be64(b []byte, v uint64) []byte {
	return be32(be32(b, uint32(v>>32)), uint32(v))
}

type valEntry struct {
	pubKey    []byte
	address   []byte
	tokens    int64
	consPower int64
}

func decodeHist(b []byte) (stakingtypes.HistoricalInfo, []valEntry, error) {
	var hi stakingtypes.HistoricalInfo
	if err := hi.Unmarshal(b); err != nil {
		return hi, nil, err
	}
	if len(hi.Valset) == 0 {
		return hi, nil, errors.New("empty validator set")
	}
	out := make([]valEntry, 0, len(hi.Valset))
	for _, v := range hi.Valset {
		pk, err := ed25519FromAny(v.ConsensusPubkey)
		if err != nil {
			return hi, nil, err
		}
		if !v.Tokens.IsInt64() || v.Tokens.Sign() <= 0 {
			return hi, nil, errors.New("tokens out of range")
		}
		t := v.Tokens.Int64()
		addr := sha256.Sum256(pk)
		out = append(out, valEntry{pubKey: pk, address: addr[:20], tokens: t, consPower: t / powerReduction})
	}
	return hi, out, nil
}

// keeperVerdict is the keeper's validateValidatorSignatures at the pin, with
// the staking read replaced by the archived list: power = tokens, positions
// over the list as stored, threshold from validator.SignatureSet.
func keeperVerdict(signBytes []byte, height int64, vals []valEntry, sigs [][]byte) (rule string, err error) {
	defer func() {
		if r := recover(); r != nil {
			rule, err = "CV4", fmt.Errorf("validator set rejected: %v", r)
		}
	}()
	cmtVals := make([]*core.Validator, len(vals))
	for i, v := range vals {
		cmtVals[i] = core.NewValidator(cmted25519.PubKey(v.pubKey), v.tokens)
	}
	set := validator.Set{ValidatorSet: core.NewValidatorSet(cmtVals), Height: uint64(height)}
	ss := set.NewSignatureSet(cmtmath.Fraction{Numerator: 2, Denominator: 3}, signBytes)
	if len(sigs) > len(cmtVals) {
		return "CV5", fmt.Errorf("signature count %d exceeds validator count %d", len(sigs), len(cmtVals))
	}
	for i, s := range sigs {
		if len(s) == 0 {
			continue
		}
		enough, err := ss.Add(cmtVals[i], s)
		if err != nil {
			return "CV6", fmt.Errorf("invalid signature at index %d: %w", i, err)
		}
		if enough {
			return "", nil
		}
	}
	if _, err := ss.Signatures(); err != nil {
		return "CV6", err
	}
	return "", nil
}

type certReport struct {
	SignaturesLen    int    `json:"signatures_len"`
	ValidatorsLen    int    `json:"validators_len"`
	Valid            int    `json:"valid"`
	Invalid          int    `json:"invalid"`
	Empty            int    `json:"empty"`
	InvalidAfterStop int    `json:"invalid_after_stop"`
	StopIndex        string `json:"stop_index"`
	SignedPower      string `json:"signed_power"`
	TotalPower       string `json:"total_power"`
	Required         string `json:"required"`
	SignedShare      string `json:"signed_share"`
	AtMostTwoThirds  bool   `json:"at_most_two_thirds"`
}

// report walks the whole list (the verifier report), independent of the
// keeper's early stop. The stop index is where the running sum of valid
// entries first reaches the requirement; "none" if it never does.
func report(signBytes []byte, vals []valEntry, sigs [][]byte) certReport {
	var total, signed, running int64
	for _, v := range vals {
		total += v.tokens
	}
	required := total * 2 / 3
	r := certReport{SignaturesLen: len(sigs), ValidatorsLen: len(vals), StopIndex: "none"}
	stopped := false
	if required <= 0 {
		r.StopIndex, stopped = "-1", true
	}
	for i, s := range sigs {
		switch {
		case len(s) == 0:
			r.Empty++
		case i >= len(vals) || !ed25519.Verify(vals[i].pubKey, signBytes, s):
			r.Invalid++
			if stopped {
				r.InvalidAfterStop++
			}
		default:
			r.Valid++
			signed += vals[i].tokens
			if !stopped {
				running += vals[i].tokens
				if running >= required {
					r.StopIndex, stopped = strconv.Itoa(i), true
				}
			}
		}
	}
	r.SignedPower = strconv.FormatInt(signed, 10)
	r.TotalPower = strconv.FormatInt(total, 10)
	r.Required = strconv.FormatInt(required, 10)
	r.SignedShare = share(signed, total)
	r.AtMostTwoThirds = big.NewInt(0).Mul(big.NewInt(3), big.NewInt(signed)).Cmp(
		big.NewInt(0).Mul(big.NewInt(2), big.NewInt(total))) <= 0
	return r
}

func share(signed, total int64) string {
	if total == 0 {
		return "undefined"
	}
	return new(big.Rat).SetFrac64(signed, total).FloatString(6)
}

func consensusOrder(vals []valEntry) bool {
	return sort.SliceIsSorted(vals, func(i, j int) bool {
		if vals[i].consPower != vals[j].consPower {
			return vals[i].consPower > vals[j].consPower
		}
		return bytes.Compare(vals[i].address, vals[j].address) < 0
	})
}

func tokenOrder(vals []valEntry) bool {
	return sort.SliceIsSorted(vals, func(i, j int) bool {
		if vals[i].tokens != vals[j].tokens {
			return vals[i].tokens > vals[j].tokens
		}
		return bytes.Compare(vals[i].address, vals[j].address) < 0
	})
}

func decodeHeader(b []byte) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	return core.HeaderFromProto(&ph)
}

func decodeValset(b []byte) (*core.ValidatorSet, error) {
	var pv cmtproto.ValidatorSet
	if err := pv.Unmarshal(b); err != nil {
		return nil, err
	}
	return core.ValidatorSetFromProto(&pv)
}

type binding struct {
	ChainID       string `json:"chain_id"`
	NamespaceHex  string `json:"namespace_hex"`
	CommitmentHex string `json:"commitment_hex"`
	BlobVersion   string `json:"blob_version"`
	BlobSize      string `json:"blob_size"`
	PayloadSize   string `json:"payload_size"`
}

// The payload_ref the live PFF anchors (fibre_commit.json case
// fibre_live_mocha_popsmin1): CV2 is checked against it.
var liveBinding = binding{
	ChainID:       liveChainID,
	NamespaceHex:  "000000000000000000000000000000000000000000706f70736d696e31",
	CommitmentHex: "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e",
	BlobVersion:   "0",
	BlobSize:      "262144",
	PayloadSize:   "1",
}

type evaluation struct {
	fails      []string
	pff        *parsedPFF
	vals       []valEntry
	hist       stakingtypes.HistoricalInfo
	report     *certReport
	valsetVia  string
	keeperNote string
}

func addFail(e *evaluation, rule string) {
	for _, f := range e.fails {
		if f == rule {
			return
		}
	}
	e.fails = append(e.fails, rule)
}

// evaluate runs every check a verifier applies to the archived bytes and
// records each rule that fails, not only the first, so a vector shows which
// checks catch a mutation.
func evaluate(in inputs) evaluation {
	var e evaluation
	p, err := parsePFF(in.tx)
	if err != nil {
		addFail(&e, "CV1")
	} else {
		e.pff = &p
		pp := p.pp
		if pp.ChainID != liveBinding.ChainID || hex.EncodeToString(pp.Namespace.Bytes()) != liveBinding.NamespaceHex ||
			hex.EncodeToString(pp.Commitment[:]) != liveBinding.CommitmentHex ||
			strconv.FormatUint(uint64(pp.BlobVersion), 10) != liveBinding.BlobVersion ||
			strconv.FormatUint(uint64(pp.UploadSize), 10) != liveBinding.BlobSize {
			addFail(&e, "CV2")
		}
		if err := pp.Validate(); err != nil {
			addFail(&e, "CV3")
		}
	}

	hi, vals, err := decodeHist(in.hist)
	if err != nil || (e.pff != nil && uint64(hi.Header.Height) != e.pff.pp.Height) {
		addFail(&e, "CV4")
	} else {
		e.vals, e.hist = vals, hi
	}

	if e.pff != nil && e.vals != nil {
		rule, err := keeperVerdict(e.pff.signBytes, int64(e.pff.pp.Height), e.vals, e.pff.msg.ValidatorSignatures)
		if err != nil {
			addFail(&e, rule)
			e.keeperNote = err.Error()
		}
		r := report(e.pff.signBytes, e.vals, e.pff.msg.ValidatorSignatures)
		e.report = &r
	}

	var ph int64 = livePromiseHeight
	if e.pff != nil {
		ph = int64(e.pff.pp.Height)
	}
	if e.vals != nil {
		e.valsetVia = cv7(in, ph, e.vals)
		if e.valsetVia == "" {
			addFail(&e, "CV7")
		}
	}

	th, err := decodeHeader(in.headers[in.trustedHeight])
	if err != nil || !bytes.Equal(th.Hash(), in.trustedHash) {
		addFail(&e, "HT2")
	}
	for k := in.trustedHeight; k > ph; k-- {
		hk, err1 := decodeHeader(in.headers[k])
		prev, err2 := decodeHeader(in.headers[k-1])
		if err1 != nil || err2 != nil || !bytes.Equal(prev.Hash(), hk.LastBlockID.Hash) {
			addFail(&e, "HT3")
			break
		}
	}
	return e
}

// cv7 ties the HistoricalInfo list to a header: the CometBFT set behind
// next_validators_hash at the promise height (equivalently validators_hash at
// the next height) must hold exactly the same keys, with consensus power
// floor(tokens / 10^6). It returns which header field matched, or "".
func cv7(in inputs, ph int64, vals []valEntry) string {
	vs, err := decodeValset(in.valsets[ph+1])
	if err != nil {
		return ""
	}
	want := map[string]int64{}
	for _, v := range vals {
		want[string(v.pubKey)] = v.consPower
	}
	if len(vs.Validators) != len(want) {
		return ""
	}
	for _, v := range vs.Validators {
		p, ok := want[string(v.PubKey.Bytes())]
		if !ok || p != v.VotingPower {
			return ""
		}
	}
	hash := vs.Hash()
	if h, err := decodeHeader(in.headers[ph]); err == nil && bytes.Equal(h.NextValidatorsHash, hash) {
		return fmt.Sprintf("next_validators_hash@%d", ph)
	}
	if h, err := decodeHeader(in.headers[ph+1]); err == nil && bytes.Equal(h.ValidatorsHash, hash) {
		return fmt.Sprintf("validators_hash@%d", ph+1)
	}
	return ""
}
