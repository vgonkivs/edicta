package main

import (
	"bytes"
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

// ed25519FromAny leaves the key length to the keeper, which rejects the whole
// tx on a key that is not 32 bytes.
func ed25519FromAny(a *codectypes.Any) ([]byte, error) {
	if a == nil || a.TypeUrl != ed25519PubKeyURL {
		return nil, errors.New("consensus key is not an ed25519 key")
	}
	var pk sdked25519.PubKey
	if err := pk.Unmarshal(a.Value); err != nil {
		return nil, err
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
		// The keeper calls Tokens.Int64(), which panics outside int64. Zero
		// tokens pass here: NewValidatorSet rejects them in keeperVerdict.
		if !v.Tokens.IsInt64() || v.Tokens.Sign() < 0 {
			return hi, nil, errors.New("tokens out of range")
		}
		t := v.Tokens.Int64()
		addr := sha256.Sum256(pk)
		out = append(out, valEntry{pubKey: pk, address: addr[:20], tokens: t, consPower: t / powerReduction})
	}
	return hi, out, nil
}

// keeperVerdict is the keeper's validateValidatorSignatures at the pin, with
// the staking read replaced by the archived list: the key-size check, power =
// tokens, positions over the list as stored, the set and threshold from
// core.NewValidatorSet and validator.SignatureSet. The keeper itself cannot be
// called (unexported, needs a full sdk.Context), so its body is transcribed
// here; every decision inside it is an upstream call. A panic in
// NewValidatorSet (duplicate, zero power, total above MaxTotalVotingPower)
// fails the tx on chain, so it is a rejection here.
func keeperVerdict(signBytes []byte, height int64, vals []valEntry, sigs [][]byte) (rule string, err error) {
	defer func() {
		if r := recover(); r != nil {
			rule, err = "CV4", fmt.Errorf("validator set rejected: %v", r)
		}
	}()
	cmtVals := make([]*core.Validator, len(vals))
	for i, v := range vals {
		if len(v.pubKey) != cmted25519.PubKeySize {
			return "CV4", fmt.Errorf("invalid ed25519 public key size at index %d", i)
		}
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

// upstreamSet builds the keeper's CometBFT set from the list (power = tokens),
// or reports that the keeper would reject the list as a whole.
func upstreamSet(vals []valEntry) (cmtVals []*core.Validator, set validator.Set, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	cmtVals = make([]*core.Validator, len(vals))
	for i, v := range vals {
		if len(v.pubKey) != cmted25519.PubKeySize {
			return nil, set, false
		}
		cmtVals[i] = core.NewValidator(cmted25519.PubKey(v.pubKey), v.tokens)
	}
	return cmtVals, validator.Set{ValidatorSet: core.NewValidatorSet(cmtVals), Height: 1}, true
}

// report is the verifier report over the whole list, taken from upstream
// validator.SignatureSet: every non-empty entry is offered to Add in list
// order (an entry beyond the list has no validator and counts as invalid);
// the stop index is the first Add that returns true, which is where the
// keeper returns; signed power is what Signatures reports as collected; the
// requirement is the one an empty SignatureSet reports as missing. nil when
// the keeper rejects the list itself, because no walk happens then.
func report(signBytes []byte, vals []valEntry, sigs [][]byte) *certReport {
	cmtVals, set, ok := upstreamSet(vals)
	if !ok {
		return nil
	}
	twoThirds := cmtmath.Fraction{Numerator: 2, Denominator: 3}
	ss := set.NewSignatureSet(twoThirds, signBytes)
	r := certReport{SignaturesLen: len(sigs), ValidatorsLen: len(vals), StopIndex: "none"}
	stopped := false
	for i, s := range sigs {
		if len(s) == 0 {
			r.Empty++
			continue
		}
		var enough bool
		var err error = errors.New("no validator at this index")
		if i < len(cmtVals) {
			enough, err = ss.Add(cmtVals[i], s)
		}
		if err != nil {
			r.Invalid++
			if stopped {
				r.InvalidAfterStop++
			}
			continue
		}
		r.Valid++
		if enough && !stopped {
			r.StopIndex, stopped = strconv.Itoa(i), true
		}
	}
	collected, err := ss.Signatures()
	var short *validator.NotEnoughSignaturesError
	if errors.As(err, &short) {
		collected = short.Collected
	}
	var signed int64
	for j, sig := range collected {
		if sig != nil {
			signed += set.Validators[j].VotingPower
		}
	}
	var required int64
	if _, err := set.NewSignatureSet(twoThirds, signBytes).Signatures(); errors.As(err, &short) {
		required = short.RequiredPower
	}
	total := set.TotalVotingPower()
	r.SignedPower = strconv.FormatInt(signed, 10)
	r.TotalPower = strconv.FormatInt(total, 10)
	r.Required = strconv.FormatInt(required, 10)
	r.SignedShare = share(signed, total)
	r.AtMostTwoThirds = big.NewInt(0).Mul(big.NewInt(3), big.NewInt(signed)).Cmp(
		big.NewInt(0).Mul(big.NewInt(2), big.NewInt(total))) <= 0
	return &r
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
	keeperRule string
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

	chainID := liveChainID
	var ph int64 = livePromiseHeight
	var signBytes []byte
	var sigs [][]byte
	if e.pff != nil {
		chainID, ph, signBytes, sigs = e.pff.pp.ChainID, int64(e.pff.pp.Height), e.pff.signBytes, e.pff.msg.ValidatorSignatures
	}
	evalValset(&e, chainID, ph, signBytes, sigs, in.hist, in.headers[ph])

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

// evalValset runs CV4 to CV7 on an archived HistoricalInfo and the header at
// the promise height. signBytes is nil when the PFF did not parse: then only
// the list and its header binding are checked.
func evalValset(e *evaluation, chainID string, ph int64, signBytes []byte, sigs [][]byte, hist, promiseHeader []byte) {
	hi, vals, err := decodeHist(hist)
	if err != nil || hi.Header.Height != ph {
		addFail(e, "CV4")
		return
	}
	e.vals, e.hist = vals, hi
	if signBytes != nil {
		rule, err := keeperVerdict(signBytes, ph, vals, sigs)
		if err != nil {
			addFail(e, rule)
			e.keeperRule, e.keeperNote = rule, err.Error()
		}
		e.report = report(signBytes, vals, sigs)
	}
	e.valsetVia = cv7(chainID, ph, vals, promiseHeader)
	if e.valsetVia == "" {
		addFail(e, "CV7")
	}
}

// consensusSetHash is the hash of the CometBFT set the list stands for:
// core.NewValidatorSet over (key, floor(tokens / 10^6)), so duplicates, zero
// consensus power and bad keys (all panics upstream) give no hash, and the
// hash binds both the size and the multiplicity of the list. The hash is
// order-free because NewValidatorSet sorts, so the list must also be in the
// set's own order (the stored order, which the keeper walks): otherwise no
// hash either.
func consensusSetHash(vals []valEntry) (h []byte) {
	defer func() {
		if recover() != nil {
			h = nil
		}
	}()
	cv := make([]*core.Validator, len(vals))
	for i, v := range vals {
		cv[i] = core.NewValidator(cmted25519.PubKey(v.pubKey), v.consPower)
	}
	set := core.NewValidatorSet(cv)
	for i, v := range set.Validators {
		if !bytes.Equal(v.PubKey.Bytes(), vals[i].pubKey) {
			return nil
		}
	}
	return set.Hash()
}

// cv7 ties the HistoricalInfo list to the chain with upstream hashes only: the
// list's own CometBFT set must hash to next_validators_hash of the header at
// the promise height, on the promise's chain. No fallback to validators_hash
// at height + 1: once that header must chain to the promise header, CometBFT
// makes the two fields equal, so it could never match where this one failed.
func cv7(chainID string, ph int64, vals []valEntry, promiseHeader []byte) string {
	want := consensusSetHash(vals)
	if want == nil {
		return ""
	}
	p, err := decodeHeader(promiseHeader)
	if err != nil || p.Height != ph || p.ChainID != chainID || !bytes.Equal(p.NextValidatorsHash, want) {
		return ""
	}
	return fmt.Sprintf("next_validators_hash@%d", ph)
}
