package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/celestiaorg/celestia-app/v10/fibre/validator"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtmath "github.com/cometbft/cometbft/libs/math"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
)

const histHeaderNote = "partial: x/staking stores the SDK context header, which carries chain_id, height, time, next_validators_hash, app_hash and proposer_address equal to the header at the promise height, and no version, last_block_id or validators_hash; it does not hash to the block id and is not a trust anchor"

const revision = "v0-draft.18"

type file struct {
	Format     string            `json:"format"`
	Revision   string            `json:"revision"`
	Generator  string            `json:"generator"`
	Upstream   map[string]string `json:"upstream"`
	Rules      map[string]string `json:"rules"`
	Live       liveDoc           `json:"live"`
	Mutations  []mutation        `json:"mutations"`
	Undetected []mutation        `json:"undetected_mutations"`
	Boundary   boundaryDoc       `json:"boundary"`
	Threshold  []thresholdCase   `json:"threshold"`
	Valset     valsetDoc         `json:"valset"`
}

type liveDoc struct {
	Description string      `json:"description"`
	Source      liveSource  `json:"source"`
	Raw         liveRaw     `json:"raw"`
	Derived     liveDerived `json:"derived"`
}

type promiseDoc struct {
	ChainID             string `json:"chain_id"`
	Height              string `json:"height"`
	NamespaceHex        string `json:"namespace_hex"`
	BlobSize            string `json:"blob_size"`
	BlobVersion         string `json:"blob_version"`
	CommitmentHex       string `json:"commitment_hex"`
	CreationTimestamp   string `json:"creation_timestamp"`
	CreationUnixSeconds string `json:"creation_unix_seconds"`
	CreationNanos       string `json:"creation_nanos"`
	SignerPublicKeyHex  string `json:"signer_public_key_hex"`
	OwnerSignatureHex   string `json:"owner_signature_hex"`
}

type valDoc struct {
	Index          string `json:"index"`
	PubKeyHex      string `json:"pubkey_hex"`
	AddressHex     string `json:"address_hex"`
	Tokens         string `json:"tokens"`
	ConsensusPower string `json:"consensus_power"`
	Signature      string `json:"signature"`
}

type heightHash struct {
	Height  string `json:"height"`
	HashHex string `json:"hash_hex"`
}

type liveDerived struct {
	Binding              binding      `json:"binding"`
	MsgSigner            string       `json:"msg_signer"`
	Promise              promiseDoc   `json:"promise"`
	StrippedSignBytesHex string       `json:"stripped_sign_bytes_hex"`
	SignBytesHex         string       `json:"sign_bytes_hex"`
	OwnerSignatureValid  bool         `json:"owner_signature_valid"`
	ValidatorSignatures  []string     `json:"validator_signatures_hex"`
	Validators           []valDoc     `json:"validators"`
	ValsetOrder          orderDoc     `json:"valset_order"`
	PowerReduction       string       `json:"power_reduction"`
	Certificate          certReport   `json:"certificate"`
	Verdict              string       `json:"verdict"`
	CV7Matched           string       `json:"cv7_matched"`
	CV7Both              bool         `json:"cv7_both_header_fields_match"`
	HistoricalInfoHeader string       `json:"historical_info_header"`
	HeaderHashes         []heightHash `json:"header_hashes"`
	ValsetHashes         []heightHash `json:"cometbft_valset_hashes"`
}

type orderDoc struct {
	Rule                      string `json:"rule"`
	ConsensusPowerThenAddress bool   `json:"consensus_power_then_address"`
	TokensThenAddress         bool   `json:"tokens_then_address"`
}

type mutation struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Target      string         `json:"target"`
	Height      string         `json:"height,omitempty"`
	Offset      string         `json:"offset"`
	XOR         string         `json:"xor"`
	Expect      mutationExpect `json:"expect"`
}

type mutationExpect struct {
	Verdict     string      `json:"verdict"`
	Fails       []string    `json:"fails"`
	Certificate *certReport `json:"certificate,omitempty"`
}

type boundaryDoc struct {
	Message     string         `json:"message"`
	KeySeedRule string         `json:"key_seed_rule"`
	Cases       []boundaryCase `json:"cases"`
}

type boundaryVal struct {
	KeyIndex    string `json:"key_index"`
	PubKeyHex   string `json:"pubkey_hex"`
	TruncatedTo string `json:"truncated_to,omitempty"`
	Power       string `json:"power"`
}

type boundaryCase struct {
	ID            string         `json:"id"`
	Description   string         `json:"description"`
	Validators    []boundaryVal  `json:"validators"`
	SignaturesHex []string       `json:"signatures_hex"`
	Expect        boundaryExpect `json:"expect"`
}

// Certificate is absent when the keeper rejects the list itself (rule CV4):
// no signature is walked then.
type boundaryExpect struct {
	Verdict     string      `json:"verdict"`
	Rule        string      `json:"rule,omitempty"`
	Certificate *certReport `json:"certificate,omitempty"`
}

type thresholdCase struct {
	ID              string `json:"id"`
	Signed          string `json:"signed"`
	Total           string `json:"total"`
	Required        string `json:"required"`
	Accept          bool   `json:"accept"`
	AtMostTwoThirds bool   `json:"at_most_two_thirds"`
	Note            string `json:"note,omitempty"`
}

func uniqueIndex(hay, needle []byte, what string) (int, error) {
	if len(needle) == 0 || bytes.Count(hay, needle) != 1 {
		return 0, fmt.Errorf("%s: not found exactly once", what)
	}
	return bytes.Index(hay, needle), nil
}

func outcome(e evaluation) mutationExpect {
	m := mutationExpect{Verdict: "accept", Fails: []string{}}
	if len(e.fails) > 0 {
		m.Verdict = "reject"
		m.Fails = slices.Clone(e.fails)
	}
	return m
}

func build(in liveInput) (*file, error) {
	base, err := decodeInputs(in.Raw)
	if err != nil {
		return nil, err
	}
	txHash, err := hex.DecodeString(in.Raw.TxHash)
	if err != nil {
		return nil, err
	}
	if s := sha256.Sum256(base.tx); !bytes.Equal(s[:], txHash) {
		return nil, errors.New("live PFF tx bytes do not hash to the recorded tx hash")
	}
	if in.Raw.TxResultCode != "0" {
		return nil, fmt.Errorf("live PFF result code %s", in.Raw.TxResultCode)
	}

	e := evaluate(base)
	if len(e.fails) > 0 {
		return nil, fmt.Errorf("live inputs fail %v (%s)", e.fails, e.keeperNote)
	}
	if e.report == nil || e.report.Valid != 73 || e.report.Invalid != 0 || e.report.AtMostTwoThirds || share3(e.report) != "0.762" {
		return nil, fmt.Errorf("live certificate differs from the 009 probe: %+v", *e.report)
	}
	derived, err := describeLive(base, e)
	if err != nil {
		return nil, err
	}

	f := &file{
		Format:    "edicta-vectors/v0",
		Revision:  revision,
		Generator: "spec/vectors/tools/fibrecert-gen",
		Upstream: map[string]string{
			"celestia-app":  "github.com/celestiaorg/celestia-app/v10 v10.4.0-mocha (x/fibre/types.TryParseFibreTx, fibre.PaymentPromise.FromProto/Validate/SignBytes, fibre/validator.SignatureSet as the keeper's validateValidatorSignatures uses it)",
			"celestia-core": "github.com/celestiaorg/celestia-core v0.42.0 (types.Header.Hash, types.ValidatorSet.Hash, RawBytesMessageSignBytes)",
			"cosmos-sdk":    "github.com/celestiaorg/cosmos-sdk v0.52.8 (x/staking HistoricalInfo)",
			"replace_set":   "identical to github.com/celestiaorg/celestia-node v0.34.2-mocha go.mod",
		},
		Rules: map[string]string{
			"threshold":          "required = floor(2 * total / 3) over token amounts (int64); walk the signatures in list order, skip empty entries, a non-empty entry must verify (Go crypto/ed25519.Verify) under the validator at the same index or the certificate is rejected, add that validator's tokens once, accept as soon as the sum >= required; entries after that point are not checked. If the walk ends below required, reject.",
			"at_most_two_thirds": "true iff 3 * signed_power <= 2 * total_power, with signed_power summed over every valid entry of the whole list. Never changes the verdict; the gate, Recorder and verifier log it as a warning.",
			"length":             "len(signatures) > len(validators) rejects before any signature is checked; a shorter list is walked as is.",
			"list":               "The keeper rejects the whole list (rule CV4, no walk, no certificate in the vector) on a consensus key that is not 32 bytes, and wherever core.NewValidatorSet panics over (key, tokens): a duplicate address, power 0, a validator or a total above MaxTotalVotingPower (MaxInt64 / 8).",
			"cv7":                "core.NewValidatorSet over (key, floor(tokens / 10^6)) of the list must not panic, and its hash must equal the hash of the archived CometBFT set and next_validators_hash of the promise header (height and chain id equal to the promise's), or validators_hash of the next header if that header has height promise height + 1, the same chain id and last_block_id.hash equal to the promise header's hash.",
			"report":             "From upstream validator.SignatureSet: every non-empty entry offered to Add in list order; stop_index is the first Add that returns true (none if no Add does, even when an empty walk meets a requirement of 0); invalid_after_stop counts failed entries after it; signed_power is the power Signatures reports as collected.",
			"valset":             "valset.cases: network is the keeper's answer with the case's list as its state; verdict and fails cover CV4 to CV7 over the archived bytes. A list the network accepts can still fail CV7 when the evidence headers do not bind it.",
			"positions":          "Signature i belongs to HistoricalInfo.valset[i] as stored by x/staking (consensus power floor(tokens / 10^6) descending, then address ascending); the keeper does not re-sort.",
			"fails":              "Rule ids of spec section 10.6.1 (CV1..CV7) and 10.6.2 (HT2 trusted header hash, HT3 backward last_block_id chain to the promise height). Every rule that fails is listed, in check order.",
			"mutation":           "Flip: byte at offset of the target's raw bytes (live.raw, hex-decoded) XOR xor. Targets: pff_tx, historical_info, cometbft_valset (at height), header (header_hex at height). commit_hex is archived with the headers but v0 checks no commit signatures (header trust comes from the trusted hash and the hash chain), so no mutation targets it.",
		},
		Live: liveDoc{
			Description: "PayForFibre at height 1402819 on mocha-5 (one byte 0x65 in namespace popsmin1), the x/staking HistoricalInfo at its promise height 1402813, the CometBFT validator sets at 1402813 and 1402814, and headers 1402813..1402819 with the commits of 1402813, 1402814 and 1402819. Trusted header: 1402819.",
			Source:      in.Source,
			Raw:         in.Raw,
			Derived:     derived,
		},
	}

	if f.Mutations, f.Undetected, err = mutations(base, e); err != nil {
		return nil, err
	}
	if f.Boundary, err = boundary(e.pff.signBytes); err != nil {
		return nil, err
	}
	if f.Threshold, err = thresholds(e.report); err != nil {
		return nil, err
	}
	if f.Valset, err = valsetCases(base, e); err != nil {
		return nil, err
	}
	return f, nil
}

// share3 rounds the signed share to three decimals, as the 009 probe printed it.
func share3(r *certReport) string {
	s, _ := new(big.Rat).SetString(r.SignedPower)
	t, _ := new(big.Rat).SetString(r.TotalPower)
	return new(big.Rat).Quo(s, t).FloatString(3)
}

func describeLive(in inputs, e evaluation) (liveDerived, error) {
	p := e.pff
	pp := p.pp
	d := liveDerived{
		Binding:   liveBinding,
		MsgSigner: p.msg.Signer,
		Promise: promiseDoc{
			ChainID: pp.ChainID, Height: strconv.FormatUint(pp.Height, 10),
			NamespaceHex: hex.EncodeToString(pp.Namespace.Bytes()), BlobSize: strconv.FormatUint(uint64(pp.UploadSize), 10),
			BlobVersion: strconv.FormatUint(uint64(pp.BlobVersion), 10), CommitmentHex: hex.EncodeToString(pp.Commitment[:]),
			CreationTimestamp:   pp.CreationTimestamp.UTC().Format(time.RFC3339Nano),
			CreationUnixSeconds: strconv.FormatInt(pp.CreationTimestamp.Unix(), 10),
			CreationNanos:       strconv.Itoa(pp.CreationTimestamp.Nanosecond()),
			SignerPublicKeyHex:  hex.EncodeToString(pp.SignerKey.Bytes()),
			OwnerSignatureHex:   hex.EncodeToString(pp.Signature),
		},
		StrippedSignBytesHex: hex.EncodeToString(p.stripped),
		SignBytesHex:         hex.EncodeToString(p.signBytes),
		OwnerSignatureValid:  true,
		ValsetOrder: orderDoc{
			Rule:                      "HistoricalInfo.valset as stored",
			ConsensusPowerThenAddress: consensusOrder(e.vals),
			TokensThenAddress:         tokenOrder(e.vals),
		},
		PowerReduction: strconv.Itoa(powerReduction),
		Certificate:    *e.report,
		Verdict:        "accept",
		CV7Matched:     e.valsetVia,
	}
	if !d.ValsetOrder.ConsensusPowerThenAddress {
		return d, errors.New("live HistoricalInfo is not in consensus-power order")
	}
	stripped, err := core.RawBytesMessageSignBytes(pp.ChainID, "fibre/pp:v0", p.stripped)
	if err != nil || !bytes.Equal(stripped, p.signBytes) {
		return d, errors.New("stripped sign bytes do not rebuild the upstream sign bytes")
	}
	for _, s := range p.msg.ValidatorSignatures {
		d.ValidatorSignatures = append(d.ValidatorSignatures, hex.EncodeToString(s))
	}
	for i, v := range e.vals {
		state := "absent"
		if i < len(p.msg.ValidatorSignatures) {
			switch s := p.msg.ValidatorSignatures[i]; {
			case len(s) == 0:
				state = "empty"
			case ed25519.Verify(v.pubKey, p.signBytes, s):
				state = "valid"
			default:
				state = "invalid"
			}
		}
		d.Validators = append(d.Validators, valDoc{Index: strconv.Itoa(i), PubKeyHex: hex.EncodeToString(v.pubKey),
			AddressHex: hex.EncodeToString(v.address), Tokens: strconv.FormatInt(v.tokens, 10),
			ConsensusPower: strconv.FormatInt(v.consPower, 10), Signature: state})
	}
	var real cmtproto.Header
	if err := real.Unmarshal(in.headers[livePromiseHeight]); err != nil {
		return d, err
	}
	hi := e.hist.Header
	if hi.ChainID != real.ChainID || hi.Height != real.Height || !hi.Time.Equal(real.Time) ||
		!bytes.Equal(hi.NextValidatorsHash, real.NextValidatorsHash) || !bytes.Equal(hi.AppHash, real.AppHash) ||
		!bytes.Equal(hi.ProposerAddress, real.ProposerAddress) || len(hi.ValidatorsHash) != 0 {
		return d, errors.New("HistoricalInfo header differs from the header at the promise height")
	}
	d.HistoricalInfoHeader = histHeaderNote
	for h := int64(livePromiseHeight); h <= livePFFHeight; h++ {
		hd, err := decodeHeader(in.headers[h])
		if err != nil {
			return d, err
		}
		d.HeaderHashes = append(d.HeaderHashes, heightHash{Height: strconv.FormatInt(h, 10), HashHex: hex.EncodeToString(hd.Hash())})
	}
	for _, h := range []int64{livePromiseHeight, livePromiseHeight + 1} {
		vs, err := decodeValset(in.valsets[h])
		if err != nil {
			return d, err
		}
		d.ValsetHashes = append(d.ValsetHashes, heightHash{Height: strconv.FormatInt(h, 10), HashHex: hex.EncodeToString(vs.Hash())})
	}
	h0, _ := decodeHeader(in.headers[livePromiseHeight])
	h1, _ := decodeHeader(in.headers[livePromiseHeight+1])
	if !bytes.Equal(h0.ValidatorsHash, d.mustHash(0)) {
		return d, errors.New("valset at the promise height does not match its header")
	}
	d.CV7Both = bytes.Equal(h0.NextValidatorsHash, h1.ValidatorsHash) && bytes.Equal(h1.ValidatorsHash, d.mustHash(1))
	if !d.CV7Both {
		return d, errors.New("the two CV7 header fields disagree on the live data")
	}
	return d, nil
}

func (d liveDerived) mustHash(i int) []byte {
	b, _ := hex.DecodeString(d.ValsetHashes[i].HashHex)
	return b
}

type flip struct {
	id, desc string
	target   string
	height   int64
	offset   func(in inputs, e evaluation) (int, error)
	want     []string
}

func targetBytes(in inputs, target string, height int64) ([]byte, error) {
	switch target {
	case "pff_tx":
		return in.tx, nil
	case "historical_info":
		return in.hist, nil
	case "cometbft_valset":
		return in.valsets[height], nil
	case "header":
		return in.headers[height], nil
	}
	return nil, fmt.Errorf("unknown target %s", target)
}

func firstNonEmpty(sigs [][]byte, fromEnd bool) int {
	for k := range sigs {
		i := k
		if fromEnd {
			i = len(sigs) - 1 - k
		}
		if len(sigs[i]) > 0 {
			return i
		}
	}
	return -1
}

func mutations(base inputs, e evaluation) ([]mutation, []mutation, error) {
	sigs := e.pff.msg.ValidatorSignatures
	pp := e.pff.pp
	sigAt := func(i int) func(inputs, evaluation) (int, error) {
		return func(in inputs, _ evaluation) (int, error) {
			o, err := uniqueIndex(in.tx, sigs[i], fmt.Sprintf("signature %d", i))
			return o + 17, err
		}
	}
	inTx := func(needle []byte, what string, add int) func(inputs, evaluation) (int, error) {
		return func(in inputs, _ evaluation) (int, error) {
			o, err := uniqueIndex(in.tx, needle, what)
			return o + add, err
		}
	}
	valKey := func(target string, height int64, pick func(n int) int) func(inputs, evaluation) (int, error) {
		return func(in inputs, _ evaluation) (int, error) {
			b, err := targetBytes(in, target, height)
			if err != nil {
				return 0, err
			}
			i := pick(len(e.vals))
			for ; i < len(e.vals); i++ {
				if bytes.Count(b, e.vals[i].pubKey) == 1 {
					return bytes.Index(b, e.vals[i].pubKey) + 9, nil
				}
			}
			return 0, errors.New("no validator key occurs exactly once")
		}
	}
	// tag is the protobuf key byte of the header field: the value alone can
	// occur twice (validators_hash equals next_validators_hash when the set
	// does not change).
	inHeader := func(height int64, tag byte, field func(core.Header) []byte, add int) func(inputs, evaluation) (int, error) {
		return func(in inputs, _ evaluation) (int, error) {
			h, err := decodeHeader(in.headers[height])
			if err != nil {
				return 0, err
			}
			v := field(h)
			needle := append([]byte{tag, byte(len(v))}, v...)
			o, err := uniqueIndex(in.headers[height], needle, fmt.Sprintf("header %d field", height))
			return o + 2 + add, err
		}
	}
	first := firstNonEmpty(sigs, false)
	last := firstNonEmpty(sigs, true)
	stop, _ := strconv.Atoi(e.report.StopIndex)
	if last <= stop {
		return nil, nil, errors.New("live certificate has no signature after the stop point")
	}
	tokensOf := func(in inputs, _ evaluation) (int, error) {
		for i := len(e.vals) - 1; i >= 0; i-- {
			t := []byte(strconv.FormatInt(e.vals[i].tokens, 10))
			// Validator.tokens is field 5, length-delimited.
			field := append([]byte{0x2a, byte(len(t))}, t...)
			if bytes.Count(in.hist, field) == 1 && t[len(t)-1] != '0' {
				return bytes.Index(in.hist, field) + len(field) - 1, nil
			}
		}
		return 0, errors.New("no unique token string")
	}

	must := []flip{
		{"sig_first_signature", "First non-empty validator signature in the PFF tx, one byte flipped: it is checked before the quorum is reached, so the certificate is rejected (the chain rejects it too).",
			"pff_tx", 0, sigAt(first), []string{"CV6"}},
		{"promise_commitment", "One byte of the promise commitment: the owner signature and every validator signature are over other bytes, and the binding to payload_ref fails.",
			"pff_tx", 0, inTx(pp.Commitment[:], "commitment", 7), []string{"CV2", "CV3", "CV6"}},
		{"promise_namespace", "Last byte of the promise namespace (still a valid v0 namespace).",
			"pff_tx", 0, inTx(pp.Namespace.Bytes(), "namespace", len(pp.Namespace.Bytes())-1), []string{"CV2", "CV3", "CV6"}},
		{"promise_chain_id", "One byte of the promise chain id ('mocha-5' to 'mocha-4'). The headers that commit to the validator set carry 'mocha-5', so CV7 fails too.",
			"pff_tx", 0, inTx([]byte(pp.ChainID), "chain id", len(pp.ChainID)-1), []string{"CV2", "CV3", "CV6", "CV7"}},
		{"promise_owner_signature", "One byte of the owner (escrow signer) signature: only the owner check fails; validators signed the sign bytes, which do not include it.",
			"pff_tx", 0, inTx(pp.Signature, "owner signature", 40), []string{"CV3"}},
		{"valset_signer_key", "One byte of the consensus key of the validator at the first signed position in the archived HistoricalInfo: its signature no longer verifies and the set no longer matches the header.",
			"historical_info", 0, valKey("historical_info", 0, func(int) int { return first }), []string{"CV6", "CV7"}},
		{"valset_last_key", "One byte of the consensus key of the last validator in the archived HistoricalInfo (not needed for the quorum): only the header cross-check catches it.",
			"historical_info", 0, valKey("historical_info", 0, func(n int) int { return n - 1 }), []string{"CV7"}},
		{"cometbft_valset_key", "One byte of a validator key in the CometBFT set at promise height + 1: its hash no longer equals next_validators_hash / validators_hash.",
			"cometbft_valset", livePromiseHeight + 1, valKey("cometbft_valset", livePromiseHeight+1, func(int) int { return 0 }), []string{"CV7"}},
		{"header_promise_next_validators_hash", "One byte of next_validators_hash in the header at the promise height: it no longer matches, and validators_hash at promise height + 1 cannot stand in, because that header's last_block_id no longer equals the promise header's hash; the backward hash chain breaks at the same place.",
			"header", livePromiseHeight, inHeader(livePromiseHeight, 0x4a, func(h core.Header) []byte { return h.NextValidatorsHash }, 3), []string{"CV7", "HT3"}},
		{"header_next_validators_hash", "One byte of validators_hash in the header at promise height + 1.",
			"header", livePromiseHeight + 1, inHeader(livePromiseHeight+1, 0x42, func(h core.Header) []byte { return h.ValidatorsHash }, 3), []string{"HT3"}},
		{"header_middle_data_hash", "One byte of data_hash in a header between the promise height and the anchor: the backward hash chain breaks.",
			"header", livePromiseHeight + 3, inHeader(livePromiseHeight+3, 0x3a, func(h core.Header) []byte { return h.DataHash }, 3), []string{"HT3"}},
		{"header_trusted_app_hash", "One byte of app_hash in the trusted header (the anchor height): its hash differs from the trusted hash.",
			"header", livePFFHeight, inHeader(livePFFHeight, 0x5a, func(h core.Header) []byte { return h.AppHash }, 3), []string{"HT2"}},
	}
	undetected := []flip{
		{"sig_after_quorum", "Last non-empty validator signature, one byte flipped. It lies after the point where the walk reaches the requirement, so neither the chain nor the network rule checks it: the verdict stays accept; the verifier report counts it as invalid_after_stop (a warning) and leaves its power out of signed_power.",
			"pff_tx", 0, sigAt(last), nil},
		{"valset_tokens_low_digit", "Last decimal digit of one validator's tokens in the archived HistoricalInfo. Token amounts are not committed by any header: CV7 sees only floor(tokens / 10^6), which this flip leaves unchanged, and the verdict here does not move. The archive is trusted for availability only, so a forger with write access could move total and signed power within each 10^6 bucket; at the exact two-thirds edge that could flip a verdict.",
			"historical_info", 0, tokensOf, nil},
	}

	run := func(fl flip) (mutation, evaluation, error) {
		mut := base.clone()
		b, err := targetBytes(mut, fl.target, fl.height)
		if err != nil {
			return mutation{}, evaluation{}, err
		}
		o, err := fl.offset(base, e)
		if err != nil {
			return mutation{}, evaluation{}, fmt.Errorf("%s: %w", fl.id, err)
		}
		if o < 0 || o >= len(b) {
			return mutation{}, evaluation{}, fmt.Errorf("%s: offset out of range", fl.id)
		}
		b[o] ^= 0x01
		me := evaluate(mut)
		m := mutation{ID: fl.id, Description: fl.desc, Target: fl.target, Offset: strconv.Itoa(o), XOR: "01", Expect: outcome(me)}
		if fl.height != 0 {
			m.Height = strconv.FormatInt(fl.height, 10)
		}
		return m, me, nil
	}

	var out, und []mutation
	for _, fl := range must {
		m, _, err := run(fl)
		if err != nil {
			return nil, nil, err
		}
		if m.Expect.Verdict != "reject" || !slices.Equal(m.Expect.Fails, fl.want) {
			return nil, nil, fmt.Errorf("%s: got %s %v, want reject %v", fl.id, m.Expect.Verdict, m.Expect.Fails, fl.want)
		}
		out = append(out, m)
	}
	for _, fl := range undetected {
		m, me, err := run(fl)
		if err != nil {
			return nil, nil, err
		}
		if m.Expect.Verdict != "accept" {
			return nil, nil, fmt.Errorf("%s: got %s %v, want accept", fl.id, m.Expect.Verdict, m.Expect.Fails)
		}
		m.Expect.Certificate = me.report
		und = append(und, m)
	}
	if und[0].Expect.Certificate == nil || und[0].Expect.Certificate.InvalidAfterStop != 1 {
		return nil, nil, errors.New("sig_after_quorum: report does not count the invalid entry")
	}
	return out, und, nil
}

// keyFor derives test-only validator keys; they sign nothing but vectors.
func keyFor(i int) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("edicta/v0/vectors/fibre_cert/validator/" + strconv.Itoa(i)))
	return ed25519.NewKeyFromSeed(seed[:])
}

type bspec struct {
	id, desc string
	powers   []int64
	sigs     []string // "s" own key, "" empty, "x" own key with a flipped byte, "o<j>" key j, "short" 63 bytes, "k<j>" key j beyond the set, "zero64" 64 zero bytes
	verdict  string
	rule     string
	warn     bool
	keys     []int       // key index at each position; nil means the position itself
	trunc    map[int]int // position -> key length after truncation
}

const maxTotal = int64(core.MaxTotalVotingPower)

func boundary(msg []byte) (boundaryDoc, error) {
	specs := []bspec{
		{"exactly_two_thirds_small", "Three validators of power 1, two sign: signed 2 of 3 equals the requirement floor(2*3/3) = 2. Accepted by the network rule; exactly two thirds, so at_most_two_thirds is set (warning).",
			[]int64{1, 1, 1}, []string{"s", "s", ""}, "accept", "", true, nil, nil},
		{"exactly_two_thirds_large", "Power 100 each, first and last sign: 200 of 300. Accepted, warning.",
			[]int64{100, 100, 100}, []string{"s", "", "s"}, "accept", "", true, nil, nil},
		{"just_above_two_thirds", "Powers 101, 100, 99; the first two sign: 201 of 300, one above two thirds. Accepted, no warning.",
			[]int64{101, 100, 99}, []string{"s", "s", ""}, "accept", "", false, nil, nil},
		{"just_below_two_thirds", "Powers 100, 100, 99, 1; 199 of 300 signed, one below the requirement 200. Rejected.",
			[]int64{100, 100, 99, 1}, []string{"s", "", "s", ""}, "reject", "CV6", true, nil, nil},
		{"two_thirds_by_last_entry", "Same set, the power-1 validator also signs: 200 of 300, reached at the last entry. Accepted, warning.",
			[]int64{100, 100, 99, 1}, []string{"s", "", "s", "s"}, "accept", "", true, nil, nil},
		{"floor_admits_below_two_thirds", "Powers 40, 34, 26 (total 100); 40 + 26 = 66 signed. The requirement floor(200/3) = 66 admits a share of 0.66, below two thirds. Accepted (network rule), warning.",
			[]int64{40, 34, 26}, []string{"s", "", "s"}, "accept", "", true, nil, nil},
		{"floor_just_below", "Powers 39, 35, 26 (total 100); 39 + 26 = 65 signed, one below floor(200/3) = 66. Rejected.",
			[]int64{39, 35, 26}, []string{"s", "", "s"}, "reject", "CV6", true, nil, nil},
		{"zero_signatures_total_one", "One validator of power 1 and no signatures: the requirement floor(2/3) = 0 is met by the empty sum, so the network rule accepts. Unreachable on a real chain (total power is many orders larger), recorded so implementations copy the arithmetic, not an intuition.",
			[]int64{1}, []string{}, "accept", "", true, nil, nil},
		{"more_signatures_than_validators", "Three validators, four entries: rejected before any signature is checked, even though the first two entries already reach the requirement.",
			[]int64{1, 1, 1}, []string{"s", "s", "s", "k3"}, "reject", "CV5", false, nil, nil},
		{"fewer_signatures_quorum", "Three validators, two entries, both valid: the list is shorter than the set, which the chain allows; 2 of 3 is met. Accepted, warning.",
			[]int64{1, 1, 1}, []string{"s", "s"}, "accept", "", true, nil, nil},
		{"fewer_signatures_no_quorum", "Three validators, one entry: 1 of 3. Rejected.",
			[]int64{1, 1, 1}, []string{"s"}, "reject", "CV6", true, nil, nil},
		{"all_entries_empty", "Three validators, three empty entries. Rejected.",
			[]int64{1, 1, 1}, []string{"", "", ""}, "reject", "CV6", true, nil, nil},
		{"empty_list", "Three validators, no entries. Rejected.",
			[]int64{1, 1, 1}, []string{}, "reject", "CV6", true, nil, nil},
		{"empty_entries_interleaved", "Seven validators of power 1, entries empty at 0, 2 and valid at 1, 3, 4, 5, 6: the requirement 4 is reached at index 5; signed power over the whole list is 5. Accepted, no warning.",
			[]int64{1, 1, 1, 1, 1, 1, 1}, []string{"", "s", "", "s", "s", "s", "s"}, "accept", "", false, nil, nil},
		{"invalid_before_quorum", "First entry is a signature with one byte flipped: rejected even though the other two reach the requirement.",
			[]int64{1, 1, 1}, []string{"x", "s", "s"}, "reject", "CV6", true, nil, nil},
		{"invalid_after_quorum", "Third entry invalid after the first two reached the requirement: the chain never checks it. Accepted; the report counts it as invalid_after_stop.",
			[]int64{1, 1, 1}, []string{"s", "s", "x"}, "accept", "", true, nil, nil},
		{"swapped_positions", "Two valid signatures in each other's slots: positions are fixed by the list, so both fail. Rejected.",
			[]int64{1, 1, 1}, []string{"o1", "o0", ""}, "reject", "CV6", true, nil, nil},
		{"short_signature", "A 63-byte entry is not empty and does not verify. Rejected.",
			[]int64{1, 1, 1}, []string{"short", "s", "s"}, "reject", "CV6", true, nil, nil},
		{"total_one_invalid_first", "One validator of power 1 and a 64-byte zero signature. The requirement floor(2/3) = 0 is met before any entry, but the keeper verifies each non-empty entry before it asks whether the requirement is met, so the bad entry rejects. No Add returns true, so stop_index is none.",
			[]int64{1}, []string{"zero64"}, "reject", "CV6", true, nil, nil},
		{"duplicate_signer", "The audit example as a list: A (34%) repeated four times, then B and C (33% each); A's signature in each of the four A slots. Counting every copy would give 136e6 of 202e6, above the requirement; the keeper's core.NewValidatorSet panics on the duplicate address, which fails the tx, so the list is rejected before any signature is walked (no certificate).",
			[]int64{34_000_000, 34_000_000, 34_000_000, 34_000_000, 33_000_000, 33_000_000}, []string{"s", "s", "s", "s"}, "reject", "CV4", false, []int{0, 0, 0, 0, 1, 2}, nil},
		{"zero_power", "Powers 34e6, 33e6 and 0: core.NewValidatorSet refuses a validator with power 0 (it would be a removal), so the keeper rejects the list.",
			[]int64{34_000_000, 33_000_000, 0}, []string{"s", "s"}, "reject", "CV4", false, nil, nil},
		{"total_above_max", "Powers MaxTotalVotingPower (MaxInt64 / 8) and 1: the total exceeds the maximum and core.NewValidatorSet panics, so the keeper rejects the list although the first validator alone would meet the requirement.",
			[]int64{maxTotal, 1}, []string{"s"}, "reject", "CV4", false, nil, nil},
		{"total_at_max", "Powers MaxTotalVotingPower - 1 and 1: the total is exactly the maximum, which core.NewValidatorSet allows; the first validator meets floor(2 * total / 3). Accepted, no warning. Control for total_above_max.",
			[]int64{maxTotal - 1, 1}, []string{"s"}, "accept", "", false, nil, nil},
		{"bad_key_length", "Three validators of power 1, the second key cut to 31 bytes (truncated_to): the keeper rejects the tx on any key that is not 32 bytes, before building the set, although the first two entries would meet the requirement.",
			[]int64{1, 1, 1}, []string{"s", "s"}, "reject", "CV4", false, nil, map[int]int{1: 31}},
	}
	doc := boundaryDoc{
		Message:     "live.derived.sign_bytes_hex (every boundary signature is over the live promise sign bytes)",
		KeySeedRule: "validator key k: Ed25519 seed = SHA-256(ASCII \"edicta/v0/vectors/fibre_cert/validator/\" || decimal k); test keys, never used outside vectors",
	}
	for _, s := range specs {
		c := boundaryCase{ID: s.id, Description: s.desc, SignaturesHex: []string{}}
		keyAt := func(i int) int {
			if s.keys != nil {
				return s.keys[i]
			}
			return i
		}
		var vals []valEntry
		for i, p := range s.powers {
			pub := []byte(keyFor(keyAt(i)).Public().(ed25519.PublicKey))
			bv := boundaryVal{KeyIndex: strconv.Itoa(keyAt(i)), Power: strconv.FormatInt(p, 10)}
			if n, ok := s.trunc[i]; ok {
				pub = pub[:n]
				bv.TruncatedTo = strconv.Itoa(n)
			}
			bv.PubKeyHex = hex.EncodeToString(pub)
			a := sha256.Sum256(pub)
			vals = append(vals, valEntry{pubKey: pub, address: a[:20], tokens: p, consPower: p / powerReduction})
			c.Validators = append(c.Validators, bv)
		}
		var sigs [][]byte
		for i, t := range s.sigs {
			var sig []byte
			switch {
			case t == "":
			case t == "zero64":
				sig = make([]byte, 64)
			case t == "s":
				sig = ed25519.Sign(keyFor(keyAt(i)), msg)
			case t == "x":
				sig = ed25519.Sign(keyFor(keyAt(i)), msg)
				sig[5] ^= 0x01
			case t == "short":
				sig = ed25519.Sign(keyFor(keyAt(i)), msg)[:63]
			case t[0] == 'o' || t[0] == 'k':
				j, err := strconv.Atoi(t[1:])
				if err != nil {
					return doc, err
				}
				sig = ed25519.Sign(keyFor(j), msg)
			default:
				return doc, fmt.Errorf("%s: bad signature spec %q", s.id, t)
			}
			sigs = append(sigs, sig)
			c.SignaturesHex = append(c.SignaturesHex, hex.EncodeToString(sig))
		}
		rule, _ := keeperVerdict(msg, 1, vals, sigs)
		verdict := "accept"
		if rule != "" {
			verdict = "reject"
		}
		if verdict != s.verdict || rule != s.rule {
			return doc, fmt.Errorf("%s: upstream says %s %s, expected %s %s", s.id, verdict, rule, s.verdict, s.rule)
		}
		r := report(msg, vals, sigs)
		if (r == nil) != (rule == "CV4") {
			return doc, fmt.Errorf("%s: certificate present %v with rule %q", s.id, r != nil, rule)
		}
		if r != nil && r.AtMostTwoThirds != s.warn {
			return doc, fmt.Errorf("%s: at_most_two_thirds %v, expected %v", s.id, r.AtMostTwoThirds, s.warn)
		}
		c.Expect = boundaryExpect{Verdict: verdict, Rule: rule, Certificate: r}
		doc.Cases = append(doc.Cases, c)
	}
	return doc, nil
}

// upstreamAccepts asks validator.SignatureSet whether signed of total power
// meets its threshold: two validators of power signed and total - signed,
// only the first signs.
func upstreamAccepts(signed, total int64) (bool, error) {
	msg := []byte("threshold")
	var vals []*core.Validator
	if signed > 0 {
		vals = append(vals, core.NewValidator(cmted25519.PubKey(keyFor(0).Public().(ed25519.PublicKey)), signed))
	}
	if total-signed > 0 {
		vals = append(vals, core.NewValidator(cmted25519.PubKey(keyFor(1).Public().(ed25519.PublicKey)), total-signed))
	}
	set := validator.Set{ValidatorSet: core.NewValidatorSet(vals), Height: 1}
	ss := set.NewSignatureSet(cmtmath.Fraction{Numerator: 2, Denominator: 3}, msg)
	if signed > 0 {
		enough, err := ss.Add(vals[0], ed25519.Sign(keyFor(0), msg))
		if err != nil {
			return false, err
		}
		if enough {
			return true, nil
		}
	}
	_, err := ss.Signatures()
	return err == nil, nil
}

func thresholds(live *certReport) ([]thresholdCase, error) {
	ls, _ := strconv.ParseInt(live.SignedPower, 10, 64)
	lt, _ := strconv.ParseInt(live.TotalPower, 10, 64)
	maxT := maxTotal
	rows := []struct {
		id            string
		signed, total int64
		note          string
	}{
		{"t1_s0", 0, 1, "requirement floor(2/3) = 0: the empty sum suffices"},
		{"t2_s0", 0, 2, ""},
		{"t2_s1", 1, 2, "floor(4/3) = 1: half the power is accepted"},
		{"t3_s1", 1, 3, ""},
		{"t3_s2", 2, 3, "exactly two thirds"},
		{"t100_s65", 65, 100, ""},
		{"t100_s66", 66, 100, "below two thirds, accepted through the floor"},
		{"t100_s67", 67, 100, ""},
		{"t300_s199", 199, 300, ""},
		{"t300_s200", 200, 300, "exactly two thirds"},
		{"t300_s201", 201, 300, ""},
		{"live", ls, lt, "the live certificate's signed and total token power"},
		{"tmax_req_minus_1", maxT*2/3 - 1, maxT, "total = CometBFT MaxTotalVotingPower (MaxInt64 / 8): 2 * total does not overflow int64"},
		{"tmax_req", maxT * 2 / 3, maxT, ""},
		{"tmax_req_plus_1", maxT*2/3 + 1, maxT, ""},
	}
	var out []thresholdCase
	for _, r := range rows {
		req := r.total * 2 / 3
		acc := r.signed >= req
		up, err := upstreamAccepts(r.signed, r.total)
		if err != nil {
			return nil, err
		}
		if up != acc {
			return nil, fmt.Errorf("threshold %s: upstream %v, floor rule %v", r.id, up, acc)
		}
		warn := new(big.Int).Mul(big.NewInt(3), big.NewInt(r.signed)).Cmp(new(big.Int).Mul(big.NewInt(2), big.NewInt(r.total))) <= 0
		out = append(out, thresholdCase{ID: r.id, Signed: strconv.FormatInt(r.signed, 10), Total: strconv.FormatInt(r.total, 10),
			Required: strconv.FormatInt(req, 10), Accept: acc, AtMostTwoThirds: warn, Note: r.note})
	}
	return out, nil
}
