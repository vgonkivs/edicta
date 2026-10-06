package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"cosmossdk.io/math"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	core "github.com/cometbft/cometbft/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	sdked25519 "github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

type valsetDoc struct {
	Description string       `json:"description"`
	Message     string       `json:"message"`
	Promise     string       `json:"promise"`
	KeySeedRule string       `json:"key_seed_rule"`
	Headers     string       `json:"headers"`
	Cases       []valsetCase `json:"cases"`
}

type valsetVal struct {
	KeyIndex    string `json:"key_index"`
	PubKeyHex   string `json:"pubkey_hex"`
	TruncatedTo string `json:"truncated_to,omitempty"`
	Tokens      string `json:"tokens"`
}

type valsetCase struct {
	ID                string       `json:"id"`
	Description       string       `json:"description"`
	Validators        []valsetVal  `json:"validators,omitempty"`
	HistoricalInfoHex string       `json:"historical_info_hex"`
	PromiseHeaderHex  string       `json:"promise_header_hex"`
	SignaturesHex     []string     `json:"signatures_hex"`
	Expect            valsetExpect `json:"expect"`
}

// Network is what validateValidatorSignatures returns with this list as its
// HistoricalInfo; the verdict adds the archive-side checks (CV4 height, CV7).
type valsetExpect struct {
	Verdict     string        `json:"verdict"`
	Fails       []string      `json:"fails"`
	Network     networkResult `json:"network"`
	CV7Matched  string        `json:"cv7_matched"`
	Certificate *certReport   `json:"certificate,omitempty"`
}

type networkResult struct {
	Verdict string `json:"verdict"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type vmember struct {
	key    int
	tokens int64
	trunc  int
}

func (m vmember) pub() []byte {
	pk := []byte(keyFor(m.key).Public().(ed25519.PublicKey))
	if m.trunc > 0 {
		return pk[:m.trunc]
	}
	return pk
}

// cometSet is the CometBFT set a header commits to: consensus power per key.
func cometSet(ms []vmember) *core.ValidatorSet {
	var vs []*core.Validator
	for _, m := range ms {
		vs = append(vs, core.NewValidator(cmted25519.PubKey(keyFor(m.key).Public().(ed25519.PublicKey)), m.tokens/powerReduction))
	}
	return core.NewValidatorSet(vs)
}

func histBytes(hdrTemplate stakingtypes.HistoricalInfo, next []byte, ms []vmember) ([]byte, error) {
	hi := stakingtypes.HistoricalInfo{Header: hdrTemplate.Header}
	hi.Header.NextValidatorsHash = next
	for _, m := range ms {
		pk := sdked25519.PubKey{Key: m.pub()}
		v, err := pk.Marshal()
		if err != nil {
			return nil, err
		}
		hi.Valset = append(hi.Valset, stakingtypes.Validator{
			ConsensusPubkey:   &codectypes.Any{TypeUrl: ed25519PubKeyURL, Value: v},
			Status:            stakingtypes.Bonded,
			Tokens:            math.NewInt(m.tokens),
			DelegatorShares:   math.LegacyNewDec(m.tokens),
			MinSelfDelegation: math.OneInt(),
			Commission: stakingtypes.Commission{CommissionRates: stakingtypes.CommissionRates{
				Rate: math.LegacyZeroDec(), MaxRate: math.LegacyZeroDec(), MaxChangeRate: math.LegacyZeroDec()}},
		})
	}
	return hi.Marshal()
}

func headerBytes(h core.Header) ([]byte, error) {
	return h.ToProto().Marshal()
}

type vspec struct {
	id, desc string
	list     []vmember
	sigs     []string  // per list position: "s" signs with that position's key, "g" garbage, "" empty
	evidence []vmember // set behind the promise header's next_validators_hash
	promise  func(p *core.Header)
	fails    []string
	network  string // keeper rule, "" accepts
	// resorted: the list is not in the stored order, so the keeper's state is
	// the same entries as NewHistoricalInfo stores them, not the list itself.
	resorted bool
}

func valsetCases(base inputs, live evaluation) (valsetDoc, error) {
	msg := live.pff.signBytes
	ph := int64(livePromiseHeight)
	doc := valsetDoc{
		Description: "Validator-set evidence cases (CV4 to CV7) for the live promise: each case gives the archived HistoricalInfo, the header at the promise height and the signature list; the owner signature and binding are the live ones. fails lists the rules that fail; network is the keeper's answer with the chain's state for these entries: the same entries in the order SDK NewHistoricalInfo stores them (consensus power descending, then address). For every case but valset_out_of_order that is the archived list itself.",
		Message:     "live.derived.sign_bytes_hex",
		Promise:     "live.derived.promise (chain_id mocha-5, height 1402813)",
		KeySeedRule: "as boundary.key_seed_rule",
		Headers:     "Synthetic cases: the live header at 1402813 with validators_hash and next_validators_hash replaced by the case's evidence set (and height or chain id changed where the case says so). It does not chain to the live trusted header, so header trust (HT2, HT3) is out of scope for them; the fails list covers CV4 to CV7 only. Cases ending in _live use the live header unchanged, so HT2 and HT3 hold.",
	}

	A := vmember{key: 0, tokens: 34_000_000}
	B := vmember{key: 1, tokens: 33_000_000}
	C := vmember{key: 2, tokens: 33_000_000}
	abc := sortedMembers([]vmember{A, B, C})
	// The two 33% validators swapped: same multiset, same CometBFT set hash.
	swapped := []vmember{abc[0], abc[2], abc[1]}
	ab := sortedMembers([]vmember{A, B})
	bShort := B
	bShort.trunc = 31
	cZero := C
	cZero.tokens = 0
	big := vmember{key: 0, tokens: maxTotal}
	one := vmember{key: 1, tokens: powerReduction}
	signAB := func(ms []vmember) []string {
		out := make([]string, len(ms))
		for i, m := range ms {
			if m.key != C.key {
				out[i] = "s"
			}
		}
		return out
	}

	specs := []vspec{
		{"valset_synthetic_ok", "Control: A 34e6, B 33e6, C 33e6 tokens; A and B sign; the promise header's next_validators_hash commits to the set. Accepted.",
			abc, signAB(abc), abc, nil, nil, "", false},
		{"valset_honest_insufficient", "The audit's real set (A 34%, B 33%, C 33%) with only A's signature: 34e6 below the requirement 66666666. Rejected by the network and here. valset_duplicate_signer forges this certificate.",
			abc, []string{"s"}, abc, nil, []string{"CV6"}, "CV6", false},
		{"valset_duplicate_signer", "The audit example: the archived list repeats A four times ([A, A, A, A, B, C]) and the signature list holds A's signature in each A slot; the headers and CometBFT set are the genuine {A, B, C}. Counting each copy would give 136e6 of 202e6, above the requirement. core.NewValidatorSet panics on the duplicate address, so the keeper rejects the tx (CV4), and the list stands for no CometBFT set, so CV7 fails as well.",
			[]vmember{A, A, A, A, B, C}, []string{"s", "s", "s", "s"}, abc, nil, []string{"CV4", "CV7"}, "CV4", false},
		{"valset_zero_power", "Archived list A 34e6, B 33e6, C 0 tokens; headers commit to {A, B}. core.NewValidatorSet refuses power 0, so the keeper rejects the list (CV4), and CV7 fails because the list stands for no CometBFT set.",
			[]vmember{A, B, cZero}, []string{"s", "s"}, ab, nil, []string{"CV4", "CV7"}, "CV4", false},
		{"valset_total_above_max", "Archived list A with MaxTotalVotingPower tokens and B with 10^6; the headers commit to the consensus powers (1152921504606, 1), which CometBFT accepts, so CV7 holds. The keeper counts tokens: the total exceeds MaxTotalVotingPower, core.NewValidatorSet panics and the tx fails. Only CV4 fails.",
			[]vmember{big, one}, []string{"s"}, []vmember{big, one}, nil, []string{"CV4"}, "CV4", false},
		{"valset_bad_key_length", "Archived list A, B, C with B's key cut to 31 bytes; headers commit to the genuine {A, B, C}. The keeper rejects any key that is not 32 bytes (CV4) and the list matches no CometBFT set (CV7).",
			[]vmember{A, bShort, C}, []string{"s", "s"}, abc, nil, []string{"CV4", "CV7"}, "CV4", false},
		{"promise_header_other_set", "The promise header's next_validators_hash commits to {A, B}, not to the list {A, B, C}. A header at promise height + 1 that carries {A, B, C} cannot help: on a valid chain its validators_hash equals this field. CV7 fails; the network accepts the certificate.",
			abc, signAB(abc), ab, nil, []string{"CV7"}, "", false},
		{"promise_header_wrong_height", "The header commits to the list but its height is promise height + 1. CV7 fails; the network accepts.",
			abc, signAB(abc), abc, func(p *core.Header) { p.Height++ }, []string{"CV7"}, "", false},
		{"promise_header_other_chain", "The header commits to the list but its chain id is mocha-4. CV7 fails; the network accepts.",
			abc, signAB(abc), abc, func(p *core.Header) { p.ChainID = "mocha-4" }, []string{"CV7"}, "", false},
		{"valset_out_of_order", "The audit's permutation: the stored order is A 34e6 then the two 33e6 validators by address (X, Y); the archived list swaps them ([A, Y, X]) and the signatures are [A's, Y's, 64 garbage bytes]. NewValidatorSet sorts, so the list hashes to the promise header's next_validators_hash. Walked over the archived list it reaches 67e6 >= 66666666 at index 1 and never checks the garbage. The keeper walks the stored order [A, X, Y]: index 1 is not X's signature, so the chain rejects (CV6). The verifier fails CV7, which compares the list position by position with the sorted set.",
			swapped, []string{"s", "s", "g"}, abc, nil, []string{"CV7"}, "CV6", true},
	}

	livePH, err := decodeHeader(base.headers[ph])
	if err != nil {
		return doc, err
	}
	for _, s := range specs {
		pnv := cometSet(s.evidence).Hash()
		p := livePH
		p.ValidatorsHash, p.NextValidatorsHash = pnv, pnv
		if s.promise != nil {
			s.promise(&p)
		}
		hist, err := histBytes(live.hist, pnv, s.list)
		if err != nil {
			return doc, err
		}
		pb, err := headerBytes(p)
		if err != nil {
			return doc, err
		}
		var sigs [][]byte
		for i, t := range s.sigs {
			var sig []byte
			switch t {
			case "s":
				sig = ed25519.Sign(keyFor(s.list[i].key), msg)
			case "g":
				g := sha512.Sum512([]byte("edicta/v0/vectors/fibre_cert/garbage/" + s.id))
				sig = g[:]
			}
			sigs = append(sigs, sig)
		}
		keeperHist := hist
		if s.resorted {
			if keeperHist, err = storedOrder(hist); err != nil {
				return doc, fmt.Errorf("%s: %w", s.id, err)
			}
			if bytes.Equal(keeperHist, hist) {
				return doc, fmt.Errorf("%s: list is already in the stored order", s.id)
			}
		}
		c, err := valsetCase1(s.id, s.desc, msg, ph, hist, keeperHist, pb, sigs, s.fails, s.network)
		if err != nil {
			return doc, err
		}
		for _, m := range s.list {
			v := valsetVal{KeyIndex: strconv.Itoa(m.key), PubKeyHex: hex.EncodeToString(m.pub()), Tokens: strconv.FormatInt(m.tokens, 10)}
			if m.trunc > 0 {
				v.TruncatedTo = strconv.Itoa(m.trunc)
			}
			c.Validators = append(c.Validators, v)
		}
		doc.Cases = append(doc.Cases, c)
	}

	lc, err := duplicateLive(base, live)
	if err != nil {
		return doc, err
	}
	doc.Cases = append(doc.Cases, lc)
	return doc, nil
}

// sortedMembers orders a list as x/staking stores it for distinct consensus
// powers: power descending, then address ascending.
func sortedMembers(ms []vmember) []vmember {
	out := slices.Clone(ms)
	slices.SortStableFunc(out, func(a, b vmember) int {
		if a.tokens != b.tokens {
			if a.tokens > b.tokens {
				return -1
			}
			return 1
		}
		x, y := sha256.Sum256(a.pub()), sha256.Sum256(b.pub())
		return slices.Compare(x[:20], y[:20])
	})
	return out
}

// storedOrder is the HistoricalInfo the chain would hold for the same
// entries: upstream NewHistoricalInfo re-sorts them as x/staking stores them.
// The keys are unpacked first, because the address tie-break reads them.
func storedOrder(hist []byte) ([]byte, error) {
	var hi stakingtypes.HistoricalInfo
	if err := hi.Unmarshal(hist); err != nil {
		return nil, err
	}
	reg := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(reg)
	vs := stakingtypes.Validators{Validators: hi.Valset}
	if err := vs.UnpackInterfaces(reg); err != nil {
		return nil, err
	}
	out := stakingtypes.NewHistoricalInfo(hi.Header, vs, math.NewInt(powerReduction))
	return out.Marshal()
}

// keeperHist is the keeper's state; it differs from hist only for a list that
// is not in the stored order.
func valsetCase1(id, desc string, msg []byte, ph int64, hist, keeperHist, promiseHeader []byte, sigs [][]byte, wantFails []string, wantNetwork string) (valsetCase, error) {
	var e evaluation
	evalValset(&e, liveChainID, ph, msg, sigs, hist, promiseHeader)
	if !bytes.Equal(keeperHist, hist) {
		_, kv, err := decodeHist(keeperHist)
		if err != nil {
			return valsetCase{}, fmt.Errorf("%s: stored list: %w", id, err)
		}
		e.keeperRule, e.keeperNote = "", ""
		if rule, err := keeperVerdict(msg, ph, kv, sigs); err != nil {
			e.keeperRule, e.keeperNote = rule, err.Error()
		}
	}
	fails := e.fails
	if fails == nil {
		fails = []string{}
	}
	if wantFails == nil {
		wantFails = []string{}
	}
	if !slices.Equal(fails, wantFails) || e.keeperRule != wantNetwork {
		return valsetCase{}, fmt.Errorf("%s: upstream gives fails %v, keeper %q (%s); expected %v, %q", id, fails, e.keeperRule, e.keeperNote, wantFails, wantNetwork)
	}
	c := valsetCase{ID: id, Description: desc, HistoricalInfoHex: hex.EncodeToString(hist),
		PromiseHeaderHex: hex.EncodeToString(promiseHeader), SignaturesHex: []string{}}
	for _, s := range sigs {
		c.SignaturesHex = append(c.SignaturesHex, hex.EncodeToString(s))
	}
	c.Expect = valsetExpect{Verdict: "accept", Fails: fails, CV7Matched: e.valsetVia, Certificate: e.report,
		Network: networkResult{Verdict: "accept"}}
	if len(fails) > 0 {
		c.Expect.Verdict = "reject"
	}
	if e.keeperRule != "" {
		c.Expect.Network = networkResult{Verdict: "reject", Rule: e.keeperRule, Reason: e.keeperNote}
	}
	return c, nil
}

// duplicateLive repeats the first signing validator of the live HistoricalInfo
// three more times right after itself, and its signature likewise, over the
// live headers and CometBFT set.
func duplicateLive(base inputs, live evaluation) (valsetCase, error) {
	sigs := live.pff.msg.ValidatorSignatures
	f := firstNonEmpty(sigs, false)
	if f < 0 {
		return valsetCase{}, errors.New("live list has no signature")
	}
	hi := live.hist
	var vals []stakingtypes.Validator
	var nsigs [][]byte
	for i, v := range hi.Valset {
		vals = append(vals, v)
		if i < len(sigs) {
			nsigs = append(nsigs, sigs[i])
		}
		if i == f {
			for range 3 {
				vals = append(vals, v)
				nsigs = append(nsigs, sigs[i])
			}
		}
	}
	hi.Valset = vals
	hist, err := hi.Marshal()
	if err != nil {
		return valsetCase{}, err
	}
	ph := int64(livePromiseHeight)
	desc := fmt.Sprintf("The live HistoricalInfo with validator %d (the first that signed) repeated three more times right after itself, and its signature repeated in the same slots; the live header at the promise height, so the header binding is the real one. The keeper's core.NewValidatorSet panics on the duplicate (CV4); the list stands for no CometBFT set (CV7).", f)
	return valsetCase1("valset_duplicate_signer_live", desc, live.pff.signBytes, ph, hist, hist, base.headers[ph], nsigs, []string{"CV4", "CV7"}, "CV4")
}
