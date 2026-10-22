// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/testkit"
)

type jsonVector struct {
	ID      string `json:"id"`
	Expect  string `json:"expect"`
	Cause   string `json:"cause"`
	JSON    string `json:"json"`
	JSONHex string `json:"json_hex"`
	CBORHex string `json:"cbor_hex"`
}

// body is the case's answer; a body that is not UTF-8 travels as hex.
func (c jsonVector) body(t testing.TB) []byte {
	t.Helper()
	if c.JSONHex != "" {
		require.Empty(t, c.JSON)
		return unhex(t, c.JSONHex)
	}
	return []byte(c.JSON)
}

type rVector struct {
	ID                  string `json:"id"`
	Expect              string `json:"expect"`
	RHex                string `json:"r_hex"`
	RequirementsHashHex string `json:"requirements_hash_hex"`
}

type x402File struct {
	header
	Inputs map[string]struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	} `json:"inputs"`
	Build struct {
		FromFile string `json:"from_file"`
		Input    struct {
			ChainID        string `json:"chain_id"`
			Nonce          string `json:"nonce"`
			MaxPriorityFee string `json:"max_priority_fee_per_gas"`
			MaxFeePerGas   string `json:"max_fee_per_gas"`
			GasLimit       string `json:"gas_limit"`
			To             string `json:"to"`
			Value          string `json:"value"`
			DataHex        string `json:"data_hex"`
			PaymentIDHex   string `json:"payment_id_hex"`
		} `json:"input"`
		TxHex                string      `json:"tx_hex"`
		TxLength             string      `json:"tx_length"`
		SighashHex           string      `json:"sighash_hex"`
		Resource             string      `json:"resource"`
		RequirementsURL      string      `json:"requirements_resource_url"`
		RequirementsFromFile string      `json:"requirements_from_file"`
		RequirementsHashHex  string      `json:"requirements_hash_hex"`
		CBORHex              string      `json:"cbor_hex"`
		ActionLength         string      `json:"action_length"`
		ActionSaltHex        string      `json:"action_salt_hex"`
		ActionHashHex        string      `json:"action_hash_hex"`
		ExtractorIDs         []string    `json:"extractor_ids"`
		Facts                vectorFacts `json:"facts"`
		FactsCBORHex         string      `json:"facts_cbor_hex"`
		ProfileFields        DepositView `json:"profile_fields"`
	} `json:"build"`
	BuildLimits struct {
		MaxLength string `json:"max_length"`
		MaxDepth  string `json:"max_depth"`
	} `json:"build_limits"`
	BuildAccept  []jsonVector `json:"build_accept"`
	BuildReject  []jsonVector `json:"build_reject"`
	Requirements struct {
		TxRef                string `json:"tx_ref"`
		MaxLength            string `json:"max_length"`
		MaxDepth             string `json:"max_depth"`
		CheckServerSignature bool   `json:"check_server_signature"`
		ServerSignature      struct {
			MessageHex    string `json:"message_hex"`
			DigestHex     string `json:"digest_hex"`
			SignatureHex  string `json:"signature_hex"`
			V             string `json:"v"`
			Recovered     string `json:"recovered"`
			FacilitatorW2 string `json:"facilitator_w2"`
		} `json:"server_signature"`
		Accept []rVector `json:"accept"`
		Reject []rVector `json:"reject"`
		Header struct {
			MaxChars string `json:"max_chars"`
			Accept   []struct {
				ID    string `json:"id"`
				Value string `json:"value"`
				RHex  string `json:"r_hex"`
			} `json:"accept"`
			Reject []struct {
				ID     string `json:"id"`
				Expect string `json:"expect"`
				Value  string `json:"value"`
			} `json:"reject"`
		} `json:"header"`
	} `json:"requirements"`
	PaymentSignature struct {
		Cases []struct {
			Field        string `json:"field"`
			MessageHex   string `json:"message_hex"`
			PreimageHex  string `json:"preimage_hex"`
			DigestHex    string `json:"digest_hex"`
			SignatureHex string `json:"signature_hex"`
			Signer       string `json:"signer"`
		} `json:"cases"`
		RefusedFields []string `json:"refused_fields"`
		SameDigest    bool     `json:"payment_id_digest_equals_server_signature_digest"`
	} `json:"payment_signature"`
}

func readVectorFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, vectorDir, name))
	require.NoError(t, err)
	return b
}

// x402Build loads the vectors and converts the recorded /deposit/build
// answer with the recorded document as R.
func x402Build(t testing.TB) (x402File, []byte, TxAction) {
	t.Helper()
	v := loadJSON[x402File](t, "x402.json")
	r := readVectorFile(t, v.Build.RequirementsFromFile)
	action, a, err := ActionFromDepositBuild(readVectorFile(t, v.Build.FromFile), v.Build.Resource, RequirementsHash(r))
	require.NoError(t, err)
	return v, action, a
}

func TestX402Inputs(t *testing.T) {
	v := loadJSON[x402File](t, "x402.json")
	checkHeader(t, v.header)
	require.Len(t, v.Inputs, 2)
	for name, in := range v.Inputs {
		sum := sha256.Sum256(readVectorFile(t, in.File))
		assert.Equal(t, in.SHA256, hex.EncodeToString(sum[:]), name)
	}
}

func TestX402BuildVector(t *testing.T) {
	v, action, a := x402Build(t)
	b := v.Build
	r := readVectorFile(t, b.RequirementsFromFile)
	rh := RequirementsHash(r)
	assert.Equal(t, b.RequirementsHashHex, hex.EncodeToString(rh[:]))
	assert.True(t, strings.HasPrefix(b.Resource, "https://"))
	doc, err := parseJSON(r)
	require.NoError(t, err)
	assert.Equal(t, b.RequirementsURL, doc.member("resource").member("url").text)
	assert.Equal(t, strconv.Itoa(MaxBuildBodySize), v.BuildLimits.MaxLength)
	assert.Equal(t, strconv.Itoa(maxJSONDepth), v.BuildLimits.MaxDepth)
	assert.Equal(t, b.CBORHex, hex.EncodeToString(action))
	assert.Equal(t, b.ActionLength, strconv.Itoa(len(action)))
	assert.Equal(t, b.TxHex, hex.EncodeToString(a.Unsigned()))
	assert.Equal(t, b.TxLength, strconv.Itoa(len(a.Unsigned())))
	sh := a.SigHash()
	assert.Equal(t, b.SighashHex, hex.EncodeToString(sh[:]))

	assert.Equal(t, u64(t, b.Input.ChainID), a.ChainID)
	assert.Equal(t, u64(t, b.Input.Nonce), a.Nonce)
	assert.Equal(t, minimal(t, b.Input.MaxPriorityFee), a.MaxPriorityFee)
	assert.Equal(t, minimal(t, b.Input.MaxFeePerGas), a.MaxFeePerGas)
	assert.Equal(t, u64(t, b.Input.GasLimit), a.GasLimit)
	assert.Equal(t, addr(t, b.Input.To), a.To)
	assert.Equal(t, minimal(t, b.Input.Value), a.Value)
	assert.Equal(t, b.Input.PaymentIDHex, hex.EncodeToString(a.Deposit.PaymentID[:]))
	data, err := DecodeDepositCall(unhex(t, b.Input.DataHex))
	require.NoError(t, err)
	assert.Equal(t, data, a.Deposit)

	ah, err := commitment.ActionHash(ActionType, unhex(t, b.ActionSaltHex), action)
	require.NoError(t, err)
	assert.Equal(t, b.ActionHashHex, hex.EncodeToString(ah[:]))
	assert.Equal(t, b.ProfileFields, a.DepositView())

	for _, id := range b.ExtractorIDs {
		tbl, ok := tablesInBuild[id]
		if !ok {
			continue
		}
		f, err := txExtractor{t: tbl}.Extract(action)
		require.NoError(t, err, id)
		assert.Equal(t, b.Facts.Kind, f.Kind)
		assert.Equal(t, b.Facts.Asset, f.Asset)
		assert.Equal(t, b.Facts.Amount, hex.EncodeToString(f.Amount))
		assert.Equal(t, b.Facts.Scale, strconv.FormatUint(f.Scale, 10))
		assert.Equal(t, b.Facts.Recipient, f.Recipient)
		fc, err := policy.EncodeFacts(&f)
		require.NoError(t, err)
		assert.Equal(t, b.FactsCBORHex, hex.EncodeToString(fc))
	}
}

func TestX402BuildAccept(t *testing.T) {
	v, want, _ := x402Build(t)
	rh := RequirementsHash(readVectorFile(t, v.Build.RequirementsFromFile))
	require.Len(t, v.BuildAccept, 11)
	for _, c := range v.BuildAccept {
		t.Run(c.ID, func(t *testing.T) {
			require.Equal(t, "pass", c.Expect)
			action, _, err := ActionFromDepositBuild(c.body(t), v.Build.Resource, rh)
			require.NoError(t, err)
			if c.CBORHex != "" {
				assert.Equal(t, c.CBORHex, hex.EncodeToString(action))
				return
			}
			assert.Equal(t, want, action)
		})
	}
}

func TestX402BuildReject(t *testing.T) {
	v := loadJSON[x402File](t, "x402.json")
	rh := RequirementsHash(readVectorFile(t, v.Build.RequirementsFromFile))
	requireIDs(t, v.BuildReject, "build_type_2_0", "build_type_2e0", "build_type_20e_minus_1", "build_type_02")
	for _, c := range v.BuildReject {
		t.Run(c.ID, func(t *testing.T) {
			_, _, err := ActionFromDepositBuild(c.body(t), v.Build.Resource, rh)
			want := ErrMalformed
			if c.Expect == "ED1" {
				want = ErrUnknownDomain
			}
			require.ErrorIs(t, err, want)
			assert.Equal(t, c.Expect, ruleOf(t, err))
		})
	}
}

// u is the backslash and u that start a JSON unicode escape, spelled out so
// that editors and generators that unescape literals leave the escapes in.
const u = "\\" + "u"

// The conversion reads member names after unescaping: an escaped name is
// the same member, so it repeats one written plainly.
func TestBuildEscapedNames(t *testing.T) {
	v, want, _ := x402Build(t)
	rh := RequirementsHash(readVectorFile(t, v.Build.RequirementsFromFile))
	body := string(readVectorFile(t, v.Build.FromFile))

	escaped := strings.Replace(body, `"to":`, `"`+u+`0074o":`, 1)
	require.NotEqual(t, body, escaped)
	action, _, err := ActionFromDepositBuild([]byte(escaped), v.Build.Resource, rh)
	require.NoError(t, err)
	assert.Equal(t, want, action)

	twice := strings.Replace(body, `"to":`, `"`+u+`0074o":"0x0000000000000000000000000000000000000001","to":`, 1)
	_, _, err = ActionFromDepositBuild([]byte(twice), v.Build.Resource, rh)
	require.ErrorIs(t, err, ErrMalformed)
	assert.Equal(t, "BJ1", ruleOf(t, err))
}

// The requirements-bound action of a requirements case: the build's
// transaction with the hash the case says the action carries.
func rAction(t testing.TB, a TxAction, resource, hashHex string) TxAction {
	t.Helper()
	b, err := EncodeTxAction(a.Unsigned(), resource, [32]byte(unhex(t, hashHex)))
	require.NoError(t, err)
	out, err := DecodeTxAction(b)
	require.NoError(t, err)
	return out
}

func TestX402Requirements(t *testing.T) {
	v, _, a := x402Build(t)
	req := v.Requirements
	require.Equal(t, "build", req.TxRef)
	require.Equal(t, strconv.Itoa(MaxRequirementsSize), req.MaxLength)
	require.Equal(t, strconv.Itoa(maxJSONDepth), req.MaxDepth)
	require.True(t, req.CheckServerSignature)
	require.Len(t, req.Accept, 9)
	requireRIDs(t, req.Reject, "r_version_2_0", "r_version_2e0", "r_version_02")
	for _, c := range req.Accept {
		t.Run(c.ID, func(t *testing.T) {
			r := unhex(t, c.RHex)
			rh := RequirementsHash(r)
			require.Equal(t, c.RequirementsHashHex, hex.EncodeToString(rh[:]))
			ra := rAction(t, a, v.Build.Resource, c.RequirementsHashHex)
			q, err := CheckRequirements(ra, r, true)
			require.NoError(t, err)
			assert.Equal(t, a.Deposit.PaymentID, q.PaymentID())
			assert.Equal(t, rh, q.RequirementsHash())
		})
	}
	for _, c := range req.Reject {
		t.Run(c.ID, func(t *testing.T) {
			ra := rAction(t, a, v.Build.Resource, c.RequirementsHashHex)
			r := unhex(t, c.RHex)
			_, err := CheckRequirements(ra, r, true)
			require.ErrorIs(t, err, ErrRequirements)
			assert.Equal(t, c.Expect, ruleOf(t, err))

			// Without the server-signature check, only its own rule stops
			// passing to refuse.
			_, err = CheckRequirements(ra, r, false)
			if c.Expect == "S4f" {
				require.NoError(t, err)
			} else {
				assert.Equal(t, c.Expect, ruleOf(t, err))
			}
		})
	}
}

func TestX402ServerSignature(t *testing.T) {
	v, _, a := x402Build(t)
	s := v.Requirements.ServerSignature
	m := [32]byte(unhex(t, s.MessageHex))
	assert.Equal(t, a.Deposit.PaymentID, m)
	d := PersonalDigest(m)
	assert.Equal(t, s.DigestHex, hex.EncodeToString(d[:]))
	sig := [65]byte(unhex(t, s.SignatureHex))
	assert.Equal(t, s.V, strconv.Itoa(int(sig[64])))
	got, err := RecoverPersonal(m, sig)
	require.NoError(t, err)
	assert.Equal(t, addr(t, s.Recovered), got)
	assert.Equal(t, addr(t, s.FacilitatorW2), got)
	assert.Equal(t, a.Deposit.Facilitator, got)
}

// The vectors' Payment-Signature digest and signature check against the
// personal_sign digest, and the message is the action's paymentId: the
// only field offered.
func TestX402PaymentSignatureDigests(t *testing.T) {
	v, _, a := x402Build(t)
	ps := v.PaymentSignature
	require.Len(t, ps.Cases, 1)
	assert.Equal(t, []string{"nonce"}, ps.RefusedFields)
	want := map[string][32]byte{"paymentId": a.Deposit.PaymentID}
	for _, c := range ps.Cases {
		t.Run(c.Field, func(t *testing.T) {
			m := [32]byte(unhex(t, c.MessageHex))
			require.Contains(t, want, c.Field)
			assert.Equal(t, want[c.Field], m)
			assert.Equal(t, c.PreimageHex, hex.EncodeToString(append([]byte(personalPrefix), m[:]...)))
			d := PersonalDigest(m)
			assert.Equal(t, c.DigestHex, hex.EncodeToString(d[:]))

			sig := [65]byte(unhex(t, c.SignatureHex))
			assert.Contains(t, []byte{27, 28}, sig[64])
			got, err := RecoverPersonal(m, sig)
			require.NoError(t, err)
			assert.Equal(t, addr(t, c.Signer), got)
			assert.Equal(t, payerAddr(t), got)

			// Deterministic and low s: the payer key gives exactly these bytes.
			s, err := Sign(payerKey(t), d)
			require.NoError(t, err)
			assert.Equal(t, c.SignatureHex, hex.EncodeToString(append(append(s.R[:], s.S[:]...), 27+s.YParity)))
		})
	}
	srv := PersonalDigest([32]byte(unhex(t, v.Requirements.ServerSignature.MessageHex)))
	assert.Equal(t, ps.SameDigest, PersonalDigest(a.Deposit.PaymentID) == srv)
}

func TestRecoverPersonalRanges(t *testing.T) {
	v, _, a := x402Build(t)
	sig := [65]byte(unhex(t, v.Requirements.ServerSignature.SignatureHex))
	n := [32]byte(unhex(t, loadJSON[signedFile](t, "signed.json").NHex))
	for name, mod := range map[string]func(*[65]byte){
		"v 2":    func(s *[65]byte) { s[64] = 2 },
		"v 29":   func(s *[65]byte) { s[64] = 29 },
		"r zero": func(s *[65]byte) { clear(s[:32]) },
		"r = n":  func(s *[65]byte) { copy(s[:32], n[:]) },
		"s zero": func(s *[65]byte) { clear(s[32:64]) },
		"s = n":  func(s *[65]byte) { copy(s[32:64], n[:]) },
	} {
		s := sig
		mod(&s)
		_, err := RecoverPersonal(a.Deposit.PaymentID, s)
		require.ErrorIs(t, err, ErrSignature, name)
	}
	for _, v := range []byte{0, 1, 27, 28} {
		s := sig
		s[64] = v
		_, err := RecoverPersonal(a.Deposit.PaymentID, s)
		require.NoError(t, err, "v %d", v)
	}
}

func TestDecodePaymentRequired(t *testing.T) {
	v := loadJSON[x402File](t, "x402.json")
	r := readVectorFile(t, v.Build.RequirementsFromFile)
	if len(r)%3 == 0 {
		// One byte less, so that the padded and unpadded spellings differ.
		r = r[:len(r)-1]
	}
	padded := base64.StdEncoding.EncodeToString(r)
	raw := base64.RawStdEncoding.EncodeToString(r)
	require.NotEqual(t, padded, raw)
	for _, h := range []string{padded, raw} {
		got, err := DecodePaymentRequired(h)
		require.NoError(t, err)
		assert.Equal(t, r, got)
	}

	big := base64.StdEncoding.EncodeToString(make([]byte, MaxRequirementsSize))
	got, err := DecodePaymentRequired(big)
	require.NoError(t, err)
	assert.Len(t, got, MaxRequirementsSize)

	for name, h := range map[string]string{
		"empty":            "",
		"line break":       padded[:8] + "\r\n" + padded[8:],
		"space":            " " + padded,
		"url alphabet":     strings.NewReplacer("+", "-", "/", "_").Replace(padded) + "-",
		"padding inside":   padded[:4] + "=" + padded[4:],
		"too much padding": raw + "===",
		"wrong padding":    raw + map[int]string{2: "=", 3: "=="}[len(raw)%4],
		"one byte long":    base64.StdEncoding.EncodeToString(make([]byte, MaxRequirementsSize+1)),
		"dangling char":    "QUJDR",
	} {
		_, err := DecodePaymentRequired(h)
		require.ErrorIs(t, err, ErrRequirements, name)
	}
}

func TestStrictJSON(t *testing.T) {
	ok := []string{
		`{}`, `[]`, ` {"a" : [1, -0.5e+3, "x", true, false, null, {}]} `,
		`{"a":{"b":1},"c":{"b":2}}`, `"` + u + `d83d` + u + `de00"`, `{"` + u + `0000":1}`,
	}
	for _, s := range ok {
		_, err := parseJSON([]byte(s))
		require.NoError(t, err, s)
	}
	bad := []string{
		``, ` `, `{`, `{"a":1,}`, `[1,]`, `{"a":1}x`, `{"a" 1}`, `{a:1}`,
		`{"a":1,"a":2}`, `{"x":{"a":1,"a":1}}`, `[{"a":1,"a":2}]`,
		"\xef\xbb\xbf{}", "{\"a\":\"\x01\"}", "\f{}", `"` + u + `d83d"`, `"` + u + `de00"`, `"` + u + `d83d` + u + `0041"`,
		`01`, `1.`, `.5`, `1e`, `-`, `+1`, `tru`, `nul`, `"\x"`, `"` + u + `12"`, "\"\xff\"", `{"a":1,"` + u + `0061":2}`,
	}
	for _, s := range bad {
		_, err := parseJSON([]byte(s))
		require.ErrorIs(t, err, errJSON, "%q", s)
	}
	nest := func(n int) []byte { return []byte(strings.Repeat("[", n) + strings.Repeat("]", n)) }
	_, err := parseJSON(nest(maxJSONDepth))
	require.NoError(t, err)
	_, err = parseJSON(nest(maxJSONDepth + 1))
	require.ErrorIs(t, err, errJSON)
	_, err = parseJSON(nest(1 << 20))
	require.ErrorIs(t, err, errJSON, "refused before descending")
	objects := func(n int) []byte {
		return []byte(strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n))
	}
	_, err = parseJSON(objects(maxJSONDepth))
	require.NoError(t, err)
	_, err = parseJSON(objects(maxJSONDepth + 1))
	require.ErrorIs(t, err, errJSON)
}

func TestJSONValueForms(t *testing.T) {
	doc, err := parseJSON([]byte(`{"u":9007199254740991,"big":9007199254740992,"lz":"01","d":"0","h":"0xAb","H":"0Xab"}`))
	require.NoError(t, err)
	n, ok := jsonUint(doc.member("u"))
	require.True(t, ok)
	assert.Equal(t, uint64(maxSafeInt), n)
	_, ok = jsonUint(doc.member("big"))
	assert.False(t, ok)
	_, ok = decimalString(doc.member("lz"))
	assert.False(t, ok)
	_, ok = decimalString(doc.member("d"))
	assert.True(t, ok)
	b, ok := hexString(doc.member("h"), 1)
	require.True(t, ok)
	assert.Equal(t, []byte{0xab}, b)
	_, ok = hexString(doc.member("H"), 1)
	assert.False(t, ok)
}

// requireIDs checks that the cases the latest revision added are present,
// without pinning the file's count.
func requireIDs(t *testing.T, cases []jsonVector, ids ...string) {
	t.Helper()
	require.NotEmpty(t, cases)
	have := map[string]bool{}
	for _, c := range cases {
		have[c.ID] = true
	}
	for _, id := range ids {
		assert.True(t, have[id], id)
	}
}

func requireRIDs(t *testing.T, cases []rVector, ids ...string) {
	t.Helper()
	vs := make([]jsonVector, len(cases))
	for i, c := range cases {
		vs[i] = jsonVector{ID: c.ID}
	}
	requireIDs(t, vs, ids...)
}

func TestX402HeaderDecoding(t *testing.T) {
	v := loadJSON[x402File](t, "x402.json")
	h := v.Requirements.Header
	require.Equal(t, strconv.Itoa(base64.StdEncoding.EncodedLen(MaxRequirementsSize)), h.MaxChars)
	require.NotEmpty(t, h.Accept)
	require.NotEmpty(t, h.Reject)
	for _, c := range h.Accept {
		t.Run(c.ID, func(t *testing.T) {
			got, err := DecodePaymentRequired(c.Value)
			require.NoError(t, err)
			assert.Equal(t, c.RHex, hex.EncodeToString(got))
		})
	}
	for _, c := range h.Reject {
		t.Run(c.ID, func(t *testing.T) {
			_, err := DecodePaymentRequired(c.Value)
			require.ErrorIs(t, err, ErrRequirements)
			assert.Equal(t, c.Expect, ruleOf(t, err))
		})
	}
}

// The number 2 is the token 2: other spellings of the same value refuse,
// in the build answer and in R alike.
func TestNumberTwoIsTheToken(t *testing.T) {
	v, _, a := x402Build(t)
	r := readVectorFile(t, v.Build.RequirementsFromFile)
	rh := RequirementsHash(r)
	body := string(readVectorFile(t, v.Build.FromFile))
	require.Contains(t, body, `"chainId":`)
	for _, tok := range []string{"2.0", "2e0", "2E0", "20e-1", "0.2e1", "-2"} {
		typed := strings.Replace(body, `"chainId":`, `"type":`+tok+`,"chainId":`, 1)
		_, _, err := ActionFromDepositBuild([]byte(typed), v.Build.Resource, rh)
		require.ErrorIs(t, err, ErrMalformed, tok)

		doc := []byte(strings.Replace(string(r), `"x402Version": 2,`, `"x402Version": `+tok+`,`, 1))
		require.NotEqual(t, r, doc)
		dh := RequirementsHash(doc)
		ra := rAction(t, a, v.Build.Resource, hex.EncodeToString(dh[:]))
		_, err = CheckRequirements(ra, doc, true)
		require.ErrorIs(t, err, ErrRequirements, tok)
		assert.Equal(t, "S4c", ruleOf(t, err), tok)
	}
	typed := strings.Replace(body, `"chainId":`, `"type":2,"chainId":`, 1)
	_, _, err := ActionFromDepositBuild([]byte(typed), v.Build.Resource, rh)
	require.NoError(t, err)
}
