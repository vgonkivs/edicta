// Package sdkfix loads spec/vectors/v0/payload_blob.json and builds the
// recipient keys, payloads and envelopes the SDK tests share. It is used by
// tests only and does not import package sdk, so the lower packages can use it
// before sdk exists.
package sdkfix

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/gatefix"
)

const file = "payload_blob.json"

type jsonOrder struct {
	Account    string  `json:"account"`
	ConID      string  `json:"conid"`
	Symbol     *string `json:"symbol"`
	Side       string  `json:"side"`
	Qty        string  `json:"qty"`
	OrderType  string  `json:"order_type"`
	LimitPrice *string `json:"limit_price"`
	Currency   string  `json:"currency"`
	TIF        string  `json:"tif"`
}

type jsonData struct {
	MediaType string `json:"media_type"`
	Data      string `json:"data"`
}

type jsonPayload struct {
	Version string `json:"version"`
	Model   struct {
		ID      string  `json:"id"`
		Version *string `json:"version"`
		Digest  string  `json:"digest"`
	} `json:"model"`
	Policy struct {
		ID      string  `json:"id"`
		Version *string `json:"version"`
		Digest  string  `json:"digest"`
		Text    string  `json:"text"`
	} `json:"policy"`
	Context jsonData `json:"context"`
	Action  struct {
		Kind   string    `json:"kind"`
		Params jsonOrder `json:"params"`
	} `json:"action"`
	Constraints struct {
		MaxNotional string  `json:"max_notional"`
		PriceBound  *string `json:"price_bound"`
		Deadline    *string `json:"deadline"`
	} `json:"constraints"`
	Metadata *jsonData `json:"metadata"`
}

type jsonRecipient struct {
	Key        string `json:"key"`
	KIDHex     string `json:"kid_hex"`
	EncHex     string `json:"enc_hex"`
	WrappedHex string `json:"wrapped_dek_hex"`
}

type jsonCase struct {
	ID                string          `json:"id"`
	Payload           jsonPayload     `json:"payload"`
	PlaintextCBORHex  string          `json:"plaintext_cbor_hex"`
	SaltHex           string          `json:"salt_hex"`
	PlaintextHashHex  string          `json:"plaintext_hash_hex"`
	DEKHex            string          `json:"dek_hex"`
	AEADNonceHex      string          `json:"aead_nonce_hex"`
	Recipients        []jsonRecipient `json:"recipients"`
	CiphertextHex     string          `json:"ciphertext_hex"`
	BlobHex           string          `json:"blob_hex"`
	PayloadSize       string          `json:"payload_size"`
	CiphertextHashHex string          `json:"ciphertext_hash_hex"`
	ActionCBORHex     string          `json:"action_cbor_hex"`
	ConstraintsHex    string          `json:"constraints_cbor_hex"`
	Commitment        struct {
		CommitmentHashHex string `json:"commitment_hash_hex"`
		EnvelopeHex       string `json:"envelope_hex"`
		Now               string `json:"now"`
	} `json:"commitment"`
}

type jsonReject struct {
	ID               string `json:"id"`
	Stage            string `json:"stage"`
	Rule             string `json:"rule"`
	BlobHex          string `json:"blob_hex"`
	Key              string `json:"key"`
	KIDHex           string `json:"kid_hex"`
	PlaintextHashHex string `json:"plaintext_hash_hex"`
	ActionCBORHex    string `json:"action_cbor_hex"`
	ConstraintsHex   string `json:"constraints_cbor_hex"`
	Expect           string `json:"expect_error"`
	HonestKey        string `json:"honest_key"`
	HonestKIDHex     string `json:"honest_kid_hex"`
	AuditorPTHex     string `json:"auditor_aead_plaintext_hex"`
}

type jsonDCA struct {
	Cases []struct {
		ID      string `json:"id"`
		CBORHex string `json:"cbor_hex"`
	} `json:"cases"`
	Reject []struct {
		ID      string `json:"id"`
		CBORHex string `json:"cbor_hex"`
		Expect  string `json:"expect_error"`
	} `json:"reject"`
}

type jsonFile struct {
	Suite struct {
		HPKEInfoHex   string `json:"hpke_info_hex"`
		PayloadAADHex string `json:"payload_aad_hex"`
	} `json:"suite"`
	HPKEKAT struct {
		Mode  string `json:"mode"`
		KEMID string `json:"kem_id"`
		KDFID string `json:"kdf_id"`
		AEAD  string `json:"aead_id"`
		Info  string `json:"info"`
		SkRm  string `json:"skRm"`
		Enc   string `json:"enc"`
		Encs  []struct {
			PT  string `json:"pt"`
			AAD string `json:"aad"`
			CT  string `json:"ct"`
		} `json:"encryptions"`
	} `json:"hpke_kat"`
	RecipientKeys map[string]struct {
		KIDHex string `json:"kid_hex"`
		SkHex  string `json:"sk_hex"`
	} `json:"recipient_keys"`
	Cases  []jsonCase   `json:"cases"`
	Reject []jsonReject `json:"reject"`
	DCA    jsonDCA      `json:"dca"`
}

// Key is a vector recipient.
type Key struct {
	Name string
	KID  []byte
	Priv *ecdh.PrivateKey
	rk   blob.RecipientKey
}

// Recipient returns the sealing side of the key.
func (k Key) Recipient() blob.Recipient {
	return blob.Recipient{KID: k.KID, PublicKey: k.Priv.PublicKey()}
}

// OpenKey returns the opening side of the key; withKID false asks Open to try
// every entry.
func (k Key) OpenKey(withKID bool) blob.RecipientKey {
	rk := k.rk
	if withKID {
		rk.KID = k.KID
	}
	return rk
}

// CaseRecipient is one entry of a valid case.
type CaseRecipient struct {
	Key     string
	KID     []byte
	Enc     []byte
	Wrapped []byte
}

// Case is a valid vector with the full seal trace.
type Case struct {
	ID              string
	Payload         *payload.Payload
	Plaintext       []byte
	Salt            [32]byte
	PlaintextHash   commitment.Hash
	DEK             []byte
	Nonce           []byte
	Recipients      []CaseRecipient
	Ciphertext      []byte
	Blob            []byte
	PayloadSize     uint64
	CiphertextHash  commitment.Hash
	ActionCBOR      []byte
	ConstraintsCBOR []byte
	Envelope        []byte
	CommitmentHash  commitment.Hash
}

// Reject is a must-reject vector of stage decode, open or plaintext.
type Reject struct {
	ID              string
	Stage           string
	Blob            []byte
	Key             string
	KID             []byte
	PlaintextHash   []byte
	ActionCBOR      []byte
	ConstraintsCBOR []byte
	Expect          string
	HonestKey       string
	HonestKID       []byte
	AuditorAEADPT   []byte
}

// DCACase is one structured DCA context body.
type DCACase struct {
	ID     string
	CBOR   []byte
	Expect string
}

// KAT is the RFC 9180 Appendix A.2.1 base mode record.
type KAT struct {
	Mode, KEMID, KDFID, AEADID  int
	Info, SkR, Enc, PT, AAD, CT []byte
}

// Vectors is the parsed payload_blob.json.
type Vectors struct {
	HPKEInfo   []byte
	PayloadAAD []byte
	KAT        KAT
	Keys       map[string]Key
	Cases      []Case
	Rejects    []Reject
	DCAValid   []DCACase
	DCARejects []DCACase
}

func hexb(t testing.TB, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	return gatefix.MustHex(t, s)
}

func hash32(t testing.TB, s string) (h commitment.Hash) {
	t.Helper()
	b := hexb(t, s)
	require.Len(t, b, 32)
	copy(h[:], b)
	return h
}

func optU64(t testing.TB, s *string) *uint64 {
	if s == nil {
		return nil
	}
	v := gatefix.U64(t, *s)
	return &v
}

func atoi(t testing.TB, s string) int {
	t.Helper()
	v, err := strconv.Atoi(s)
	require.NoError(t, err)
	return v
}

func toPayload(t testing.TB, j jsonPayload) *payload.Payload {
	t.Helper()
	o := j.Action.Params
	p := &payload.Payload{
		Version: gatefix.U64(t, j.Version),
		Model:   payload.Model{ID: j.Model.ID, Version: j.Model.Version, Digest: hexb(t, j.Model.Digest)},
		Policy: payload.Policy{
			ID: j.Policy.ID, Version: j.Policy.Version,
			Digest: hexb(t, j.Policy.Digest), Text: hexb(t, j.Policy.Text),
		},
		Context: payload.Data{MediaType: j.Context.MediaType, Bytes: hexb(t, j.Context.Data)},
		Action: commitment.Action{Kind: j.Action.Kind, IBKROrder: &commitment.IBKROrderV0{
			Account:    o.Account,
			ConID:      gatefix.U64(t, o.ConID),
			Symbol:     o.Symbol,
			Side:       commitment.Side(gatefix.U64(t, o.Side)),
			Qty:        gatefix.U64(t, o.Qty),
			OrderType:  commitment.OrderType(gatefix.U64(t, o.OrderType)),
			LimitPrice: optU64(t, o.LimitPrice),
			Currency:   o.Currency,
			TIF:        commitment.TIF(gatefix.U64(t, o.TIF)),
		}},
		Constraints: commitment.Constraints{
			MaxNotional: gatefix.U64(t, j.Constraints.MaxNotional),
			PriceBound:  optU64(t, j.Constraints.PriceBound),
			Deadline:    optU64(t, j.Constraints.Deadline),
		},
	}
	if j.Metadata != nil {
		p.Metadata = &payload.Data{MediaType: j.Metadata.MediaType, Bytes: hexb(t, j.Metadata.Data)}
	}
	return p
}

// Load parses the vector file. Every call returns fresh values, so tests may
// mutate them.
func Load(t testing.TB) *Vectors {
	t.Helper()
	var f jsonFile
	gatefix.ReadVector(t, file, &f)
	v := &Vectors{
		HPKEInfo:   hexb(t, f.Suite.HPKEInfoHex),
		PayloadAAD: hexb(t, f.Suite.PayloadAADHex),
		Keys:       map[string]Key{},
	}
	require.NotEmpty(t, f.HPKEKAT.Encs)
	v.KAT = KAT{
		Mode: atoi(t, f.HPKEKAT.Mode), KEMID: atoi(t, f.HPKEKAT.KEMID),
		KDFID: atoi(t, f.HPKEKAT.KDFID), AEADID: atoi(t, f.HPKEKAT.AEAD),
		Info: hexb(t, f.HPKEKAT.Info), SkR: hexb(t, f.HPKEKAT.SkRm), Enc: hexb(t, f.HPKEKAT.Enc),
		PT: hexb(t, f.HPKEKAT.Encs[0].PT), AAD: hexb(t, f.HPKEKAT.Encs[0].AAD), CT: hexb(t, f.HPKEKAT.Encs[0].CT),
	}
	for name, k := range f.RecipientKeys {
		priv, err := ecdh.X25519().NewPrivateKey(hexb(t, k.SkHex))
		require.NoError(t, err, "recipient key %s", name)
		rk, err := blob.NewRecipientKey(priv)
		require.NoError(t, err, "recipient key %s", name)
		v.Keys[name] = Key{Name: name, KID: hexb(t, k.KIDHex), Priv: priv, rk: rk}
	}
	for _, c := range f.Cases {
		out := Case{
			ID:              c.ID,
			Payload:         toPayload(t, c.Payload),
			Plaintext:       hexb(t, c.PlaintextCBORHex),
			PlaintextHash:   hash32(t, c.PlaintextHashHex),
			DEK:             hexb(t, c.DEKHex),
			Nonce:           hexb(t, c.AEADNonceHex),
			Ciphertext:      hexb(t, c.CiphertextHex),
			Blob:            hexb(t, c.BlobHex),
			PayloadSize:     gatefix.U64(t, c.PayloadSize),
			CiphertextHash:  hash32(t, c.CiphertextHashHex),
			ActionCBOR:      hexb(t, c.ActionCBORHex),
			ConstraintsCBOR: hexb(t, c.ConstraintsHex),
			Envelope:        hexb(t, c.Commitment.EnvelopeHex),
			CommitmentHash:  hash32(t, c.Commitment.CommitmentHashHex),
		}
		copy(out.Salt[:], hexb(t, c.SaltHex))
		for _, r := range c.Recipients {
			out.Recipients = append(out.Recipients, CaseRecipient{
				Key: r.Key, KID: hexb(t, r.KIDHex), Enc: hexb(t, r.EncHex), Wrapped: hexb(t, r.WrappedHex),
			})
		}
		v.Cases = append(v.Cases, out)
	}
	for _, r := range f.Reject {
		v.Rejects = append(v.Rejects, Reject{
			ID: r.ID, Stage: r.Stage, Blob: hexb(t, r.BlobHex), Key: r.Key, KID: hexb(t, r.KIDHex),
			PlaintextHash: hexb(t, r.PlaintextHashHex), ActionCBOR: hexb(t, r.ActionCBORHex),
			ConstraintsCBOR: hexb(t, r.ConstraintsHex), Expect: r.Expect,
			HonestKey: r.HonestKey, HonestKID: hexb(t, r.HonestKIDHex), AuditorAEADPT: hexb(t, r.AuditorPTHex),
		})
	}
	for _, c := range f.DCA.Cases {
		v.DCAValid = append(v.DCAValid, DCACase{ID: c.ID, CBOR: hexb(t, c.CBORHex)})
	}
	for _, c := range f.DCA.Reject {
		v.DCARejects = append(v.DCARejects, DCACase{ID: c.ID, CBOR: hexb(t, c.CBORHex), Expect: c.Expect})
	}
	return v
}

// Case0 is the one-recipient DCA case, the base of most builder tests.
func (v *Vectors) Case0(t testing.TB) Case {
	t.Helper()
	require.NotEmpty(t, v.Cases)
	return v.Cases[0]
}

// Recipients returns the sealing side of the named keys, in that order.
func (v *Vectors) Recipients(t testing.TB, names ...string) []blob.Recipient {
	t.Helper()
	out := make([]blob.Recipient, 0, len(names))
	for _, n := range names {
		k, ok := v.Keys[n]
		require.Truef(t, ok, "no recipient key %q", n)
		out = append(out, k.Recipient())
	}
	return out
}

// Key returns a recipient key by name.
func (v *Vectors) Key(t testing.TB, name string) Key {
	t.Helper()
	k, ok := v.Keys[name]
	require.Truef(t, ok, "no recipient key %q", name)
	return k
}

// OpenPlaintext opens the AEAD layer of a reject vector with its key and
// returns the plaintext (without the salt). It fails the test if the blob does
// not open: plaintext-stage vectors are well-formed blobs.
func (v *Vectors) OpenPlaintext(t testing.TB, r Reject) (salt [32]byte, plaintext []byte) {
	t.Helper()
	k := v.Key(t, r.Key)
	rk := k.OpenKey(false)
	rk.KID = r.KID
	s, pt, err := blob.Open(r.Blob, rk)
	require.NoErrorf(t, err, "vector %s: the AEAD layer must open", r.ID)
	return s, pt
}

// EnvelopeFor signs, with agent1, a commitment shaped like case 0 but bound to
// raw: ciphertext_hash and payload_size come from the blob, plaintext_hash,
// action and constraints from the arguments. Action and constraints are the
// canonical CBOR of commitment keys 8 and 9.
func (v *Vectors) EnvelopeFor(t testing.TB, raw, plaintextHash, actionCBOR, constraintsCBOR []byte) []byte {
	t.Helper()
	s, err := commitment.DecodeSigned(v.Case0(t).Envelope)
	require.NoError(t, err)
	c := gatefix.Clone(&s.Commitment)
	var act commitment.Action
	require.NoError(t, cbor.Unmarshal(actionCBOR, &act))
	var con commitment.Constraints
	require.NoError(t, cbor.Unmarshal(constraintsCBOR, &con))
	c.Action, c.Constraints = act, con
	sum := sha256.Sum256(raw)
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(raw))
	c.PlaintextHash = append([]byte(nil), plaintextHash...)
	env, _ := gatefix.Sign(t, "agent1", c)
	return env
}

// Sentinel maps "blob.ErrX" and "payload.ErrX" to the Go error.
func Sentinel(name string) (error, bool) {
	m := map[string]error{
		"blob.ErrTooLarge":     blob.ErrTooLarge,
		"blob.ErrMalformed":    blob.ErrMalformed,
		"blob.ErrVersion":      blob.ErrVersion,
		"blob.ErrRecipients":   blob.ErrRecipients,
		"blob.ErrDuplicateKID": blob.ErrDuplicateKID,
		"blob.ErrNoRecipient":  blob.ErrNoRecipient,
		"blob.ErrUnwrap":       blob.ErrUnwrap,
		"blob.ErrDecrypt":      blob.ErrDecrypt,
		"payload.ErrMalformed": payload.ErrMalformed,
		"payload.ErrVersion":   payload.ErrVersion,
		"payload.ErrTooLarge":  payload.ErrTooLarge,
	}
	e, ok := m[name]
	return e, ok
}

// BlobSentinels lists every blob sentinel a decode or open may return.
func BlobSentinels() []error {
	return []error{
		blob.ErrTooLarge, blob.ErrMalformed, blob.ErrVersion, blob.ErrRecipients, blob.ErrDuplicateKID,
		blob.ErrNoRecipient, blob.ErrUnwrap, blob.ErrDecrypt, blob.ErrRecipientKey,
	}
}

// RequireOnly requires err to match want and none of the others.
func RequireOnly(t testing.TB, err, want error, others []error) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIsf(t, err, want, "want %v", want)
	for _, o := range others {
		if !errors.Is(want, o) {
			require.NotErrorIsf(t, err, o, "error also matches %v", o)
		}
	}
}

// HexOf is hex.EncodeToString, for failure messages and secret scans.
func HexOf(b []byte) string { return hex.EncodeToString(b) }

// RejectInput is the commitment input of a reject.json case, for the static
// refusal table.
type RejectInput struct {
	ID         string
	Rule       string
	Stage      string
	Expect     string
	Commitment *commitment.Commitment
	Params     commitment.Params
}

type rejectJSON struct {
	Params struct {
		Fibre string `json:"fibre_retention_s"`
		Blob  string `json:"blob_retention_s"`
		Skew  string `json:"skew_s"`
	} `json:"params"`
	Cases []struct {
		ID     string `json:"id"`
		Stage  string `json:"stage"`
		Rule   string `json:"rule"`
		Expect string `json:"expect_error"`
		Input  *struct {
			AgentID     string `json:"agent_id"`
			AgentPubKey string `json:"agent_pubkey"`
			Nonce       string `json:"nonce"`
			IssuedAt    string `json:"issued_at"`
			ValidUntil  string `json:"valid_until"`
			Scope       struct {
				GateID  string  `json:"gate_id"`
				Rail    string  `json:"rail"`
				Account string  `json:"account"`
				ChainID *string `json:"chain_id"`
			} `json:"scope"`
			Action struct {
				Kind   string    `json:"kind"`
				Params jsonOrder `json:"params"`
			} `json:"action"`
			Constraints struct {
				MaxNotional string  `json:"max_notional"`
				PriceBound  *string `json:"price_bound"`
				Deadline    *string `json:"deadline"`
			} `json:"constraints"`
			PayloadRef struct {
				DA         string `json:"da"`
				Namespace  string `json:"namespace"`
				Commitment string `json:"commitment"`
				Height     string `json:"height"`
				Signer     string `json:"signer"`
			} `json:"payload_ref"`
			CiphertextHash string `json:"ciphertext_hash"`
			PlaintextHash  string `json:"plaintext_hash"`
			PayloadSize    string `json:"payload_size"`
		} `json:"input"`
		Params *struct {
			Fibre string `json:"fibre_retention_s"`
			Blob  string `json:"blob_retention_s"`
			Skew  string `json:"skew_s"`
		} `json:"params"`
	} `json:"cases"`
}

// RejectInputs returns the stage S and stage G cases of reject.json that carry
// a commitment input, with the version field as written. The sentinel names
// are the commitment package's ("ErrInvalidEnum").
func RejectInputs(t testing.TB) []RejectInput {
	t.Helper()
	var f rejectJSON
	gatefix.ReadVector(t, "reject.json", &f)
	def := commitment.Params{
		FibreRetentionS: gatefix.U64(t, f.Params.Fibre),
		BlobRetentionS:  gatefix.U64(t, f.Params.Blob),
		SkewS:           gatefix.U64(t, f.Params.Skew),
	}
	var out []RejectInput
	for _, c := range f.Cases {
		if c.Input == nil || (c.Stage != "S" && c.Stage != "G") {
			continue
		}
		in := c.Input
		o := in.Action.Params
		com := &commitment.Commitment{
			AgentID:     in.AgentID,
			AgentPubKey: hexb(t, in.AgentPubKey),
			Nonce:       hexb(t, in.Nonce),
			IssuedAt:    gatefix.U64(t, in.IssuedAt),
			ValidUntil:  gatefix.U64(t, in.ValidUntil),
			Scope: commitment.Scope{
				GateID: in.Scope.GateID, Rail: commitment.Rail(gatefix.U64(t, in.Scope.Rail)),
				Account: in.Scope.Account, ChainID: in.Scope.ChainID,
			},
			Action: commitment.Action{Kind: in.Action.Kind, IBKROrder: &commitment.IBKROrderV0{
				Account: o.Account, ConID: gatefix.U64(t, o.ConID), Symbol: o.Symbol,
				Side: commitment.Side(gatefix.U64(t, o.Side)), Qty: gatefix.U64(t, o.Qty),
				OrderType:  commitment.OrderType(gatefix.U64(t, o.OrderType)),
				LimitPrice: optU64(t, o.LimitPrice), Currency: o.Currency,
				TIF: commitment.TIF(gatefix.U64(t, o.TIF)),
			}},
			Constraints: commitment.Constraints{
				MaxNotional: gatefix.U64(t, in.Constraints.MaxNotional),
				PriceBound:  optU64(t, in.Constraints.PriceBound),
				Deadline:    optU64(t, in.Constraints.Deadline),
			},
			PayloadRef: commitment.PayloadRef{
				DA:         commitment.DA(gatefix.U64(t, in.PayloadRef.DA)),
				Namespace:  hexb(t, in.PayloadRef.Namespace),
				Commitment: hexb(t, in.PayloadRef.Commitment),
				Height:     gatefix.U64(t, in.PayloadRef.Height),
				Signer:     hexb(t, in.PayloadRef.Signer),
			},
			CiphertextHash: hexb(t, in.CiphertextHash),
			PlaintextHash:  hexb(t, in.PlaintextHash),
			PayloadSize:    gatefix.U64(t, in.PayloadSize),
		}
		com.Version = gatefix.U64(t, "0")
		p := def
		if c.Params != nil {
			p = commitment.Params{
				FibreRetentionS: gatefix.U64(t, c.Params.Fibre),
				BlobRetentionS:  gatefix.U64(t, c.Params.Blob),
				SkewS:           gatefix.U64(t, c.Params.Skew),
			}
		}
		out = append(out, RejectInput{ID: c.ID, Rule: c.Rule, Stage: c.Stage, Expect: c.Expect, Commitment: com, Params: p})
	}
	return out
}

// ClonePayload deep-copies a payload, so a test can change one without
// touching the loaded vector.
func ClonePayload(p *payload.Payload) *payload.Payload {
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte{}, b...)
	}
	str := func(s *string) *string {
		if s == nil {
			return nil
		}
		v := *s
		return &v
	}
	u := func(x *uint64) *uint64 {
		if x == nil {
			return nil
		}
		v := *x
		return &v
	}
	out := *p
	out.Model.Version, out.Model.Digest = str(p.Model.Version), cp(p.Model.Digest)
	out.Policy.Version, out.Policy.Digest, out.Policy.Text = str(p.Policy.Version), cp(p.Policy.Digest), cp(p.Policy.Text)
	out.Context.Bytes = cp(p.Context.Bytes)
	if o := p.Action.IBKROrder; o != nil {
		c := *o
		c.Symbol, c.LimitPrice = str(o.Symbol), u(o.LimitPrice)
		out.Action.IBKROrder = &c
	}
	out.Constraints.PriceBound, out.Constraints.Deadline = u(p.Constraints.PriceBound), u(p.Constraints.Deadline)
	if p.Metadata != nil {
		m := *p.Metadata
		m.Bytes = cp(p.Metadata.Bytes)
		out.Metadata = &m
	}
	return &out
}

// OpenKeyOf wraps a private key (and an optional kid) for blob.Open.
func OpenKeyOf(t testing.TB, kid []byte, priv *ecdh.PrivateKey) blob.RecipientKey {
	t.Helper()
	rk, err := blob.NewRecipientKey(priv)
	require.NoError(t, err)
	rk.KID = kid
	return rk
}
