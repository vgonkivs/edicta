package commitment_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

const vectorDir = "../spec/vectors/v0"

var sentinels = map[string]error{
	"ErrTooLarge":              commitment.ErrTooLarge,
	"ErrMalformed":             commitment.ErrMalformed,
	"ErrTrailingData":          commitment.ErrTrailingData,
	"ErrFloat":                 commitment.ErrFloat,
	"ErrSimpleValue":           commitment.ErrSimpleValue,
	"ErrTag":                   commitment.ErrTag,
	"ErrIndefiniteLength":      commitment.ErrIndefiniteLength,
	"ErrNonMinimalInt":         commitment.ErrNonMinimalInt,
	"ErrNestingTooDeep":        commitment.ErrNestingTooDeep,
	"ErrUnsortedMap":           commitment.ErrUnsortedMap,
	"ErrDuplicateKey":          commitment.ErrDuplicateKey,
	"ErrKeyType":               commitment.ErrKeyType,
	"ErrInvalidString":         commitment.ErrInvalidString,
	"ErrUnknownKey":            commitment.ErrUnknownKey,
	"ErrWrongType":             commitment.ErrWrongType,
	"ErrMissingField":          commitment.ErrMissingField,
	"ErrFieldSize":             commitment.ErrFieldSize,
	"ErrUnsupportedActionKind": commitment.ErrUnsupportedActionKind,
	"ErrNonCanonical":          commitment.ErrNonCanonical,
	"ErrUnsupportedVersion":    commitment.ErrUnsupportedVersion,
	"ErrIntRange":              commitment.ErrIntRange,
	"ErrInvalidEnum":           commitment.ErrInvalidEnum,
	"ErrUnsupportedRail":       commitment.ErrUnsupportedRail,
	"ErrUnsupportedOrderType":  commitment.ErrUnsupportedOrderType,
	"ErrZeroValue":             commitment.ErrZeroValue,
	"ErrPayloadTooLarge":       commitment.ErrPayloadTooLarge,
	"ErrInvalidNamespace":      commitment.ErrInvalidNamespace,
	"ErrLimitPrice":            commitment.ErrLimitPrice,
	"ErrAccountMismatch":       commitment.ErrAccountMismatch,
	"ErrChainIDRule":           commitment.ErrChainIDRule,
	"ErrTimeOrder":             commitment.ErrTimeOrder,
	"ErrDeadlineRange":         commitment.ErrDeadlineRange,
	"ErrTTLTooLong":            commitment.ErrTTLTooLong,
	"ErrPriceBound":            commitment.ErrPriceBound,
	"ErrNotionalExceeded":      commitment.ErrNotionalExceeded,
	"ErrInvalidParams":         commitment.ErrInvalidParams,
	"ErrInvalidPublicKey":      commitment.ErrInvalidPublicKey,
	"ErrSignatureInvalid":      commitment.ErrSignatureInvalid,
	"ErrNotYetValid":           commitment.ErrNotYetValid,
	"ErrExpired":               commitment.ErrExpired,
	"ErrScopeMismatch":         commitment.ErrScopeMismatch,
	"ErrActionMismatch":        commitment.ErrActionMismatch,
	"ErrPayloadSizeMismatch":   commitment.ErrPayloadSizeMismatch,
	"ErrPayloadHashMismatch":   commitment.ErrPayloadHashMismatch,
}

// assertSentinel requires err to match the named sentinel and no other one.
func assertSentinel(t *testing.T, err error, name string) {
	t.Helper()
	want, ok := sentinels[name]
	if !ok {
		t.Fatalf("vector expects unknown sentinel %q", name)
	}
	if err == nil {
		t.Fatalf("want %s, got nil error", name)
	}
	if !errors.Is(err, want) {
		t.Fatalf("want %s, got %v", name, err)
	}
	for other, s := range sentinels {
		if other != name && errors.Is(err, s) {
			t.Fatalf("want exactly %s, error also matches %s: %v", name, other, err)
		}
	}
}

func matchesAnySentinel(err error) bool {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// optHex returns nil for an absent value so that da=1 inputs decode equal.
func optHex(t testing.TB, s string) []byte {
	if s == "" {
		return nil
	}
	return mustHex(t, s)
}

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad uint %q: %v", s, err)
	}
	return v
}

func optU64(t testing.TB, s *string) *uint64 {
	if s == nil {
		return nil
	}
	v := u64(t, *s)
	return &v
}

func loadJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

type jsonScope struct {
	GateID  string  `json:"gate_id"`
	Rail    string  `json:"rail"`
	Account string  `json:"account"`
	ChainID *string `json:"chain_id"`
}

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

type jsonParams struct {
	FibreRetentionS string `json:"fibre_retention_s"`
	BlobRetentionS  string `json:"blob_retention_s"`
	SkewS           string `json:"skew_s"`
}

type jsonInput struct {
	Version     string    `json:"version"`
	AgentID     string    `json:"agent_id"`
	AgentPubKey string    `json:"agent_pubkey"`
	Nonce       string    `json:"nonce"`
	IssuedAt    string    `json:"issued_at"`
	ValidUntil  string    `json:"valid_until"`
	Scope       jsonScope `json:"scope"`
	Action      struct {
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
}

type validCase struct {
	ID                string      `json:"id"`
	Input             jsonInput   `json:"input"`
	CommitmentCBORHex string      `json:"commitment_cbor_hex"`
	CommitmentHashHex string      `json:"commitment_hash_hex"`
	Signer            string      `json:"signer"`
	SignedMessageHex  string      `json:"signed_message_hex"`
	SignatureHex      string      `json:"signature_hex"`
	EnvelopeHex       string      `json:"envelope_hex"`
	Now               string      `json:"now"`
	Params            *jsonParams `json:"params"`
	Request           jsonOrder   `json:"request"`
}

type validFile struct {
	Params jsonParams  `json:"params"`
	Gate   jsonScope   `json:"gate"`
	Cases  []validCase `json:"cases"`
}

type rejectCase struct {
	ID                string      `json:"id"`
	Stage             string      `json:"stage"`
	Rule              string      `json:"rule"`
	EnvelopeHex       string      `json:"envelope_hex"`
	Now               string      `json:"now"`
	Params            *jsonParams `json:"params"`
	Gate              *jsonScope  `json:"gate"`
	Request           *jsonOrder  `json:"request"`
	ExpectError       string      `json:"expect_error"`
	CommitmentHashHex string      `json:"commitment_hash_hex"`
}

type rejectFile struct {
	Params jsonParams   `json:"params"`
	Gate   jsonScope    `json:"gate"`
	Cases  []rejectCase `json:"cases"`
}

type keyEntry struct {
	SeedHex      string `json:"seed_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

type keysFile struct {
	Keys map[string]keyEntry `json:"keys"`
}

type payloadCase struct {
	ID                string `json:"id"`
	BlobHex           string `json:"blob_hex"`
	PayloadSize       string `json:"payload_size"`
	CiphertextHashHex string `json:"ciphertext_hash_hex"`
	SaltHex           string `json:"salt_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	PlaintextHashHex  string `json:"plaintext_hash_hex"`
	ExpectError       string `json:"expect_error"`
}

type payloadFile struct {
	Cases  []payloadCase `json:"cases"`
	Reject []payloadCase `json:"reject"`
}

func toParams(t testing.TB, p jsonParams) commitment.Params {
	return commitment.Params{
		FibreRetentionS: u64(t, p.FibreRetentionS),
		BlobRetentionS:  u64(t, p.BlobRetentionS),
		SkewS:           u64(t, p.SkewS),
	}
}

func toGate(t testing.TB, g jsonScope) commitment.GateScope {
	return commitment.GateScope{
		GateID:  g.GateID,
		Rail:    commitment.Rail(u64(t, g.Rail)),
		Account: g.Account,
		ChainID: g.ChainID,
	}
}

func toOrder(t testing.TB, o jsonOrder) commitment.IBKROrderV0 {
	return commitment.IBKROrderV0{
		Account:    o.Account,
		ConID:      u64(t, o.ConID),
		Symbol:     o.Symbol,
		Side:       commitment.Side(u64(t, o.Side)),
		Qty:        u64(t, o.Qty),
		OrderType:  commitment.OrderType(u64(t, o.OrderType)),
		LimitPrice: optU64(t, o.LimitPrice),
		Currency:   o.Currency,
		TIF:        commitment.TIF(u64(t, o.TIF)),
	}
}

func toCommitment(t testing.TB, in jsonInput) *commitment.Commitment {
	order := toOrder(t, in.Action.Params)
	return &commitment.Commitment{
		Version:     u64(t, in.Version),
		AgentID:     in.AgentID,
		AgentPubKey: mustHex(t, in.AgentPubKey),
		Nonce:       mustHex(t, in.Nonce),
		IssuedAt:    u64(t, in.IssuedAt),
		ValidUntil:  u64(t, in.ValidUntil),
		Scope: commitment.Scope{
			GateID:  in.Scope.GateID,
			Rail:    commitment.Rail(u64(t, in.Scope.Rail)),
			Account: in.Scope.Account,
			ChainID: in.Scope.ChainID,
		},
		Action: commitment.Action{Kind: in.Action.Kind, IBKROrder: &order},
		Constraints: commitment.Constraints{
			MaxNotional: u64(t, in.Constraints.MaxNotional),
			PriceBound:  optU64(t, in.Constraints.PriceBound),
			Deadline:    optU64(t, in.Constraints.Deadline),
		},
		PayloadRef: commitment.PayloadRef{
			DA:         commitment.DA(u64(t, in.PayloadRef.DA)),
			Namespace:  mustHex(t, in.PayloadRef.Namespace),
			Commitment: mustHex(t, in.PayloadRef.Commitment),
			Height:     u64(t, in.PayloadRef.Height),
			Signer:     optHex(t, in.PayloadRef.Signer),
		},
		CiphertextHash: mustHex(t, in.CiphertextHash),
		PlaintextHash:  mustHex(t, in.PlaintextHash),
		PayloadSize:    u64(t, in.PayloadSize),
	}
}

func loadKey(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	var kf keysFile
	loadJSON(t, "keys.json", &kf)
	k, ok := kf.Keys[name]
	if !ok {
		t.Fatalf("no key %q", name)
	}
	priv := ed25519.NewKeyFromSeed(mustHex(t, k.SeedHex))
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != k.PublicKeyHex {
		t.Fatalf("seed/public key mismatch in keys.json: %s", got)
	}
	return priv
}

func loadValid(t testing.TB) validFile {
	var vf validFile
	loadJSON(t, "valid.json", &vf)
	return vf
}

func validCaseByID(t testing.TB, vf validFile, id string) validCase {
	t.Helper()
	for _, c := range vf.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no valid vector %q", id)
	return validCase{}
}

func ptr[T any](v T) *T { return &v }
