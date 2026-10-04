package commitment_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

const vectorDir = "../spec/vectors/v0"

var sentinels = map[string]error{
	"ErrTooLarge":             commitment.ErrTooLarge,
	"ErrMalformed":            commitment.ErrMalformed,
	"ErrTrailingData":         commitment.ErrTrailingData,
	"ErrFloat":                commitment.ErrFloat,
	"ErrSimpleValue":          commitment.ErrSimpleValue,
	"ErrTag":                  commitment.ErrTag,
	"ErrIndefiniteLength":     commitment.ErrIndefiniteLength,
	"ErrNonMinimalInt":        commitment.ErrNonMinimalInt,
	"ErrNestingTooDeep":       commitment.ErrNestingTooDeep,
	"ErrUnsortedMap":          commitment.ErrUnsortedMap,
	"ErrDuplicateKey":         commitment.ErrDuplicateKey,
	"ErrKeyType":              commitment.ErrKeyType,
	"ErrInvalidString":        commitment.ErrInvalidString,
	"ErrUnknownKey":           commitment.ErrUnknownKey,
	"ErrWrongType":            commitment.ErrWrongType,
	"ErrMissingField":         commitment.ErrMissingField,
	"ErrFieldSize":            commitment.ErrFieldSize,
	"ErrNonCanonical":         commitment.ErrNonCanonical,
	"ErrUnsupportedVersion":   commitment.ErrUnsupportedVersion,
	"ErrIntRange":             commitment.ErrIntRange,
	"ErrInvalidEnum":          commitment.ErrInvalidEnum,
	"ErrZeroValue":            commitment.ErrZeroValue,
	"ErrPayloadTooLarge":      commitment.ErrPayloadTooLarge,
	"ErrInvalidNamespace":     commitment.ErrInvalidNamespace,
	"ErrTimeOrder":            commitment.ErrTimeOrder,
	"ErrTTLTooLong":           commitment.ErrTTLTooLong,
	"ErrInvalidParams":        commitment.ErrInvalidParams,
	"ErrInvalidPublicKey":     commitment.ErrInvalidPublicKey,
	"ErrSignatureInvalid":     commitment.ErrSignatureInvalid,
	"ErrNotYetValid":          commitment.ErrNotYetValid,
	"ErrExpired":              commitment.ErrExpired,
	"ErrScopeMismatch":        commitment.ErrScopeMismatch,
	"ErrKeyRole":              commitment.ErrKeyRole,
	"ErrActionTypeNotAllowed": commitment.ErrActionTypeNotAllowed,
	"ErrActionSize":           commitment.ErrActionSize,
	"ErrActionMismatch":       commitment.ErrActionMismatch,
	"ErrPayloadSizeMismatch":  commitment.ErrPayloadSizeMismatch,
	"ErrPayloadHashMismatch":  commitment.ErrPayloadHashMismatch,
	"ErrIssuedBeforeAnchor":   commitment.ErrIssuedBeforeAnchor,
}

// assertSentinel requires err to match the named sentinel and no other one.
func assertSentinel(t *testing.T, err error, name string) {
	t.Helper()
	want, ok := sentinels[name]
	require.Truef(t, ok, "vector expects unknown sentinel %q", name)
	require.Error(t, err)
	require.ErrorIsf(t, err, want, "want %s", name)
	for other, s := range sentinels {
		if other != name {
			require.NotErrorIsf(t, err, s, "error also matches %s", other)
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
	require.NoErrorf(t, err, "bad hex %q", s)
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
	require.NoErrorf(t, err, "bad uint %q", s)
	return v
}

func loadJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	require.NoError(t, err, "read vector file")
	err = json.Unmarshal(b, v)
	require.NoErrorf(t, err, "parse %s", name)
}

type jsonScope struct {
	GateID string `json:"gate_id"`
}

type jsonAction struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
}

type jsonGate struct {
	GateID      string   `json:"gate_id"`
	ActionTypes []string `json:"action_types"`
}

// actionSpec is how vectors describe action bytes: literal hex, or a
// pattern plus size and SHA-256 for actions too large to inline.
type actionSpec struct {
	ActionHex       string `json:"action_hex"`
	ActionPattern   string `json:"action_pattern"`
	ActionSize      string `json:"action_size"`
	ActionSHA256Hex string `json:"action_sha256_hex"`
}

type jsonParams struct {
	FibreRetentionS string `json:"fibre_retention_s"`
	BlobRetentionS  string `json:"blob_retention_s"`
	SkewS           string `json:"skew_s"`
}

type jsonInput struct {
	Version     string     `json:"version"`
	AgentID     string     `json:"agent_id"`
	AgentPubKey string     `json:"agent_pubkey"`
	Nonce       string     `json:"nonce"`
	IssuedAt    string     `json:"issued_at"`
	ValidUntil  string     `json:"valid_until"`
	Scope       jsonScope  `json:"scope"`
	Action      jsonAction `json:"action"`
	PayloadRef  struct {
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
	ActionType        string      `json:"action_type"`
	ActionHashHex     string      `json:"action_hash_hex"`
	PrefixHex         string      `json:"action_preimage_prefix_hex"`
	actionSpec
}

type validFile struct {
	Params jsonParams  `json:"params"`
	Gate   jsonGate    `json:"gate"`
	Cases  []validCase `json:"cases"`
}

type rejectCase struct {
	ID                string      `json:"id"`
	Stage             string      `json:"stage"`
	Rule              string      `json:"rule"`
	EnvelopeHex       string      `json:"envelope_hex"`
	Now               string      `json:"now"`
	Params            *jsonParams `json:"params"`
	Gate              *jsonGate   `json:"gate"`
	ActionType        string      `json:"action_type"`
	ExpectError       string      `json:"expect_error"`
	CommitmentHashHex string      `json:"commitment_hash_hex"`
	actionSpec
}

type rejectFile struct {
	Params jsonParams   `json:"params"`
	Gate   jsonGate     `json:"gate"`
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

func toGate(t testing.TB, g jsonGate) commitment.GateScope {
	return commitment.GateScope{GateID: g.GateID, ActionTypes: g.ActionTypes}
}

// actionBytes materializes the action of a vector. Patterns are defined as
// byte i = (7*i + 3) mod 256, and the digest pins the generated bytes.
func actionBytes(t testing.TB, a actionSpec) []byte {
	t.Helper()
	if a.ActionPattern == "" {
		return mustHex(t, a.ActionHex)
	}
	require.Equal(t, "affine-7-3", a.ActionPattern, "unknown action pattern")
	n := u64(t, a.ActionSize)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	if a.ActionSHA256Hex != "" {
		sum := sha256.Sum256(b)
		require.Equal(t, a.ActionSHA256Hex, hex.EncodeToString(sum[:]), "pattern digest")
	}
	return b
}

func toCommitment(t testing.TB, in jsonInput) *commitment.Commitment {
	return &commitment.Commitment{
		Version:     u64(t, in.Version),
		AgentID:     in.AgentID,
		AgentPubKey: mustHex(t, in.AgentPubKey),
		Nonce:       mustHex(t, in.Nonce),
		IssuedAt:    u64(t, in.IssuedAt),
		ValidUntil:  u64(t, in.ValidUntil),
		Scope:       commitment.Scope{GateID: in.Scope.GateID},
		Action:      commitment.Action{Type: in.Action.Type, Hash: mustHex(t, in.Action.Hash)},
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
	require.Truef(t, ok, "no key %q", name)
	priv := ed25519.NewKeyFromSeed(mustHex(t, k.SeedHex))
	got := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	require.Equalf(t, k.PublicKeyHex, got, "seed/public key mismatch in keys.json: %s", got)
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
	require.FailNow(t, fmt.Sprintf("no valid vector %q", id))
	return validCase{}
}
