// Package gatefix is the shared fixture for gate tests: a fully wired Gate on
// fakes, signed commitments built from the spec vectors, and helpers that
// read the vector files. It is used by tests only.
package gatefix

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/memreg"
)

const (
	// Now is the clock reading of every valid vector.
	Now = uint64(1791000060)
	// Epoch is the registry creation time used by default; it is far before
	// every vector.
	Epoch  = uint64(1_000_000_000)
	GateID = "gate-paper-1"
	// ActionType is the type of the action every template commits to.
	ActionType = "application/vnd.edicta.ibkr.order.v0+cbor"
	// RailRef is the opaque reference the tests record.
	RailRef = "9876543210"
)

// VectorPath returns the absolute path of a file in spec/vectors/v0.
func VectorPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "spec", "vectors", "v0", name)
}

// ReadVector parses a vector file into v.
func ReadVector(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(VectorPath(name))
	require.NoError(t, err, "read vector")
	err = json.Unmarshal(b, v)
	require.NoErrorf(t, err, "parse %s", name)
}

// MustHex decodes hex or fails the test.
func MustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "bad hex")
	return b
}

// U64 parses a decimal string.
func U64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoErrorf(t, err, "bad uint %q", s)
	return v
}

// Key returns a vector key by name (agent1, agent2, gate1).
func Key(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	var kf struct {
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
		} `json:"keys"`
	}
	ReadVector(t, "keys.json", &kf)
	k, ok := kf.Keys[name]
	require.Truef(t, ok, "no key %q", name)
	return ed25519.NewKeyFromSeed(MustHex(t, k.SeedHex))
}

// ExecutorKey returns an executor key of record_request.json (executor1, executor2).
func ExecutorKey(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	var kf struct {
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
		} `json:"keys"`
	}
	ReadVector(t, "record_request.json", &kf)
	k, ok := kf.Keys[name]
	require.Truef(t, ok, "no executor key %q", name)
	return ed25519.NewKeyFromSeed(MustHex(t, k.SeedHex))
}

// ExecutorPub returns the public key of an executor vector key.
func ExecutorPub(t testing.TB, name string) ed25519.PublicKey {
	t.Helper()
	return ExecutorKey(t, name).Public().(ed25519.PublicKey)
}

// RecordSig signs the record request of the commitment in envelope b.
func RecordSig(t testing.TB, key ed25519.PrivateKey, b []byte, railRef string) []byte {
	t.Helper()
	return RecordSigFor(t, key, GateID, b, railRef)
}

// RecordSigFor signs the record request for the named gate.
func RecordSigFor(t testing.TB, key ed25519.PrivateKey, gateID string, b []byte, railRef string) []byte {
	t.Helper()
	s, err := commitment.DecodeSigned(b)
	require.NoError(t, err)
	h, err := commitment.HashOf(&s.Commitment)
	require.NoError(t, err)
	msg, err := commitment.RecordRequestMessage(h, gateID, railRef)
	if err != nil {
		return make([]byte, ed25519.SignatureSize) // an invalid reference has no valid request
	}
	return ed25519.Sign(key, msg)
}

// Pub returns the public key of a vector key.
func Pub(t testing.TB, name string) []byte {
	t.Helper()
	return Key(t, name).Public().(ed25519.PublicKey)
}

type daBlobCase struct {
	ID           string `json:"id"`
	NamespaceHex string `json:"namespace_hex"`
	SignerHex    string `json:"signer_hex"`
	BlobHex      string `json:"blob_hex"`
	CommitmentHx string `json:"commitment_hex"`
}

func daCase(t testing.TB, id string) daBlobCase {
	t.Helper()
	var f struct {
		Cases  []daBlobCase `json:"cases"`
		Reject []daBlobCase `json:"reject"`
	}
	ReadVector(t, "da_blob.json", &f)
	for _, c := range append(f.Cases, f.Reject...) {
		if c.ID == id {
			return c
		}
	}
	require.FailNow(t, fmt.Sprintf("no da_blob case %q", id))
	return daBlobCase{}
}

// Blob is the real share-version-1 blob X of the minimal_lmt payload.
func Blob(t testing.TB) []byte {
	return MustHex(t, daCase(t, "blob_v1_minimal_lmt_payload").BlobHex)
}

// BlobY is another blob of the same size as X, used by the anchor-X,
// sign-hash-Y attack.
func BlobY(t testing.TB) []byte {
	return MustHex(t, daCase(t, "anchor_x_sign_hash_y").BlobHex)
}

// RealCommitment is the DA commitment of Blob.
func RealCommitment(t testing.TB) []byte {
	return MustHex(t, daCase(t, "blob_v1_minimal_lmt_payload").CommitmentHx)
}

type validCase struct {
	ID          string `json:"id"`
	EnvelopeHex string `json:"envelope_hex"`
	ActionHex   string `json:"action_hex"`
}

func validCaseByID(t testing.TB, id string) validCase {
	t.Helper()
	var vf struct {
		Cases []validCase `json:"cases"`
	}
	ReadVector(t, "valid.json", &vf)
	for _, c := range vf.Cases {
		if c.ID == id {
			return c
		}
	}
	require.FailNow(t, fmt.Sprintf("no valid vector %q", id))
	return validCase{}
}

// Action returns the action bytes the templates commit to: the minimal order
// of the minimal_lmt vector. The core never parses them.
func Action(t testing.TB) []byte {
	t.Helper()
	return MustHex(t, validCaseByID(t, "minimal_lmt").ActionHex)
}

// ActionOf materializes the action bytes of a vector: literal hex, or a
// pattern ("affine-7-3": byte i is (7*i + 3) mod 256) with its size.
func ActionOf(t testing.TB, actionHex, pattern, size string) []byte {
	t.Helper()
	if pattern == "" {
		return MustHex(t, actionHex)
	}
	require.Equal(t, "affine-7-3", pattern, "unknown action pattern")
	b := make([]byte, U64(t, size))
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

// OtherAction returns action bytes that differ from Action(t) and, for
// distinct i, from each other.
func OtherAction(t testing.TB, i int) []byte {
	t.Helper()
	return append(Action(t), byte(i))
}

// Variant returns a clone committed to OtherAction(t, i) under ActionType.
func Variant(t testing.TB, c *commitment.Commitment, i int) *commitment.Commitment {
	t.Helper()
	return WithAction(t, c, ActionType, OtherAction(t, i))
}

// WithAction returns a clone committed to the given type and action bytes.
// The result is unsigned.
func WithAction(t testing.TB, c *commitment.Commitment, actionType string, action []byte) *commitment.Commitment {
	t.Helper()
	h, err := commitment.ActionHash(actionType, action)
	require.NoError(t, err, "action hash")
	d := Clone(c)
	d.Action = commitment.Action{Type: actionType, Hash: h[:]}
	return d
}

func validEnvelope(t testing.TB, id string) *commitment.Commitment {
	t.Helper()
	var vf struct {
		Cases []struct {
			ID          string `json:"id"`
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	ReadVector(t, "valid.json", &vf)
	for _, c := range vf.Cases {
		if c.ID == id {
			s, err := commitment.DecodeSigned(MustHex(t, c.EnvelopeHex))
			require.NoErrorf(t, err, "decode vector %s", id)
			return &s.Commitment
		}
	}
	require.FailNow(t, fmt.Sprintf("no valid vector %q", id))
	return nil
}

// Template is the minimal_lmt commitment (da = 2, action Action(t) of type
// ActionType) with the real commitment of Blob in payload_ref, so a real DA commitment
// check accepts Blob. Unsigned; use Sign.
func Template(t testing.TB) *commitment.Commitment {
	c := validEnvelope(t, "minimal_lmt")
	c.PayloadRef.Commitment = RealCommitment(t)
	return c
}

// FibreBlob is a synthetic 1024-byte payload for da = 1 commitments.
func FibreBlob() []byte {
	b := make([]byte, 1024)
	for i := range b {
		b[i] = byte(7*i + 3)
	}
	return b
}

// FibreTemplate is the fibre_small_payload commitment bound to FibreBlob.
// Unsigned.
func FibreTemplate(t testing.TB) *commitment.Commitment {
	c := validEnvelope(t, "fibre_small_payload")
	sum := sha256.Sum256(FibreBlob())
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(FibreBlob()))
	return c
}

// Clone deep-copies the parts of a commitment that tests mutate.
func Clone(c *commitment.Commitment) *commitment.Commitment {
	d := *c
	d.Action.Hash = append([]byte(nil), c.Action.Hash...)
	d.AgentPubKey = append([]byte(nil), c.AgentPubKey...)
	d.Nonce = append([]byte(nil), c.Nonce...)
	d.CiphertextHash = append([]byte(nil), c.CiphertextHash...)
	d.PayloadRef.Commitment = append([]byte(nil), c.PayloadRef.Commitment...)
	return &d
}

// Fresh returns a clone with a different nonce.
func Fresh(c *commitment.Commitment, tag byte) *commitment.Commitment {
	d := Clone(c)
	d.Nonce[0] = tag
	return d
}

// Times returns a clone with issued_at and valid_until set.
func Times(c *commitment.Commitment, issued, validUntil uint64) *commitment.Commitment {
	d := Clone(c)
	d.IssuedAt, d.ValidUntil = issued, validUntil
	return d
}

// Sign signs with a vector key and returns the envelope bytes and the hash.
func Sign(t testing.TB, keyName string, c *commitment.Commitment) ([]byte, commitment.Hash) {
	t.Helper()
	return SignWith(t, Key(t, keyName), c)
}

// SignWith signs with an arbitrary key. When the key is not the commitment's
// agent_pubkey the envelope carries that key's signature, which a gate must
// reject.
func SignWith(t testing.TB, priv ed25519.PrivateKey, c *commitment.Commitment) ([]byte, commitment.Hash) {
	t.Helper()
	s, h, err := commitment.Sign(priv, c)
	if errors.Is(err, commitment.ErrInvalidPublicKey) {
		h, err = commitment.HashOf(c)
		require.NoError(t, err, "hash")
		s = &commitment.SignedCommitment{
			Commitment: *Clone(c),
			Signature:  ed25519.Sign(priv, commitment.SigningMessage(h)),
		}
	} else {
		require.NoError(t, err, "sign")
	}
	b, err := commitment.EncodeSigned(s)
	require.NoError(t, err, "encode")
	return b, h
}

// WithKey returns a clone whose agent_pubkey is the named key's.
func WithKey(t testing.TB, c *commitment.Commitment, keyName string) *commitment.Commitment {
	d := Clone(c)
	d.AgentPubKey = Pub(t, keyName)
	return d
}

// Env is a Gate wired to fakes. All fields may be changed before the first
// Authorize; the fakes are safe for concurrent use.
type Env struct {
	T       testing.TB
	Gate    *gate.Gate
	Cfg     gate.Config
	Deps    gate.Deps
	Clock   *gatetest.Clock
	Chain   *gatetest.ChainParams
	Headers *gatetest.Headers
	Anchors *gatetest.Anchors
	DA      *gatetest.BlobSource
	Archive *gatetest.BlobSource
	Metrics *gatetest.Metrics
	Logs    *gatetest.LogCapture
	Reg     registry.Registry
	Faulty  *gatetest.FaultyRegistry
	Signer  gate.Signer

	allow     map[string][]byte
	useFaulty bool
	depsMods  []func(*gate.Deps)
}

// Option changes the environment before the gate is built.
type Option func(*Env)

func WithRegistry(r registry.Registry) Option { return func(e *Env) { e.Reg = r } }
func WithFaultyRegistry() Option              { return func(e *Env) { e.useFaulty = true } }
func WithSigner(s gate.Signer) Option         { return func(e *Env) { e.Signer = s } }
func WithNow(unix uint64) Option              { return func(e *Env) { e.Clock.Set(unix) } }
func WithConfig(f func(*gate.Config)) Option  { return func(e *Env) { f(&e.Cfg) } }

// WithDeps edits the dependencies after they are built, so it can replace any
// of them (for example Committers).
func WithDeps(f func(*gate.Deps)) Option { return func(e *Env) { e.depsMods = append(e.depsMods, f) } }
func WithScope(g commitment.GateScope) Option {
	return func(e *Env) { e.Cfg.Scope = g }
}
func WithAllowlist(m map[string][]byte) Option { return func(e *Env) { e.allow = m } }

// WithParams sets skew, blob retention and the latest fibre retention.
func WithParams(p commitment.Params) Option {
	return func(e *Env) {
		e.Cfg.SkewS = p.SkewS
		e.Cfg.BlobRetentionS = p.BlobRetentionS
		e.Chain.SetLatest(p.FibreRetentionS)
	}
}

// New builds an environment and fails the test if the gate cannot start.
func New(t testing.TB, opts ...Option) *Env {
	t.Helper()
	e, err := TryNew(t, opts...)
	require.NoError(t, err, "gate.New")
	return e
}

// TryNew builds an environment and returns the error from gate.New.
func TryNew(t testing.TB, opts ...Option) (*Env, error) {
	t.Helper()
	e := &Env{
		T:       t,
		Clock:   gatetest.NewClock(Now),
		Chain:   gatetest.NewChainParams(14400),
		Headers: gatetest.NewHeaders(),
		Anchors: gatetest.NewAnchors(),
		DA:      gatetest.NewBlobSource(),
		Archive: gatetest.NewBlobSource(),
		Metrics: gatetest.NewMetrics(),
		Logs:    gatetest.NewLogCapture(),
		Reg:     MemReg(t, Epoch),
		allow: map[string][]byte{
			"dca-agent-1": Pub(t, "agent1"),
			"dca-agent-2": Pub(t, "agent2"),
		},
	}
	gk := Key(t, "gate1")
	s, err := gate.NewEd25519Signer(gk)
	require.NoError(t, err, "signer")
	e.Signer = s
	e.Cfg = gate.DefaultConfig()
	e.Cfg.Scope = commitment.GateScope{GateID: GateID, ActionTypes: []string{ActionType}}
	e.Cfg.SkewS = 30
	e.Cfg.BlobRetentionS = 14400
	for _, n := range []string{"executor1", "executor2"} {
		e.Cfg.ExecutorKeys = append(e.Cfg.ExecutorKeys, [32]byte(ExecutorPub(t, n)))
	}
	for _, o := range opts {
		o(e)
	}
	al, err := gate.NewStaticAllowlist(e.allow)
	require.NoError(t, err, "allowlist")
	var reg registry.Registry = e.Reg
	if e.useFaulty {
		e.Faulty = gatetest.NewFaultyRegistry(e.Reg)
		reg = e.Faulty
	}
	e.Deps = gate.Deps{
		Clock:     e.Clock,
		Params:    e.Chain,
		Headers:   e.Headers,
		Anchors:   e.Anchors,
		DA:        e.DA,
		Archive:   e.Archive,
		Allowlist: al,
		Committers: map[commitment.DA]gate.DACommitter{
			commitment.DACelestiaBlob: blobv1.New(),
		},
		Registry: reg,
		Signer:   e.Signer,
		Metrics:  e.Metrics,
		Logger:   slog.New(e.Logs),
	}
	for _, f := range e.depsMods {
		f(&e.Deps)
	}
	return e, e.Restart()
}

// Restart builds a new Gate on the same dependencies.
func (e *Env) Restart() error {
	if e.Gate != nil {
		require.NoError(e.T, e.Gate.Close(), "close the previous gate")
	}
	g, err := gate.New(context.Background(), e.Cfg, e.Deps)
	if err != nil {
		return err
	}
	e.Gate = g
	return nil
}

// Record records railRef as claimed by executor1.
func (e *Env) Record(b []byte, railRef string) ([]byte, error) {
	return e.RecordAs("executor1", b, railRef)
}

// RecordAs records railRef as claimed by the named executor key.
func (e *Env) RecordAs(executor string, b []byte, railRef string) ([]byte, error) {
	k := ExecutorKey(e.T, executor)
	return e.Gate.Record(context.Background(), b, railRef, k.Public().(ed25519.PublicKey), RecordSigFor(e.T, k, e.Cfg.Scope.GateID, b, railRef))
}

// Authorize calls the gate with a background context and the template action,
// which every template and its variants commit to.
func (e *Env) Authorize(b []byte) (gate.Result, error) {
	return e.AuthorizeWith(b, Action(e.T))
}

// AuthorizeWith calls the gate with explicit action bytes.
func (e *Env) AuthorizeWith(b, action []byte) (gate.Result, error) {
	return e.Gate.Authorize(context.Background(), b, action)
}

// BlockTime is the header time Stage uses for c: 1000 s before issued_at.
func BlockTime(c *commitment.Commitment) uint64 {
	if c.IssuedAt < 1000 {
		return 0
	}
	return c.IssuedAt - 1000
}

// StageChain registers the header time and the anchor of c.
func (e *Env) StageChain(c *commitment.Commitment, blockTime, retentionStart uint64) {
	e.Headers.Set(c.PayloadRef.Height, blockTime)
	e.Anchors.Set(c.PayloadRef, gate.Anchor{Height: c.PayloadRef.Height, RetentionStart: retentionStart})
}

// StageDA registers the chain data and puts the blob in the DA source.
func (e *Env) StageDA(c *commitment.Commitment, blob []byte) {
	th := BlockTime(c)
	e.StageChain(c, th, th)
	e.DA.Put(c.PayloadRef, blob)
}

// StageArchive registers the chain data and puts the blob in the archive.
func (e *Env) StageArchive(c *commitment.Commitment, blob []byte) {
	th := BlockTime(c)
	e.StageChain(c, th, th)
	e.Archive.Put(c.PayloadRef, blob)
}

// KeyOf returns the registry key of c.
func KeyOf(c *commitment.Commitment) registry.Key {
	var k registry.Key
	copy(k.PubKey[:], c.AgentPubKey)
	copy(k.Nonce[:], c.Nonce)
	return k
}

// Entry reads the registry entry of c.
func (e *Env) Entry(c *commitment.Commitment) (registry.Entry, error) {
	return e.Reg.Get(context.Background(), KeyOf(c))
}

// RequireUntouched fails unless no registry entry exists for c.
func (e *Env) RequireUntouched(c *commitment.Commitment) {
	e.T.Helper()
	_, err := e.Entry(c)
	require.ErrorIs(e.T, err, registry.ErrNotFound, "nonce touched")
}

// RequireRejected requires err to match want and an untouched nonce.
func (e *Env) RequireRejected(c *commitment.Commitment, err, want error) {
	e.T.Helper()
	require.ErrorIs(e.T, err, want)
	e.RequireUntouched(c)
}

// CheckReceipt verifies a receipt against the commitment hash.
func CheckReceipt(t testing.TB, receipt []byte, h commitment.Hash, wantRef string, gateID string, gatePub []byte, wantAt uint64) {
	t.Helper()
	require.NotEmpty(t, receipt, "no receipt")
	sr, _, err := commitment.VerifyReceipt(receipt)
	require.NoError(t, err, "VerifyReceipt")
	r := sr.Receipt
	require.Equal(t, string(h[:]), string(r.CommitmentHash))
	require.Equalf(t, wantRef, r.RailRef, "receipt fields %+v", r)
	require.Equalf(t, gateID, r.GateID, "receipt fields %+v", r)
	require.Equalf(t, string(gatePub), string(r.GatePubKey), "receipt fields %+v", r)
	require.EqualValuesf(t, 0, r.Version, "receipt version %+v", r)
	// Anyone can check the executor's claim without trusting the gate.
	require.NoError(t, commitment.VerifyRecordRequest(h, r.GateID, r.RailRef, r.ExecutorPubKey, r.ExecutorSignature), "executor signature in the receipt")
	require.NotEqual(t, string(gatePub), string(r.ExecutorPubKey), "executor key is the gate key")
	if wantAt != 0 {
		require.Equal(t, wantAt, r.RecordedAt)
	}
}

// CheckAuthorization verifies res.Authorization as an executor would and
// returns the decoded value.
func CheckAuthorization(t testing.TB, auth, action []byte, c *commitment.Commitment, h commitment.Hash, path commitment.PayloadPath, wantExpires, now uint64) *commitment.SignedAuthorization {
	t.Helper()
	require.NotEmpty(t, auth, "no authorization")
	sa, _, err := commitment.VerifyAuthorization(auth, commitment.AuthorizationCheck{
		GatePubKey: Pub(t, "gate1"), GateID: GateID, ActionType: c.Action.Type, Action: action, Now: now, SkewS: 30,
	})
	require.NoError(t, err, "VerifyAuthorization")
	a := sa.Authorization
	require.Equal(t, string(h[:]), string(a.CommitmentHash))
	require.Equal(t, string(c.Action.Hash), string(a.ActionHash))
	require.Equal(t, GateID, a.GateID)
	require.Equal(t, path, a.Path)
	require.EqualValues(t, 0, a.Version)
	if wantExpires != 0 {
		require.Equal(t, wantExpires, a.Expires)
	}
	return sa
}

// MemReg returns an in-memory registry with the given creation time.
func MemReg(t testing.TB, epoch uint64) *memreg.Registry {
	t.Helper()
	r, err := memreg.New(epoch)
	require.NoError(t, err)
	return r
}

// KnownSentinels lists every error a rejection may wrap.
func KnownSentinels() []error {
	return []error{
		commitment.ErrTooLarge, commitment.ErrMalformed, commitment.ErrTrailingData, commitment.ErrFloat,
		commitment.ErrSimpleValue, commitment.ErrTag, commitment.ErrIndefiniteLength, commitment.ErrNonMinimalInt,
		commitment.ErrNestingTooDeep, commitment.ErrUnsortedMap, commitment.ErrDuplicateKey, commitment.ErrKeyType,
		commitment.ErrInvalidString, commitment.ErrUnknownKey, commitment.ErrWrongType, commitment.ErrMissingField,
		commitment.ErrFieldSize, commitment.ErrNonCanonical,
		commitment.ErrUnsupportedVersion, commitment.ErrIntRange, commitment.ErrInvalidEnum, commitment.ErrZeroValue, commitment.ErrPayloadTooLarge,
		commitment.ErrInvalidNamespace, commitment.ErrTimeOrder, commitment.ErrTTLTooLong, commitment.ErrInvalidParams, commitment.ErrInvalidPublicKey,
		commitment.ErrSignatureInvalid, commitment.ErrNotYetValid, commitment.ErrExpired, commitment.ErrScopeMismatch,
		commitment.ErrActionMismatch, commitment.ErrPayloadSizeMismatch, commitment.ErrPayloadHashMismatch,
		commitment.ErrIssuedBeforeAnchor, commitment.ErrActionTypeNotAllowed, commitment.ErrActionSize,
		gate.ErrAgentNotAllowed, gate.ErrAgentKeyMismatch, gate.ErrAgentKeyIsGateKey, gate.ErrNonceUsed,
		gate.ErrBeforeRegistryEpoch, gate.ErrAnchorNotFound, gate.ErrRetentionUnavailable, gate.ErrAnchorTooOld,
		gate.ErrDACommitmentMismatch, gate.ErrArchiveRecomputeUnsupported, gate.ErrPayloadUnavailable,
		gate.ErrChainUnavailable, gate.ErrRegistryUnavailable, gate.ErrAllowlistUnavailable, gate.ErrClosed, gate.ErrRegistryInUse, gate.ErrClockRegression,
		gate.ErrNotAuthorized, gate.ErrReceiptExists, gate.ErrExecutorNotAllowed, commitment.ErrKeyRole,
		context.Canceled, context.DeadlineExceeded,
	}
}

// IsKnown reports whether err wraps one of KnownSentinels.
func IsKnown(err error) bool {
	for _, s := range KnownSentinels() {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}
