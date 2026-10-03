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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate"
	"github.com/vgonkivs/prior/gate/dacommit/blobv1"
	"github.com/vgonkivs/prior/gate/gatetest"
	"github.com/vgonkivs/prior/gate/registry"
	"github.com/vgonkivs/prior/gate/registry/memreg"
)

const (
	// Now is the clock reading of every valid vector.
	Now = uint64(1791000060)
	// Epoch is the registry creation time used by default; it is far before
	// every vector.
	Epoch   = uint64(1_000_000_000)
	GateID  = "gate-paper-1"
	Account = "DU1234567"
	// RailRef is what the default fake executor returns.
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

// Template is the minimal_lmt commitment (da = 2, 100000 units, limit order)
// with the real commitment of Blob in payload_ref, so a real DA commitment
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

// FibreTemplate is the fibre_small_payload commitment bound to FibreBlob,
// without a deadline. Unsigned.
func FibreTemplate(t testing.TB) *commitment.Commitment {
	c := validEnvelope(t, "fibre_small_payload")
	sum := sha256.Sum256(FibreBlob())
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(FibreBlob()))
	c.Constraints.Deadline = nil
	return c
}

// Clone deep-copies the parts of a commitment that tests mutate.
func Clone(c *commitment.Commitment) *commitment.Commitment {
	d := *c
	if c.Action.IBKROrder != nil {
		o := *c.Action.IBKROrder
		if o.LimitPrice != nil {
			p := *o.LimitPrice
			o.LimitPrice = &p
		}
		d.Action.IBKROrder = &o
	}
	d.AgentPubKey = append([]byte(nil), c.AgentPubKey...)
	d.Nonce = append([]byte(nil), c.Nonce...)
	d.CiphertextHash = append([]byte(nil), c.CiphertextHash...)
	d.PayloadRef.Commitment = append([]byte(nil), c.PayloadRef.Commitment...)
	if c.Constraints.Deadline != nil {
		x := *c.Constraints.Deadline
		d.Constraints.Deadline = &x
	}
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

// SignWith signs with an arbitrary key; agent_pubkey must equal its public key.
func SignWith(t testing.TB, priv ed25519.PrivateKey, c *commitment.Commitment) ([]byte, commitment.Hash) {
	t.Helper()
	s, h, err := commitment.Sign(priv, c)
	require.NoError(t, err, "sign")
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
// Admit; the fakes are safe for concurrent use.
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
	Exec    *gatetest.Executor
	Metrics *gatetest.Metrics
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
		Exec:    gatetest.NewExecutor(commitment.RailIBKR),
		Metrics: gatetest.NewMetrics(),
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
	e.Cfg.Scope = commitment.GateScope{GateID: GateID, Rail: commitment.RailIBKR, Account: Account}
	e.Cfg.SkewS = 30
	e.Cfg.BlobRetentionS = 14400
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
		Executor: e.Exec,
		Signer:   e.Signer,
		Metrics:  e.Metrics,
	}
	for _, f := range e.depsMods {
		f(&e.Deps)
	}
	return e, e.Restart()
}

// Restart builds a new Gate on the same dependencies, which runs recovery.
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

// Admit calls the gate with a background context.
func (e *Env) Admit(b []byte) (gate.Result, error) {
	return e.Gate.Admit(context.Background(), b)
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

// RequireUntouched fails unless the executor was never called and no registry
// entry exists for c.
func (e *Env) RequireUntouched(c *commitment.Commitment) {
	e.T.Helper()
	require.Zero(e.T, e.Exec.Calls(), "executor called")
	_, err := e.Entry(c)
	require.ErrorIs(e.T, err, registry.ErrNotFound, "nonce touched")
}

// RequireRejected requires err to match want, no executor call, and an
// untouched nonce.
func (e *Env) RequireRejected(c *commitment.Commitment, err, want error) {
	e.T.Helper()
	require.ErrorIs(e.T, err, want)
	e.RequireUntouched(c)
}

// CheckReceipt verifies a result receipt against the commitment.
func CheckReceipt(t testing.TB, res gate.Result, h commitment.Hash, wantRef string, wantPath commitment.ReceiptPath, gateID string, gatePub []byte, wantAt uint64) {
	t.Helper()
	require.NotEmpty(t, res.Receipt, "no receipt")
	sr, _, err := commitment.VerifyReceipt(res.Receipt)
	require.NoError(t, err, "VerifyReceipt")
	r := sr.Receipt
	require.Equal(t, string(h[:]), string(r.CommitmentHash))
	require.Equalf(t, wantRef, r.RailRef, "receipt fields %+v", r)
	require.Equalf(t, wantPath, r.Path, "receipt fields %+v", r)
	require.Equalf(t, gateID, r.GateID, "receipt fields %+v", r)
	require.Equalf(t, string(gatePub), string(r.GatePubKey), "receipt fields %+v", r)
	require.Equalf(t, commitment.RailIBKR, r.Rail, "receipt rail/version %+v", r)
	require.EqualValuesf(t, 0, r.Version, "receipt rail/version %+v", r)
	if wantAt != 0 {
		require.Equal(t, wantAt, r.ExecutedAt)
	}
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
		commitment.ErrFieldSize, commitment.ErrUnsupportedActionKind, commitment.ErrNonCanonical,
		commitment.ErrUnsupportedVersion, commitment.ErrIntRange, commitment.ErrInvalidEnum, commitment.ErrUnsupportedRail,
		commitment.ErrUnsupportedOrderType, commitment.ErrZeroValue, commitment.ErrPayloadTooLarge,
		commitment.ErrInvalidNamespace, commitment.ErrLimitPrice, commitment.ErrAccountMismatch, commitment.ErrChainIDRule,
		commitment.ErrTimeOrder, commitment.ErrDeadlineRange, commitment.ErrTTLTooLong, commitment.ErrPriceBound,
		commitment.ErrNotionalExceeded, commitment.ErrInvalidParams, commitment.ErrInvalidPublicKey,
		commitment.ErrSignatureInvalid, commitment.ErrNotYetValid, commitment.ErrExpired, commitment.ErrScopeMismatch,
		commitment.ErrActionMismatch, commitment.ErrPayloadSizeMismatch, commitment.ErrPayloadHashMismatch,
		commitment.ErrIssuedBeforeAnchor,
		gate.ErrAgentNotAllowed, gate.ErrAgentKeyMismatch, gate.ErrAgentKeyIsGateKey, gate.ErrNonceUsed,
		gate.ErrBeforeRegistryEpoch, gate.ErrAnchorNotFound, gate.ErrRetentionUnavailable, gate.ErrAnchorTooOld,
		gate.ErrDACommitmentMismatch, gate.ErrArchiveRecomputeUnsupported, gate.ErrPayloadUnavailable,
		gate.ErrChainUnavailable, gate.ErrRegistryUnavailable, gate.ErrAllowlistUnavailable, gate.ErrClosed, gate.ErrRegistryInUse, gate.ErrClockRegression,
		gate.ErrExecutionRejected, gate.ErrExecutionUnknown, gate.ErrReceiptPending,
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
