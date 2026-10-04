package sdk_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

var bg = context.Background()

const (
	now    = gatefix.Now
	height = uint64(4_200_000)
)

var (
	params = commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
	scope  = commitment.GateScope{GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType}}
	// testNS is a valid version-0 namespace.
	testNS = append(make([]byte, 19), []byte("edicta/d01")...)
)

type clock struct{ unix uint64 }

func (c *clock) Now() time.Time { return time.Unix(int64(c.unix), 0) }

// recorder is a Publisher fake. For da = 2 it returns the real share
// commitment of what it anchored, which is the submitted blob unless other is
// set (the Recorder that anchors X while the agent holds Y).
type recorder struct {
	mu             sync.Mutex
	da             commitment.DA
	blockTime      uint64
	height         uint64
	retentionStart uint64
	other          []byte
	mutate         func(p *sdk.Published)
	err            error
	blobs          [][]byte
}

func newRecorder() *recorder {
	return &recorder{da: commitment.DACelestiaBlob, blockTime: now - 100, height: height}
}

func (r *recorder) Publish(_ context.Context, blob []byte) (sdk.Published, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs = append(r.blobs, append([]byte(nil), blob...))
	if r.err != nil {
		return sdk.Published{}, r.err
	}
	anchored := blob
	if r.other != nil {
		anchored = r.other
	}
	signer := []byte("0123456789abcdefghij")
	ref := commitment.PayloadRef{DA: r.da, Namespace: append([]byte(nil), testNS...), Height: r.height}
	switch r.da {
	case commitment.DACelestiaBlob:
		cm, err := sharev1.Commitment(ref.Namespace, signer, anchored)
		if err != nil {
			return sdk.Published{}, err
		}
		ref.Commitment, ref.Signer = cm, signer
	default:
		sum := sha256.Sum256(append([]byte("fibre commitment of "), anchored...))
		ref.Commitment = sum[:]
	}
	p := sdk.Published{Ref: ref, BlockTime: r.blockTime, RetentionStart: r.retentionStart}
	if r.mutate != nil {
		r.mutate(&p)
	}
	return p, nil
}

func (r *recorder) calls() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.blobs) }

func (r *recorder) lastBlob(t testing.TB) []byte {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.blobs)
	return r.blobs[len(r.blobs)-1]
}

// spySigner wraps a real signer and records what it was asked to sign.
type spySigner struct {
	inner    sdk.Signer
	pub      ed25519.PublicKey // overrides the inner key when set
	override func(h commitment.Hash) ([]byte, error)
	mu       sync.Mutex
	hashes   []commitment.Hash
}

func (s *spySigner) PublicKey() ed25519.PublicKey {
	if s.pub != nil {
		return s.pub
	}
	return s.inner.PublicKey()
}

func (s *spySigner) SignCommitment(ctx context.Context, h commitment.Hash) ([]byte, error) {
	s.mu.Lock()
	s.hashes = append(s.hashes, h)
	s.mu.Unlock()
	if s.override != nil {
		return s.override(h)
	}
	return s.inner.SignCommitment(ctx, h)
}

func (s *spySigner) calls() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.hashes) }

// committerFn adapts a function to sdk.Committer.
type committerFn func(ref commitment.PayloadRef, blob []byte) error

func (f committerFn) Check(ref commitment.PayloadRef, blob []byte) error {
	return f(ref, blob)
}

// rig is a Builder on fakes. Fields may be changed before New.
type rig struct {
	t      *testing.T
	vec    *sdkfix.Vectors
	cfg    sdk.Config
	deps   sdk.Deps
	clock  *clock
	rec    *recorder
	signer *spySigner
	chain  *gatetest.ChainParams
}

func newRig(t *testing.T, mods ...func(*rig)) *rig {
	t.Helper()
	v := sdkfix.Load(t)
	inner, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
	require.NoError(t, err)
	r := &rig{
		t: t, vec: v,
		cfg:    sdk.DefaultConfig(),
		clock:  &clock{unix: now},
		rec:    newRecorder(),
		signer: &spySigner{inner: inner},
		chain:  gatetest.NewChainParams(14400),
	}
	r.deps = sdk.Deps{Chain: r.chain}
	r.cfg.AgentID = "dca-agent-1"
	r.cfg.Scope = commitment.Scope{GateID: gatefix.GateID}
	r.cfg.Recipients = v.Recipients(t, "gate-paper-1", "auditor-1")
	for _, m := range mods {
		m(r)
	}
	return r
}

// tryNew builds the Builder from the current fields.
func (r *rig) tryNew() (*sdk.Builder, error) {
	d := r.deps
	d.Publisher, d.Signer, d.Clock = nil, nil, nil
	if r.rec != nil {
		d.Publisher = r.rec
	}
	if r.signer != nil {
		d.Signer = r.signer
	}
	if r.clock != nil {
		d.Clock = r.clock
	}
	return sdk.New(r.cfg, d)
}

func (r *rig) builder() *sdk.Builder {
	r.t.Helper()
	b, err := r.tryNew()
	require.NoError(r.t, err)
	return b
}

func (r *rig) payload() *payload.Payload { return sdkfix.ClonePayload(r.vec.Case0(r.t).Payload) }

func (r *rig) commit() *sdk.Result {
	r.t.Helper()
	res, err := r.builder().Commit(bg, r.payload())
	require.NoError(r.t, err)
	require.NotNil(r.t, res)
	return res
}

// requireValidAtGate runs the gate's own stateless checks on the result.
func requireValidAtGate(t testing.TB, res *sdk.Result, at uint64) {
	t.Helper()
	s, h, err := commitment.VerifyForGate(res.Envelope, at, scope, params)
	require.NoError(t, err)
	require.Equal(t, res.CommitmentHash, h)
	require.Equal(t, res.Commitment, s.Commitment)
	require.NoError(t, commitment.CheckScope(&s.Commitment, scope))
	require.NoError(t, commitment.CheckAction(&s.Commitment, res.Action))
	require.NoError(t, commitment.CheckPayload(&s.Commitment, res.Blob))
	require.NoError(t, commitment.CheckAnchorTime(&s.Commitment, res.Published.BlockTime, params))
}

func isAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
