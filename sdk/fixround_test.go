package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// The opener has no chain view, so only the absolute ttl cap applies to it and
// it does not follow whatever default parameters the commitment package picks.
func TestOpenerParamsArePinnedToTheTTLCap(t *testing.T) {
	p := sdk.OpenerParams()
	require.NoError(t, p.Validate())
	assert.EqualValues(t, 3600, p.MaxTTL(commitment.DAFibre))
	assert.EqualValues(t, 3600, p.MaxTTL(commitment.DACelestiaBlob))

	v := sdkfix.Load(t)
	c0 := v.Case0(t)
	k := v.Key(t, "gate-paper-1").OpenKey(true)
	resign := func(ttl uint64) []byte {
		s, err := commitment.DecodeSigned(c0.Envelope)
		require.NoError(t, err)
		c := gatefix.Clone(&s.Commitment)
		c.ValidUntil = c.IssuedAt + ttl
		env, _ := gatefix.Sign(t, "agent1", c)
		return env
	}
	for _, ttl := range []uint64{60, 900, 3599, 3600} {
		o, err := sdk.OpenPayload(resign(ttl), c0.Blob, k)
		require.NoErrorf(t, err, "ttl %d", ttl)
		assert.NotNil(t, o)
	}
	o, err := sdk.OpenPayload(resign(3601), c0.Blob, k)
	require.ErrorIs(t, err, commitment.ErrTTLTooLong)
	assert.Nil(t, o)
}

// A signer is not printable even when it is an unexported field of another
// struct or is copied by value.
func TestSignerIsNotPrintableInsideOtherValues(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	signer, err := sdk.NewEd25519Signer(bytes.Clone(priv))
	require.NoError(t, err)
	secrets := [][]byte{priv.Seed(), priv}

	type holder struct{ s *sdk.Ed25519Signer }
	type valueHolder struct{ s sdk.Ed25519Signer }
	type nested struct{ h holder }
	byValue := *signer //nolint:govet // the copy is the point of the test
	for name, v := range map[string]any{
		"copy by value":            byValue,
		"pointer to the copy":      &byValue,
		"unexported pointer field": holder{s: signer},
		"unexported value field":   valueHolder{s: byValue},
		"nested":                   nested{h: holder{s: signer}},
		"slice":                    []*sdk.Ed25519Signer{signer},
		"slice of values":          []sdk.Ed25519Signer{byValue},
		"map":                      map[string]*sdk.Ed25519Signer{"a": signer},
		"array of values":          [1]sdk.Ed25519Signer{byValue},
		"interface":                sdk.Signer(signer),
	} {
		t.Run(name, func(t *testing.T) { requireNoSecret(t, name, v, secrets...) })
	}
}

func TestRecipientKeyHoldersInsideTheBuilderConfig(t *testing.T) {
	r := newRig(t)
	k := r.vec.Key(t, "auditor-1")
	type cfg struct {
		key blob.RecipientKey
	}
	requireNoSecret(t, "config holder", cfg{key: k.OpenKey(true)}, k.Priv.Bytes())
	requireNoSecret(t, "copy", func() blob.RecipientKey { c := k.OpenKey(true); return c }(), k.Priv.Bytes())
}

func TestMinValidityFloor(t *testing.T) {
	for _, m := range []uint64{1, 30, 59} {
		r := newRig(t, func(r *rig) { r.cfg.MinValidityS = m })
		b, err := r.tryNew()
		require.ErrorIsf(t, err, sdk.ErrInvalidConfig, "MinValidityS %d", m)
		assert.Nil(t, b)
	}
	for _, m := range []uint64{0, 60, 61, 600} {
		r := newRig(t, func(r *rig) { r.cfg.MinValidityS = m })
		_, err := r.tryNew()
		require.NoErrorf(t, err, "MinValidityS %d", m)
	}
	t.Run("zero means 60", func(t *testing.T) {
		for ttl, ok := range map[uint64]bool{59: false, 35: false, 60: true, 61: true} {
			r := newRig(t, func(r *rig) { r.cfg.MinValidityS = 0; r.cfg.TTLS = ttl })
			res, err := r.builder().Commit(bg, r.payload())
			if ok {
				require.NoErrorf(t, err, "ttl %d", ttl)
				assert.EqualValues(t, ttl, res.Validity.ValidUntil-res.Validity.IssuedAt)
				continue
			}
			require.ErrorIsf(t, err, sdk.ErrValidityWindow, "ttl %d", ttl)
			assert.Nil(t, res)
		}
	})
}

// Time passes while the signer works: a commitment that is already expired, or
// has less than the floor left, is refused instead of returned as a success.
func TestSlowSignerIsRefused(t *testing.T) {
	for _, tt := range []struct {
		name    string
		advance uint64
		ok      bool
	}{
		{"fast", 0, true},
		{"exactly the floor left", 840, true},
		{"one second under the floor", 841, false},
		{"just before expiry", 899, false},
		{"after expiry", 901, false},
		{"two hours", 7200, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			r.signer.override = func(h commitment.Hash) ([]byte, error) {
				r.clock.unix += tt.advance
				return r.signer.inner.SignCommitment(bg, h)
			}
			res, err := r.builder().Commit(bg, r.payload())
			if tt.ok {
				require.NoError(t, err)
				assert.NotNil(t, res)
				return
			}
			require.ErrorIs(t, err, sdk.ErrValidityWindow)
			assert.Nil(t, res, "an expired or nearly expired commitment is not a success")
		})
	}
}

type clockChain struct {
	inner sdk.ChainParams
	hook  func()
}

func (c clockChain) FibreRetention(ctx context.Context, h uint64) (uint64, error) {
	c.hook()
	return c.inner.FibreRetention(ctx, h)
}

// Slow chain reads are covered too: the clock is read again before signing.
func TestSlowChainReadIsRefusedBeforeSigning(t *testing.T) {
	r := fibreRig(t)
	r.deps.Chain = clockChain{inner: r.chain, hook: func() { r.clock.unix += 7200 }}
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, sdk.ErrValidityWindow)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls(), "nothing is signed for a window that has already closed")
}

// A retry after a signer error reuses the nonce, so a signature that leaked
// from the failed attempt and the retry's signature can never both be admitted.
func TestFinalizeRetryReusesTheNonceAtTheGate(t *testing.T) {
	for _, order := range []string{"retry first", "leaked first"} {
		t.Run(order, func(t *testing.T) {
			e := newE2E(t)
			var leakedHash commitment.Hash
			var leakedSig []byte
			var firstIssued uint64
			e.sign.override = func(h commitment.Hash) ([]byte, error) {
				sig, err := e.sign.inner.SignCommitment(bg, h)
				require.NoError(t, err)
				if leakedSig == nil {
					leakedHash, leakedSig, firstIssued = h, sig, uint64(e.env.Clock.Now().Unix())
					return nil, errors.New("kms timeout after signing")
				}
				return sig, nil
			}
			s, err := e.b.Seal(bg, e.rig.payload())
			require.NoError(t, err)
			pub, err := e.b.Publish(bg, s)
			require.NoError(t, err)

			_, err = e.b.Finalize(bg, s, pub)
			require.Error(t, err)
			e.env.Clock.Advance(7 * time.Second) // the retry is a different moment
			res, err := e.b.Finalize(bg, s, pub)
			require.NoError(t, err)
			assert.Equal(t, leakedHash, res.CommitmentHash, "the retry re-signs the window of the failed attempt")
			assert.Equal(t, firstIssued, res.Commitment.IssuedAt)
			assert.Equal(t, firstIssued+900, res.Commitment.ValidUntil)
			require.True(t, ed25519.Verify(res.Commitment.AgentPubKey, commitment.SigningMessage(res.CommitmentHash), leakedSig))
			leaked, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: res.Commitment, Signature: leakedSig})
			require.NoError(t, err)
			assert.Equal(t, res.Envelope, leaked, "the leaked envelope and the retry are the same bytes")

			e.stage(res)
			a, b := res.Envelope, leaked
			if order == "leaked first" {
				a, b = b, a
			}
			_, err = e.env.Admit(a)
			require.NoError(t, err)
			_, err = e.env.Admit(b)
			require.ErrorIs(t, err, gate.ErrNonceUsed)
			assert.Equal(t, 1, e.env.Exec.Calls(), "one execution for one decision")
		})
	}
}

func TestNonceIsDrawnOncePerSealed(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	p := r.payload()
	s1, err := b.Seal(bg, p)
	require.NoError(t, err)
	s2, err := b.Seal(bg, p)
	require.NoError(t, err)
	pub1, err := b.Publish(bg, s1)
	require.NoError(t, err)
	pub2, err := b.Publish(bg, s2)
	require.NoError(t, err)
	r1, err := b.Finalize(bg, s1, pub1)
	require.NoError(t, err)
	r2, err := b.Finalize(bg, s2, pub2)
	require.NoError(t, err)
	assert.NotEqual(t, r1.Commitment.Nonce, r2.Commitment.Nonce, "different payloads, different nonces")
	assert.NotEqual(t, make([]byte, 16), r1.Commitment.Nonce)
}

type panickyCommitter struct{ v any }

func (p panickyCommitter) Check(commitment.PayloadRef, []byte) error { panic(p.v) }

func TestPanickingCommitterIsAnErrorNotASignature(t *testing.T) {
	var nilMap map[string]int
	for name, v := range map[string]any{
		"string":        "committer exploded",
		"error":         errors.New("committer exploded"),
		"runtime error": recoverOf(func() { nilMap["x"] = 1 }),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DAFibre: panickyCommitter{v}}
			r.rec.da = commitment.DAFibre
			r.rec.retentionStart = now - 150
			b := r.builder()
			var res *sdk.Result
			var err error
			require.NotPanics(t, func() { res, err = b.Commit(bg, r.payload()) })
			require.Error(t, err)
			assert.Nil(t, res)
			assert.Zero(t, r.signer.calls())
		})
	}
	t.Run("a panicking extra committer for da 2 never signs", func(t *testing.T) {
		r := newRig(t)
		r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DACelestiaBlob: panickyCommitter{"x"}}
		b := r.builder()
		var res *sdk.Result
		var err error
		require.NotPanics(t, func() { res, err = b.Commit(bg, r.payload()) })
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
}

func recoverOf(f func()) (v any) {
	defer func() { v = recover() }()
	f()
	return nil
}

// A panic value from a third-party signer may carry anything; it is not copied
// into the error.
func TestSignerPanicValueIsNotInTheError(t *testing.T) {
	r := newRig(t)
	r.signer.override = func(commitment.Hash) ([]byte, error) { panic("private-material-0123456789") }
	var err error
	b := r.builder()
	require.NotPanics(t, func() { _, err = b.Commit(bg, r.payload()) })
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "private-material")
}

type noopCommitter struct{ calls atomic.Int32 }

func (n *noopCommitter) Check(commitment.PayloadRef, []byte) error {
	n.calls.Add(1)
	return nil
}

// A committer supplied for da 2 runs in addition to the built-in recompute,
// never instead of it.
func TestDA2CommitterRunsInAdditionToTheBuiltInCheck(t *testing.T) {
	t.Run("a corrupt anchor is still caught", func(t *testing.T) {
		noop := &noopCommitter{}
		r := newRig(t)
		r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DACelestiaBlob: noop}
		r.rec.other = []byte("a different blob was anchored")
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("both run on an honest anchor", func(t *testing.T) {
		noop := &noopCommitter{}
		r := newRig(t)
		r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DACelestiaBlob: noop}
		res := r.commit()
		assert.EqualValues(t, 1, noop.calls.Load())
		assert.True(t, res.DAChecked)
	})
	t.Run("the extra committer can refuse", func(t *testing.T) {
		boom := errors.New("extra check refused")
		r := newRig(t)
		r.deps.Committers = map[commitment.DA]sdk.Committer{
			commitment.DACelestiaBlob: committerFn(func(commitment.PayloadRef, []byte) error { return boom }),
		}
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, boom)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
}

func TestDACheckedReflectsARealCheck(t *testing.T) {
	t.Run("honest recorder, default committer", func(t *testing.T) {
		assert.True(t, newRig(t).commit().DAChecked)
	})
	t.Run("opt-out", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DACelestiaBlob} })
		assert.False(t, r.commit().DAChecked)
	})
	t.Run("a committer for da 1 that really runs", func(t *testing.T) {
		noop := &noopCommitter{}
		r := newRig(t)
		r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DAFibre: noop}
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		res := r.commit()
		assert.EqualValues(t, 1, noop.calls.Load())
		assert.True(t, res.DAChecked)
	})
}

// A deadline that is already in the past, or too close to leave the floor, is
// refused when the payload is sealed, before any fee is paid.
func TestSealRefusesADeadlineThatCannotBeMet(t *testing.T) {
	for _, tt := range []struct {
		name     string
		deadline uint64
		ok       bool
	}{
		{"long past", now - 3600, false},
		{"just past", now - 1, false},
		{"now", now, false},
		{"under the floor", now + 59, false},
		{"at the floor", now + 60, true},
		{"comfortably ahead", now + 600, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			p := r.payload()
			p.Constraints.Deadline = u64p(tt.deadline)
			s, err := r.builder().Seal(bg, p)
			if tt.ok {
				require.NoError(t, err)
				assert.NotNil(t, s)
				return
			}
			require.ErrorIs(t, err, sdk.ErrValidityWindow)
			assert.Nil(t, s)
			assert.Zero(t, r.rec.calls())

			res, err := r.builder().Commit(bg, p)
			require.ErrorIs(t, err, sdk.ErrValidityWindow)
			assert.Nil(t, res)
			assert.Zero(t, r.rec.calls(), "nothing is published")
		})
	}
}

// Timeouts of the SDK's own around every dependency call.

func TestCallTimeoutConfig(t *testing.T) {
	assert.Positive(t, sdk.DefaultConfig().CallTimeout, "a default timeout exists")
	r := newRig(t, func(r *rig) { r.cfg.CallTimeout = -time.Second })
	b, err := r.tryNew()
	require.ErrorIs(t, err, sdk.ErrInvalidConfig)
	assert.Nil(t, b)
}

type hangPublisher struct{}

func (hangPublisher) Publish(ctx context.Context, _ []byte) (sdk.Published, error) {
	<-ctx.Done()
	return sdk.Published{}, ctx.Err()
}

type hangChain struct{}

func (hangChain) FibreRetention(ctx context.Context, _ uint64) (uint64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

type toggleSigner struct {
	inner sdk.Signer
	hang  atomic.Bool
}

func (s *toggleSigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *toggleSigner) SignCommitment(ctx context.Context, h commitment.Hash) ([]byte, error) {
	if s.hang.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.inner.SignCommitment(ctx, h)
}

func shortTimeout(r *rig) { r.cfg.CallTimeout = 10 * time.Millisecond }

// The callers below pass a context without a deadline: the SDK's own timeout
// is what ends the wait.
func TestHungDependenciesTimeOut(t *testing.T) {
	t.Run("publisher", func(t *testing.T) {
		r := newRig(t, shortTimeout)
		b, err := sdk.New(r.cfg, sdk.Deps{Publisher: hangPublisher{}, Signer: r.signer, Clock: r.clock, Chain: r.chain})
		require.NoError(t, err)
		res, err := b.Commit(bg, r.payload())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("chain parameters", func(t *testing.T) {
		r := fibreRig(t, shortTimeout)
		r.deps.Chain = hangChain{}
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("signer, and a retry afterwards works", func(t *testing.T) {
		r := newRig(t, shortTimeout)
		ts := &toggleSigner{inner: r.signer.inner}
		ts.hang.Store(true)
		b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: ts, Clock: r.clock, Chain: r.chain})
		require.NoError(t, err)
		s, err := b.Seal(bg, r.payload())
		require.NoError(t, err)
		pub, err := b.Publish(bg, s)
		require.NoError(t, err)

		res, err := b.Finalize(bg, s, pub)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, res)

		ts.hang.Store(false)
		res, err = b.Finalize(bg, s, pub)
		require.NoError(t, err, "a timeout does not consume the sealed payload or leave it locked")
		assert.NotNil(t, res)
	})
}

func TestCallerDeadlineStillApplies(t *testing.T) {
	r := newRig(t)
	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: hangPublisher{}, Signer: r.signer, Clock: r.clock, Chain: r.chain})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(bg, 10*time.Millisecond)
	defer cancel()
	_, err = b.Commit(ctx, r.payload())
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
