package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func TestDefaultConfig(t *testing.T) {
	c := sdk.DefaultConfig()
	assert.EqualValues(t, 900, c.TTLS)
	assert.EqualValues(t, 60, c.MinValidityS)
	assert.EqualValues(t, 30, c.SkewS)
	assert.EqualValues(t, 14400, c.BlobRetentionS)
	assert.EqualValues(t, blob.MaxSealSize, c.MaxBlobSize)
	assert.Empty(t, c.UnsafeSkipDACheck, "no DA check is skipped by default")
}

func TestNewRejectsBadConfig(t *testing.T) {
	v := newRig(t).vec
	many := func(n int) []blob.Recipient {
		var rs []blob.Recipient
		for i := range n {
			k := v.Keys["rcpt-04"]
			kid := append([]byte("rcpt-"), byte('a'+i))
			rs = append(rs, blob.Recipient{KID: kid, PublicKey: k.Priv.PublicKey()})
		}
		return rs
	}
	tests := []struct {
		name string
		mod  func(r *rig)
		want error
	}{
		{"no recipients", func(r *rig) { r.cfg.Recipients = nil }, sdk.ErrInvalidConfig},
		{"17 recipients", func(r *rig) { r.cfg.Recipients = many(17) }, sdk.ErrInvalidConfig},
		{"duplicate kid", func(r *rig) {
			r.cfg.Recipients = append(r.cfg.Recipients, r.cfg.Recipients[0])
		}, sdk.ErrInvalidConfig},
		{"no publisher", func(r *rig) { r.rec = nil }, sdk.ErrInvalidConfig},
		{"no signer", func(r *rig) { r.signer = nil }, sdk.ErrInvalidConfig},
		{"no clock", func(r *rig) { r.clock = nil }, sdk.ErrInvalidConfig},
		{"skip list with an unknown da", func(r *rig) {
			r.cfg.UnsafeSkipDACheck = []commitment.DA{3}
		}, sdk.ErrInvalidConfig},
		{"skip list with da 0", func(r *rig) {
			r.cfg.UnsafeSkipDACheck = []commitment.DA{0}
		}, sdk.ErrInvalidConfig},
		{"duplicate entries in the skip list", func(r *rig) {
			r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre, commitment.DAFibre}
		}, sdk.ErrInvalidConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, tt.mod)
			b, err := r.tryNew()
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, b)
		})
	}
	t.Run("sixteen recipients are fine", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.cfg.Recipients = many(16) })
		_, err := r.tryNew()
		require.NoError(t, err)
	})
}

// A signer whose key the gate would refuse never gets to sign.
func TestNewRejectsWeakAgentKey(t *testing.T) {
	for _, in := range sdkRejectKeys(t) {
		t.Run(in.id, func(t *testing.T) {
			r := newRig(t)
			r.signer.pub = in.pub
			b, err := r.tryNew()
			require.ErrorIs(t, err, commitment.ErrInvalidPublicKey)
			assert.Nil(t, b)
			assert.Zero(t, r.signer.calls())
		})
	}
}

func TestCommitHappyPath(t *testing.T) {
	r := newRig(t)
	res := r.commit()

	requireValidAtGate(t, res, now)
	c := res.Commitment
	assert.EqualValues(t, 0, c.Version)
	assert.Equal(t, "dca-agent-1", c.AgentID)
	assert.Equal(t, gatefix.Pub(t, "agent1"), c.AgentPubKey)
	assert.Len(t, c.Nonce, 16)
	assert.Equal(t, r.cfg.Scope, c.Scope)

	p := r.payload()
	wantHash, err := commitment.ActionHash(p.Action.Type, p.Action.Data)
	require.NoError(t, err)
	assert.Equal(t, p.Action.Type, c.Action.Type, "the committed type is the payload's")
	assert.Equal(t, wantHash[:], c.Action.Hash, "the committed hash is over the payload's bytes")
	assert.Equal(t, p.Action.Data, res.Action, "the result hands the caller the exact bytes to present to the gate")
	assert.Equal(t, wantHash, res.ActionHash)

	h, err := commitment.HashOf(&c)
	require.NoError(t, err)
	assert.Equal(t, h, res.CommitmentHash)
	assert.True(t, res.DAChecked)
	require.NoError(t, commitment.CheckAction(&c, res.Action), "the gate's action check passes on the result")

	pub := res.Published
	assert.Equal(t, pub.Ref, c.PayloadRef)
	sum := sha256.Sum256(res.Blob)
	assert.Equal(t, sum[:], c.CiphertextHash)
	assert.EqualValues(t, len(res.Blob), c.PayloadSize)
	assert.Equal(t, r.rec.lastBlob(t), res.Blob, "the published bytes are the committed bytes")

	v := res.Validity
	assert.EqualValues(t, now, v.IssuedAt)
	assert.EqualValues(t, now+900, v.ValidUntil)
	assert.EqualValues(t, now+900, v.RequestedUntil)
	assert.False(t, v.Clamped)
	assert.Empty(t, v.ClampedBy)
	assert.Equal(t, v.IssuedAt, c.IssuedAt)
	assert.Equal(t, v.ValidUntil, c.ValidUntil)
}

// The envelope bytes are exactly the signed commitment, and the signature is
// over the tagged hash.
func TestEnvelopeIsTheSignedCommitment(t *testing.T) {
	res := newRig(t).commit()
	s, err := commitment.DecodeSigned(res.Envelope)
	require.NoError(t, err)
	assert.Equal(t, res.Commitment, s.Commitment)
	h, err := commitment.Verify(s)
	require.NoError(t, err)
	assert.Equal(t, res.CommitmentHash, h)
	assert.True(t, ed25519.Verify(res.Commitment.AgentPubKey, commitment.SigningMessage(h), s.Signature))
	again, err := commitment.EncodeSigned(s)
	require.NoError(t, err)
	assert.Equal(t, res.Envelope, again)
}

func TestIssuedAtIsTheLaterOfNowAndAnchorTime(t *testing.T) {
	tests := []struct {
		name      string
		blockTime uint64
		wantIssue uint64
		wantErr   error
	}{
		{"anchor long before now", now - 3000, now, nil},
		{"anchor just before now", now - 1, now, nil},
		{"anchor at now", now, now, nil},
		{"anchor ahead within skew", now + 10, now + 10, nil},
		{"anchor ahead by exactly skew", now + 30, now + 30, nil},
		{"anchor ahead by more than skew", now + 31, 0, sdk.ErrClockBehindAnchor},
		{"anchor far ahead", now + 100000, 0, sdk.ErrClockBehindAnchor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			r.rec.blockTime = tt.blockTime
			res, err := r.builder().Commit(bg, r.payload())
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, res)
				assert.Zero(t, r.signer.calls(), "nothing is signed")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantIssue, res.Commitment.IssuedAt)
			assert.Equal(t, tt.wantIssue, res.Validity.IssuedAt)
			assert.EqualValues(t, tt.wantIssue+900, res.Commitment.ValidUntil)
			require.NoError(t, commitment.CheckAnchorTime(&res.Commitment, tt.blockTime, params))
			requireValidAtGate(t, res, now)
		})
	}
}

func TestCommitTimeBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		ttl         uint64
		blockTime   uint64
		want        error // nil: success
		wantAny     []error
		wantUntil   uint64
		wantClamped string
	}{
		{name: "default ttl", ttl: 900, blockTime: now - 100, wantUntil: now + 900},
		{name: "ttl equal to the maximum", ttl: 3600, blockTime: now - 100, wantUntil: now + 3600},
		{name: "ttl above the maximum is cut", ttl: 7200, blockTime: now - 100,
			wantUntil: now + 3600, wantClamped: "max_ttl"},
		{name: "old anchor cuts to the retention bound", ttl: 3600, blockTime: now - 12000,
			wantUntil: now + 1800, wantClamped: "retention"},
		{name: "retention leaves exactly the minimum", ttl: 900, blockTime: now - 13740,
			wantUntil: now + 60, wantClamped: "retention"},
		{name: "retention leaves one second less than the minimum", ttl: 900, blockTime: now - 13741, want: sdk.ErrValidityWindow},
		{name: "retention already used up", ttl: 900, blockTime: now - 14400, want: sdk.ErrValidityWindow},
		{name: "ttl exactly the minimum", ttl: 60, blockTime: now - 100, wantUntil: now + 60},
		{name: "ttl one below the minimum", ttl: 59, blockTime: now - 100, want: sdk.ErrValidityWindow},
		{name: "ttl inside the skew", ttl: 10, blockTime: now - 100, want: sdk.ErrValidityWindow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, func(r *rig) { r.cfg.TTLS = tt.ttl })
			r.rec.blockTime = tt.blockTime
			p := r.payload()
			res, err := r.builder().Commit(bg, p)
			if tt.want != nil || tt.wantAny != nil {
				require.Error(t, err)
				if tt.want != nil {
					require.ErrorIs(t, err, tt.want)
				} else {
					require.Truef(t, isAny(err, tt.wantAny...), "unexpected error %v", err)
				}
				assert.Nil(t, res)
				assert.Zero(t, r.signer.calls(), "nothing is signed")
				return
			}
			require.NoError(t, err)
			v := res.Validity
			assert.Equal(t, tt.wantUntil, v.ValidUntil)
			assert.Equal(t, tt.wantUntil, res.Commitment.ValidUntil)
			assert.Equal(t, tt.wantClamped, v.ClampedBy)
			assert.Equal(t, tt.wantClamped != "", v.Clamped)
			assert.LessOrEqual(t, v.ValidUntil, v.RequestedUntil, "never extended")
			assert.EqualValues(t, now+tt.ttl, v.RequestedUntil)
			requireValidAtGate(t, res, now)
		})
	}
}

// A signature taken when the anchor is the retention margin away still passes
// the gate's retention rule.
func TestClampedResultPassesRetentionRule(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.TTLS = 3600 })
	r.rec.blockTime = now - 12000
	res := r.commit()
	require.True(t, commitment.WithinRetention(&res.Commitment, res.Published.BlockTime, 14400))
}

func TestFibreRetentionAtHeightIsNeverSubstituted(t *testing.T) {
	boom := errors.New("no historical value")
	r := newRig(t, func(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre} })
	r.rec.da = commitment.DAFibre
	r.rec.retentionStart = now - 150
	r.chain.FailHistorical(boom)
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())

	r.chain.FailHistorical(nil)
	r.chain.FailLatest(boom)
	res, err = r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)
}

func TestFibreRetentionWindows(t *testing.T) {
	tests := []struct {
		name     string
		latest   uint64
		atHeight uint64
		start    uint64
		ttl      uint64
		want     uint64
		by       string
		wantErr  error
	}{
		{name: "plain", latest: 14400, atHeight: 14400, start: now - 150, ttl: 900, want: now + 900},
		{name: "retention at the height was shorter", latest: 14400, atHeight: 600, start: now - 150, ttl: 900,
			want: now - 150 + 600 - 75, by: "retention"},
		{name: "latest retention shortens the ttl maximum", latest: 400, atHeight: 14400, start: now - 150, ttl: 900,
			want: now + 100, by: "max_ttl"},
		{name: "payment promise older than the block is the start", latest: 14400, atHeight: 3000, start: now - 2900, ttl: 900,
			wantErr: sdk.ErrValidityWindow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, func(r *rig) {
				r.cfg.TTLS = tt.ttl
				r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre}
			})
			r.rec.da = commitment.DAFibre
			r.rec.retentionStart = tt.start
			r.chain.SetLatest(tt.latest)
			r.chain.SetAt(height, tt.atHeight)
			res, err := r.builder().Commit(bg, r.payload())
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, res.Validity.ValidUntil)
			assert.Equal(t, tt.by, res.Validity.ClampedBy)
			assert.Empty(t, res.Commitment.PayloadRef.Signer, "a Fibre ref carries no signer")
			assert.False(t, res.DAChecked)
		})
	}
}

func TestNonceIsFreshPerCommitment(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	seen := map[string]bool{}
	blobs := map[string]bool{}
	hashes := map[commitment.Hash]bool{}
	for range 200 {
		res, err := b.Commit(bg, r.payload())
		require.NoError(t, err)
		require.Len(t, res.Commitment.Nonce, 16)
		assert.NotEqual(t, make([]byte, 16), res.Commitment.Nonce)
		seen[string(res.Commitment.Nonce)] = true
		blobs[string(res.Blob)] = true
		hashes[res.CommitmentHash] = true
	}
	assert.Len(t, seen, 200, "nonces are unique")
	assert.Len(t, blobs, 200, "the same decision is sealed under a fresh DEK, nonce and salt each time")
	assert.Len(t, hashes, 200)
}

func TestSignerReceivesOnlyTheCommitmentHash(t *testing.T) {
	t.Run("interface has exactly two methods", func(t *testing.T) {
		st := reflect.TypeOf((*sdk.Signer)(nil)).Elem()
		var names []string
		for i := range st.NumMethod() {
			names = append(names, st.Method(i).Name)
		}
		assert.ElementsMatch(t, []string{"PublicKey", "SignCommitment"}, names)
		m, _ := st.MethodByName("SignCommitment")
		assert.Equal(t, reflect.TypeOf(commitment.Hash{}), m.Type.In(1), "the argument is the 32-byte hash, not free bytes")
	})
	t.Run("one call with the hash that the result reports", func(t *testing.T) {
		r := newRig(t)
		res := r.commit()
		require.Equal(t, 1, r.signer.calls())
		assert.Equal(t, res.CommitmentHash, r.signer.hashes[0])
	})
}

func TestBrokenSignersAreCaught(t *testing.T) {
	boom := errors.New("kms down")
	other, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent2"))
	require.NoError(t, err)
	tests := []struct {
		name     string
		override func(r *rig) func(h commitment.Hash) ([]byte, error)
		want     error
	}{
		{"error", func(*rig) func(commitment.Hash) ([]byte, error) {
			return func(commitment.Hash) ([]byte, error) { return nil, boom }
		}, boom},
		{"signature of another key", func(*rig) func(commitment.Hash) ([]byte, error) {
			return func(h commitment.Hash) ([]byte, error) { return other.SignCommitment(bg, h) }
		}, commitment.ErrSignatureInvalid},
		{"signature over another hash", func(r *rig) func(commitment.Hash) ([]byte, error) {
			return func(h commitment.Hash) ([]byte, error) {
				h[0] ^= 1
				return r.signer.inner.SignCommitment(bg, h)
			}
		}, commitment.ErrSignatureInvalid},
		{"short signature", func(*rig) func(commitment.Hash) ([]byte, error) {
			return func(commitment.Hash) ([]byte, error) { return make([]byte, 63), nil }
		}, nil},
		{"nil signature", func(*rig) func(commitment.Hash) ([]byte, error) {
			return func(commitment.Hash) ([]byte, error) { return nil, nil }
		}, nil},
		{"panic", func(*rig) func(commitment.Hash) ([]byte, error) {
			return func(commitment.Hash) ([]byte, error) { panic("signer exploded") }
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			r.signer.override = tt.override(r)
			b := r.builder()
			var res *sdk.Result
			var err error
			require.NotPanics(t, func() { res, err = b.Commit(bg, r.payload()) })
			require.Error(t, err)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			}
			assert.Nil(t, res, "a signature that does not verify is never returned")
		})
	}
}

func TestPublishFailureSignsNothing(t *testing.T) {
	boom := errors.New("fibre unavailable")
	r := newRig(t)
	r.rec.err = boom
	res, err := r.builder().Commit(bg, r.payload())
	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
}

func TestCanceledContext(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	res, err := r.builder().Commit(ctx, r.payload())
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
}

func TestPublishedResultIsChecked(t *testing.T) {
	tests := []struct {
		name string
		mod  func(p *sdk.Published)
		want error
	}{
		{"no block time", func(p *sdk.Published) { p.BlockTime = 0 }, sdk.ErrPublishResult},
		{"unknown da", func(p *sdk.Published) { p.Ref.DA = 3 }, sdk.ErrPublishResult},
		{"da 0", func(p *sdk.Published) { p.Ref.DA = 0 }, sdk.ErrPublishResult},
		{"no height", func(p *sdk.Published) { p.Ref.Height = 0 }, nil},
		{"short namespace", func(p *sdk.Published) { p.Ref.Namespace = p.Ref.Namespace[:28] }, nil},
		{"reserved namespace", func(p *sdk.Published) { p.Ref.Namespace = make([]byte, 29) }, nil},
		{"short commitment", func(p *sdk.Published) { p.Ref.Commitment = p.Ref.Commitment[:31] }, nil},
		{"no signer for da 2", func(p *sdk.Published) { p.Ref.Signer = nil }, nil},
		{"short signer", func(p *sdk.Published) { p.Ref.Signer = p.Ref.Signer[:19] }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			r.rec.mutate = tt.mod
			res, err := r.builder().Commit(bg, r.payload())
			require.Error(t, err)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			}
			assert.Nil(t, res)
			assert.Zero(t, r.signer.calls())
		})
	}
	t.Run("fibre without a payment promise time", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre} })
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = 0
		res, err := r.builder().Commit(bg, r.payload())
		require.ErrorIs(t, err, sdk.ErrPublishResult)
		assert.Nil(t, res)
		assert.Zero(t, r.signer.calls())
	})
	t.Run("signer on a fibre ref", func(t *testing.T) {
		r := newRig(t, func(r *rig) { r.cfg.UnsafeSkipDACheck = []commitment.DA{commitment.DAFibre} })
		r.rec.da = commitment.DAFibre
		r.rec.retentionStart = now - 150
		r.rec.mutate = func(p *sdk.Published) { p.Ref.Signer = bytes.Repeat([]byte{1}, 20) }
		res, err := r.builder().Commit(bg, r.payload())
		require.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestStepwiseFlow(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	assert.Zero(t, r.rec.calls(), "Seal publishes nothing")
	assert.Zero(t, r.signer.calls())

	sum := sha256.Sum256(s.Blob())
	assert.Equal(t, commitment.Hash(sum), s.CiphertextHash())

	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	assert.Equal(t, s.Blob(), r.rec.lastBlob(t))

	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)
	assert.Equal(t, s.CiphertextHash(), commitment.Hash(res.Commitment.CiphertextHash))
	assert.Equal(t, s.PlaintextHash(), commitment.Hash(res.Commitment.PlaintextHash))
	assert.Equal(t, s.Blob(), res.Blob)
	requireValidAtGate(t, res, now)

	t.Run("a second Finalize is refused", func(t *testing.T) {
		res2, err := b.Finalize(bg, s, pub)
		require.ErrorIs(t, err, sdk.ErrAlreadyFinalized)
		assert.Nil(t, res2)
		assert.Equal(t, 1, r.signer.calls(), "a payload never yields two commitments")
	})
	t.Run("a retried Publish sends the same bytes", func(t *testing.T) {
		before := r.rec.lastBlob(t)
		_, err := b.Publish(bg, s)
		require.NoError(t, err)
		assert.Equal(t, before, r.rec.lastBlob(t))
	})
}

func TestStaticRefusalHappensBeforePublishing(t *testing.T) {
	tests := []struct {
		name string
		mod  func(p *payload.Payload)
		want error
	}{
		{"action type in upper case", func(p *payload.Payload) { p.Action.Type = "Application/json" }, payload.ErrMalformed},
		{"action type with a parameter", func(p *payload.Payload) { p.Action.Type = "application/json; charset=utf-8" }, payload.ErrMalformed},
		{"action type without a slash", func(p *payload.Payload) { p.Action.Type = "applicationjson" }, payload.ErrMalformed},
		{"action type empty", func(p *payload.Payload) { p.Action.Type = "" }, payload.ErrMalformed},
		{"action bytes empty", func(p *payload.Payload) { p.Action.Data = nil }, payload.ErrMalformed},
		{"action bytes above the limit", func(p *payload.Payload) { p.Action.Data = make([]byte, commitment.MaxActionSize+1) }, payload.ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			p := r.payload()
			tt.mod(p)
			res, err := r.builder().Commit(bg, p)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, res)
			assert.Zero(t, r.rec.calls(), "nothing is published for a decision the gate would refuse")
			assert.Zero(t, r.signer.calls())
		})
	}
	t.Run("invalid payload", func(t *testing.T) {
		r := newRig(t)
		p := r.payload()
		p.Context.MediaType = "Text/Plain"
		res, err := r.builder().Commit(bg, p)
		require.ErrorIs(t, err, payload.ErrMalformed)
		assert.Nil(t, res)
		assert.Zero(t, r.rec.calls())
	})
	t.Run("nil payload", func(t *testing.T) {
		r := newRig(t)
		res, err := r.builder().Commit(bg, nil)
		require.Error(t, err)
		assert.Nil(t, res)
	})
}

func TestOversizedPayloadIsRefusedBeforeSealing(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.MaxBlobSize = 1024 })
	p := r.payload()
	p.Context.Bytes = make([]byte, 2000)
	res, err := r.builder().Commit(bg, p)
	require.ErrorIs(t, err, payload.ErrTooLarge)
	assert.Nil(t, res)
	assert.Zero(t, r.rec.calls())

	p.Context.Bytes = make([]byte, 100)
	_, err = r.builder().Commit(bg, p)
	require.NoError(t, err)
}

func TestCommitDoesNotModifyThePayload(t *testing.T) {
	r := newRig(t)
	p := r.payload()
	want, err := payload.Encode(p)
	require.NoError(t, err)
	_, err = r.builder().Commit(bg, p)
	require.NoError(t, err)
	got, err := payload.Encode(p)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestSealedKeepsItsOwnCopyOfTheDecision(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	p := r.payload()
	s, err := b.Seal(bg, p)
	require.NoError(t, err)
	p.Action.Data[0] ^= 1 // the caller changes the action bytes after sealing
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)
	want := r.payload().Action
	h, err := commitment.ActionHash(want.Type, want.Data)
	require.NoError(t, err)
	assert.Equal(t, h[:], res.Commitment.Action.Hash, "the commitment follows what was sealed")
	assert.Equal(t, want.Data, res.Action, "the result carries what was sealed")
}

func TestConcurrentCommits(t *testing.T) {
	r := newRig(t)
	b := r.builder()
	base := r.payload()
	const workers, each = 8, 6
	var wg sync.WaitGroup
	var mu sync.Mutex
	nonces := map[string]bool{}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				res, err := b.Commit(bg, sdkfix.ClonePayload(base))
				if !assert.NoError(t, err) {
					return
				}
				mu.Lock()
				nonces[string(res.Commitment.Nonce)] = true
				mu.Unlock()
				_, _, err = commitment.VerifyForGate(res.Envelope, now, scope, params)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	assert.Len(t, nonces, workers*each)
}

// Error strings carry sizes, ids and sentinel names, never key or payload
// bytes.
func TestErrorsDoNotLeakSecrets(t *testing.T) {
	seed := gatefix.Key(t, "agent1").Seed()
	v := newRig(t).vec
	var secrets [][]byte
	secrets = append(secrets, seed, gatefix.Key(t, "agent1"))
	for _, k := range v.Keys {
		secrets = append(secrets, k.Priv.Bytes())
	}
	c0 := v.Case0(t)
	secrets = append(secrets, c0.Salt[:], c0.DEK)

	var errs []error
	collect := func(err error) {
		require.Error(t, err)
		errs = append(errs, err)
	}
	run := func(mod func(r *rig), p func(*payload.Payload)) {
		var mods []func(*rig)
		if mod != nil {
			mods = append(mods, mod)
		}
		r := newRig(t, mods...)
		pl := r.payload()
		if p != nil {
			p(pl)
		}
		b, err := r.tryNew()
		if err != nil {
			collect(err)
			return
		}
		_, err = b.Commit(bg, pl)
		collect(err)
	}
	run(func(r *rig) { r.rec.err = errors.New("publish failed") }, nil)
	run(func(r *rig) { r.rec.other = []byte("another blob") }, nil)
	run(func(r *rig) {
		r.signer.override = func(commitment.Hash) ([]byte, error) { return make([]byte, 64), nil }
	}, nil)
	run(nil, func(p *payload.Payload) { p.Action.Data = nil })
	run(func(r *rig) { r.cfg.Recipients = nil }, nil)

	for _, err := range errs {
		for _, s := range secrets {
			if len(s) == 0 {
				continue
			}
			assert.NotContainsf(t, err.Error(), string(s), "raw secret in %q", err)
			assert.NotContainsf(t, err.Error(), sdkfix.HexOf(s), "hex secret in %q", err)
		}
	}
}
