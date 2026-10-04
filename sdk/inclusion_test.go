package sdk_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// verifierFn is an InclusionVerifier with no independence report.
type verifierFn struct {
	mu    sync.Mutex
	fn    func(ctx context.Context, ref commitment.PayloadRef) (uint64, error)
	calls []commitment.PayloadRef
	log   *[]string
}

func (v *verifierFn) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (uint64, error) {
	v.mu.Lock()
	v.calls = append(v.calls, ref)
	if v.log != nil {
		*v.log = append(*v.log, "verify")
	}
	v.mu.Unlock()
	return v.fn(ctx, ref)
}

func (v *verifierFn) count() int { v.mu.Lock(); defer v.mu.Unlock(); return len(v.calls) }

// reporting adds the optional independence report.
type reporting struct {
	*verifierFn
	independent bool
}

func (r reporting) Independent() bool { return r.independent }

func echoTime(t uint64) *verifierFn {
	return &verifierFn{fn: func(context.Context, commitment.PayloadRef) (uint64, error) { return t, nil }}
}

func finalizeOnce(t *testing.T, r *rig) (*sdk.Result, error) {
	t.Helper()
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	return b.Finalize(bg, s, pub)
}

func TestInclusionVerifierAccepts(t *testing.T) {
	v := echoTime(now - 100)
	r := newRig(t)
	r.deps.Inclusion = v
	res, err := finalizeOnce(t, r)
	require.NoError(t, err)
	assert.Equal(t, 1, r.signer.calls())
	assert.Equal(t, 1, v.count())
	assert.Equal(t, res.Published.Ref, v.calls[0], "the verifier sees exactly the reference that is signed")
	assert.Equal(t, uint64(now-100), res.Published.BlockTime)
	requireValidAtGate(t, res, now)
}

func TestInclusionRejectionSignsNothing(t *testing.T) {
	boom := errors.New("provider unreachable")
	tests := []struct {
		name string
		fn   func(context.Context, commitment.PayloadRef) (uint64, error)
		want error
	}{
		{"verifier rejects", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return 0, sdk.ErrInclusionUnverified
		}, sdk.ErrInclusionUnverified},
		{"any verifier error is unverified", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return 0, boom
		}, sdk.ErrInclusionUnverified},
		{"block time later", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return now - 99, nil
		}, sdk.ErrBlockTimeMismatch},
		{"block time earlier", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return now - 101, nil
		}, sdk.ErrBlockTimeMismatch},
		{"block time far off", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return now - 3600, nil
		}, sdk.ErrBlockTimeMismatch},
		{"zero time", func(context.Context, commitment.PayloadRef) (uint64, error) {
			return 0, nil
		}, sdk.ErrBlockTimeMismatch},
		{"verifier panics", func(context.Context, commitment.PayloadRef) (uint64, error) {
			panic("canary-panic-value")
		}, sdk.ErrInclusionUnverified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t)
			r.deps.Inclusion = &verifierFn{fn: tt.fn}
			res, err := finalizeOnce(t, r)
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, res)
			assert.Zero(t, r.signer.calls(), "nothing is signed")
			assert.NotContains(t, err.Error(), "canary-panic-value", "a panic value never reaches an error string")
		})
	}
}

// The submitter claims a height the chain does not confirm.
func TestInclusionHeightMismatch(t *testing.T) {
	const trueHeight = height
	r := newRig(t)
	r.rec.height = trueHeight + 7
	v := &verifierFn{fn: func(_ context.Context, ref commitment.PayloadRef) (uint64, error) {
		if ref.Height != trueHeight {
			return 0, sdk.ErrInclusionUnverified
		}
		return now - 100, nil
	}}
	r.deps.Inclusion = v
	res, err := finalizeOnce(t, r)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
	require.Equal(t, 1, v.count())
	assert.Equal(t, trueHeight+7, v.calls[0].Height, "the verifier is asked about the claimed height")
}

func TestInclusionVerifierHonoursCallTimeout(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.CallTimeout = 20 * time.Millisecond })
	r.deps.Inclusion = &verifierFn{fn: func(ctx context.Context, _ commitment.PayloadRef) (uint64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	res, err := finalizeOnce(t, r)
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
}

// Order: the DA recompute first, the verifier next, the signer last.
func TestInclusionRunsAfterDACheckAndBeforeSigning(t *testing.T) {
	t.Run("recompute failure skips the verifier", func(t *testing.T) {
		v := echoTime(now - 100)
		r := newRig(t)
		r.rec.other = []byte("another blob")
		r.deps.Inclusion = v
		res, err := finalizeOnce(t, r)
		require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
		assert.Nil(t, res)
		assert.Zero(t, v.count())
		assert.Zero(t, r.signer.calls())
	})
	t.Run("verifier before signer", func(t *testing.T) {
		var log []string
		v := echoTime(now - 100)
		v.log = &log
		r := newRig(t)
		r.signer.override = func(h commitment.Hash) ([]byte, error) {
			log = append(log, "sign")
			return nil, errors.New("stop after recording")
		}
		r.deps.Inclusion = v
		_, err := finalizeOnce(t, r)
		require.Error(t, err)
		assert.Equal(t, []string{"verify", "sign"}, log)
	})
}

func TestExpectedNamespaceAndSigners(t *testing.T) {
	signer := []byte("0123456789abcdefghij")
	other20 := []byte("jihgfedcba9876543210")
	otherNS := append(make([]byte, 19), []byte("edicta/zzz")...)
	tests := []struct {
		name    string
		ns      []byte
		signers [][]byte
		want    error
	}{
		{"both match", testNS, [][]byte{other20, signer}, nil},
		{"namespace only", testNS, nil, nil},
		{"signer only", nil, [][]byte{signer}, nil},
		{"wrong namespace", otherNS, nil, sdk.ErrUnexpectedRef},
		{"signer not in allowlist", nil, [][]byte{other20}, sdk.ErrUnexpectedRef},
		{"namespace ok signer wrong", testNS, [][]byte{other20}, sdk.ErrUnexpectedRef},
		{"namespace wrong signer ok", otherNS, [][]byte{signer}, sdk.ErrUnexpectedRef},
	}
	for _, tt := range tests {
		for _, withVerifier := range []bool{false, true} {
			name := tt.name
			if withVerifier {
				name += "/with verifier"
			}
			t.Run(name, func(t *testing.T) {
				r := newRig(t)
				r.cfg.ExpectNamespace, r.cfg.ExpectSigners = tt.ns, tt.signers
				v := echoTime(now - 100)
				if withVerifier {
					r.deps.Inclusion = v
				}
				res, err := finalizeOnce(t, r)
				if tt.want == nil {
					require.NoError(t, err)
					assert.NotNil(t, res)
					return
				}
				require.ErrorIs(t, err, tt.want)
				assert.Nil(t, res)
				assert.Zero(t, r.signer.calls())
				assert.Zero(t, v.count(), "the expectation is checked before the chain is asked")
			})
		}
	}
}

func TestExpectedValuesAreValidatedAtConfig(t *testing.T) {
	for name, mod := range map[string]func(*rig){
		"short namespace": func(r *rig) { r.cfg.ExpectNamespace = testNS[:28] },
		"short signer":    func(r *rig) { r.cfg.ExpectSigners = [][]byte{make([]byte, 19)} },
		"long signer":     func(r *rig) { r.cfg.ExpectSigners = [][]byte{make([]byte, 21)} },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, mod)
			_, err := r.tryNew()
			require.ErrorIs(t, err, sdk.ErrInvalidConfig)
		})
	}
}

func TestExpectedValuesAreCopied(t *testing.T) {
	r := newRig(t)
	ns := append([]byte(nil), testNS...)
	r.cfg.ExpectNamespace = ns
	b := r.builder()
	ns[0] ^= 1
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	_, err = b.Finalize(bg, s, pub)
	require.NoError(t, err, "later changes to the caller's slice do not move the expectation")
}

func TestSubmitterTrustLevels(t *testing.T) {
	good := echoTime(now - 100)
	tests := []struct {
		name  string
		trust sdk.SubmitterTrust
		inc   sdk.InclusionVerifier
		ok    bool
	}{
		{"zero is refused", 0, nil, false},
		{"zero with verifier is refused", 0, good, false},
		{"unknown level", 9, good, false},
		{"same operator, no verifier", sdk.SubmitterSameOperator, nil, true},
		{"same operator, self check", sdk.SubmitterSameOperator, reporting{good, false}, true},
		{"same operator, independent", sdk.SubmitterSameOperator, reporting{good, true}, true},
		{"untrusted, no verifier", sdk.SubmitterUntrusted, nil, false},
		{"untrusted, self check", sdk.SubmitterUntrusted, reporting{good, false}, false},
		{"untrusted, independent", sdk.SubmitterUntrusted, reporting{good, true}, true},
		{"untrusted, verifier without a report is refused", sdk.SubmitterUntrusted, good, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, func(r *rig) { r.cfg.SubmitterTrust = tt.trust })
			r.deps.Inclusion = tt.inc
			b, err := r.tryNew()
			if !tt.ok {
				require.ErrorIs(t, err, sdk.ErrInvalidConfig)
				assert.Nil(t, b)
				return
			}
			require.NoError(t, err)
			res, err := b.Commit(bg, r.payload())
			require.NoError(t, err)
			requireValidAtGate(t, res, now)
		})
	}
}

// A different-party submitter and a lying report: with an independent
// verifier the lie is caught, and nothing is signed.
func TestUntrustedSubmitterLyingAboutTime(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.SubmitterTrust = sdk.SubmitterUntrusted })
	r.rec.blockTime = now - 100
	r.deps.Inclusion = reporting{echoTime(now - 5000), true}
	b := r.builder()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	res, err := b.Finalize(bg, s, pub)
	require.ErrorIs(t, err, sdk.ErrBlockTimeMismatch)
	assert.Nil(t, res)
	assert.Zero(t, r.signer.calls())
}

func TestDefaultConfigHasNoTrustLevel(t *testing.T) {
	c := sdk.DefaultConfig()
	assert.Zero(t, c.SubmitterTrust, "the caller must choose")
	assert.Equal(t, 120*time.Second, c.MaxPublishWait)
	assert.Equal(t, 2, c.MaxReissues)
}
