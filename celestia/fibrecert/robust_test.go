package fibrecert_test

import (
	"crypto/ed25519"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

const bucket = int64(1_000_000)

type signer struct {
	key    ed25519.PrivateKey
	tokens int64
	signs  bool
	bad    bool
}

func seedPriv(i int) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0], s[1] = byte(i), byte(i>>8)
	return ed25519.NewKeyFromSeed(s)
}

// certOf builds the PFF and the validator list. A signer that does not sign
// leaves an empty slot, and a bad one carries a signature of another message.
func certOf(t *testing.T, sg []signer) (fibrecert.PFF, []fibrecert.Validator) {
	t.Helper()
	p := fibrecert.Promise{ChainID: "mocha-5", Height: 10, Namespace: make([]byte, 29), BlobSize: 4096,
		SignerKey: append([]byte{2}, make([]byte, 32)...)}
	sb, err := fibrecert.SignBytes(p)
	require.NoError(t, err)
	f := fibrecert.PFF{Promise: p}
	var vals []fibrecert.Validator
	for _, s := range sg {
		vals = append(vals, fibrecert.Validator{PubKey: s.key.Public().(ed25519.PublicKey), Power: s.tokens})
		switch {
		case s.bad:
			f.Signatures = append(f.Signatures, ed25519.Sign(s.key, append([]byte("other"), sb...)))
		case s.signs:
			f.Signatures = append(f.Signatures, ed25519.Sign(s.key, sb))
		default:
			f.Signatures = append(f.Signatures, nil)
		}
	}
	return f, vals
}

func TestTokensRobustTable(t *testing.T) {
	k := func(i int) ed25519.PrivateKey { return seedPriv(i + 1) }
	tests := []struct {
		name string
		sg   []signer
		want bool
	}{
		{"wide margin accepted", []signer{{k(0), 70 * bucket, true, false}, {k(1), 30 * bucket, false, false}}, true},
		{"wide margin rejected", []signer{{k(0), 30 * bucket, true, false}, {k(1), 70 * bucket, false, false}}, true},
		{"nobody signed", []signer{{k(0), 50 * bucket, false, false}, {k(1), 50 * bucket, false, false}}, true},
		{"everybody signed", []signer{{k(0), 50 * bucket, true, false}, {k(1), 50 * bucket, true, false}}, true},
		{"edge: accepted at the actual tokens, rejected at the worst", []signer{{k(0), 67*bucket + bucket/2, true, false}, {k(1), 33 * bucket, false, false}}, false},
		{"edge: exact multiples still depend on the bucket", []signer{{k(0), 67 * bucket, true, false}, {k(1), 33 * bucket, false, false}}, false},
		{"edge: rejected at the actual tokens, accepted at the best", []signer{{k(0), 67*bucket - 1, true, false}, {k(1), 33 * bucket, false, false}}, false},
		{"flip inside a bucket is the same bucket", []signer{{k(0), 80*bucket + 1, true, false}, {k(1), 20*bucket + bucket - 1, false, false}}, true},
		{"bad signature before the stop point", []signer{{k(0), 40 * bucket, false, true}, {k(1), 60 * bucket, true, false}}, true},
		{"bad signature after the stop point", []signer{{k(0), 90 * bucket, true, false}, {k(1), 10 * bucket, false, true}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, vals := certOf(t, tc.sg)
			got, err := fibrecert.TokensRobust(f, vals)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTokensRobustRefusals(t *testing.T) {
	f, vals := certOf(t, []signer{{seedPriv(1), 5 * bucket, true, false}, {seedPriv(2), 5 * bucket, true, false}})
	t.Run("more signatures than validators", func(t *testing.T) {
		_, err := fibrecert.TokensRobust(f, vals[:1])
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})
	t.Run("zero power", func(t *testing.T) {
		v := append([]fibrecert.Validator(nil), vals...)
		v[0].Power = 0
		_, err := fibrecert.TokensRobust(f, v)
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})
	t.Run("duplicate key", func(t *testing.T) {
		v := []fibrecert.Validator{vals[0], vals[0]}
		_, err := fibrecert.TokensRobust(f, v)
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})
	t.Run("short key", func(t *testing.T) {
		v := []fibrecert.Validator{{PubKey: []byte{1}, Power: bucket}, vals[1]}
		_, err := fibrecert.TokensRobust(f, v)
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})
	t.Run("no validators", func(t *testing.T) {
		require.NotPanics(t, func() {
			_, _ = fibrecert.TokensRobust(fibrecert.PFF{}, nil)
		})
	})
	t.Run("no signatures", func(t *testing.T) {
		got, err := fibrecert.TokensRobust(fibrecert.PFF{Promise: f.Promise}, vals)
		require.NoError(t, err)
		assert.True(t, got)
	})
}

// A robust verdict is the verdict of every token assignment that keeps the
// consensus powers; the walk over random assignments must agree.
func TestTokensRobustMatchesTheWalk(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var robust, dependent int
	for iter := 0; iter < 150; iter++ {
		n := 3 + rng.Intn(4)
		sg := make([]signer, n)
		for i := range sg {
			sg[i] = signer{key: seedPriv(100 + i), tokens: int64(1+rng.Intn(12))*bucket + rng.Int63n(bucket), signs: rng.Intn(3) > 0}
			sg[i].bad = sg[i].signs && rng.Intn(25) == 0
		}
		f, vals := certOf(t, sg)
		got, err := fibrecert.TokensRobust(f, vals)
		require.NoError(t, err)
		_, base := fibrecert.VerifyCertificate(f, vals)

		if !got {
			dependent++
			continue
		}
		robust++
		for try := 0; try < 40; try++ {
			alt := append([]fibrecert.Validator(nil), vals...)
			for i := range alt {
				alt[i].Power = alt[i].Power/bucket*bucket + rng.Int63n(bucket)
			}
			_, err := fibrecert.VerifyCertificate(f, alt)
			require.Equal(t, base == nil, err == nil, "iteration %d try %d", iter, try)
		}
	}
	assert.Positive(t, robust)
	assert.Positive(t, dependent, "the generator reaches the edge of a bucket")
}

func TestTokensRobustLive(t *testing.T) {
	l := fibrefix.LoadLive(t)
	pff, ok, err := fibrecert.ParsePFF(l.PFFTx)
	require.NoError(t, err)
	require.True(t, ok)
	vals, err := fibrecert.ParseHistoricalInfo(l.Hist)
	require.NoError(t, err)
	got, err := fibrecert.TokensRobust(pff, vals)
	require.NoError(t, err)
	assert.True(t, got, "76 percent signed, far from the threshold")
}
