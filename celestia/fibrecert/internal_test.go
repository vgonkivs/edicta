package fibrecert

import (
	"crypto/ed25519"
	"testing"
	"time"

	cmted "github.com/cometbft/cometbft/crypto/ed25519"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	return ed25519.NewKeyFromSeed(s)
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func testPromise() Promise {
	return Promise{ChainID: "mocha-5", Height: 10, Namespace: make([]byte, 29),
		BlobSize: 4096, CreationTime: time.Unix(1700000000, 0), SignerKey: append([]byte{2}, make([]byte, 32)...)}
}

// headerFor builds the promise header committing to the set that
// NewValidatorSet makes from vals.
func headerFor(t *testing.T, vals []Validator) []byte {
	t.Helper()
	cv := make([]*core.Validator, 0, len(vals))
	for _, v := range vals {
		cv = append(cv, core.NewValidator(cmted.PubKey(v.PubKey), v.Power/powerReduction))
	}
	vs := core.NewValidatorSet(cv)
	h := core.Header{
		Version: cmtversion.Consensus{Block: 11}, ChainID: "mocha-5", Height: 10, Time: time.Unix(1700000000, 0),
		NextValidatorsHash: vs.Hash(), ValidatorsHash: vs.Hash(), ProposerAddress: vs.Validators[0].Address,
	}
	hp := h.ToProto()
	b, err := hp.Marshal()
	require.NoError(t, err)
	return b
}

// sortedSet returns vals in the order NewValidatorSet stores them.
func sortedSet(vals []Validator) []Validator {
	cv := make([]*core.Validator, 0, len(vals))
	byKey := map[string]Validator{}
	for _, v := range vals {
		cv = append(cv, core.NewValidator(cmted.PubKey(v.PubKey), v.Power/powerReduction))
		byKey[string(v.PubKey)] = v
	}
	out := make([]Validator, 0, len(vals))
	for _, v := range core.NewValidatorSet(cv).Validators {
		out = append(out, byKey[string(v.PubKey.Bytes())])
	}
	return out
}

func TestCheckValset(t *testing.T) {
	a, b, c := testKey(1), testKey(2), testKey(3)
	stored := sortedSet([]Validator{{pub(a), 34_000_000}, {pub(b), 33_000_000}, {pub(c), 33_000_000}})
	require.Equal(t, pub(a), stored[0].PubKey)
	hdr := headerFor(t, stored)

	t.Run("stored order accepted", func(t *testing.T) {
		m, err := checkValset(stored, ValsetEvidence{PromiseHeader: hdr})
		require.NoError(t, err)
		assert.Equal(t, "next_validators_hash@10", m)
	})

	t.Run("permuted list rejected", func(t *testing.T) {
		swapped := []Validator{stored[0], stored[2], stored[1]}
		m, err := checkValset(swapped, ValsetEvidence{PromiseHeader: hdr})
		require.ErrorIs(t, err, ErrValsetMismatch)
		assert.Empty(t, m)
	})

	t.Run("repeated validator is malformed", func(t *testing.T) {
		vals := []Validator{stored[0], stored[0], stored[1], stored[2]}
		_, err := checkValset(vals, ValsetEvidence{})
		require.ErrorIs(t, err, ErrCertificateMalformed)
	})

	t.Run("other set", func(t *testing.T) {
		other := []Validator{{pub(a), 34_000_000}, {pub(b), 66_000_000}}
		_, err := checkValset(sortedSet(other), ValsetEvidence{PromiseHeader: hdr})
		require.ErrorIs(t, err, ErrValsetMismatch)
	})
}

// With the list order forged the signer walk reaches quorum on the
// archived order and never sees the garbage slot; the keeper walks the stored
// order, where the same signatures fail. The order check must reject it.
func TestPermutedListSwap(t *testing.T) {
	p := testPromise()
	sb, err := SignBytes(p)
	require.NoError(t, err)
	a, b, c := testKey(1), testKey(2), testKey(3)
	keys := map[string]ed25519.PrivateKey{string(pub(a)): a, string(pub(b)): b, string(pub(c)): c}
	stored := sortedSet([]Validator{{pub(a), 34_000_000}, {pub(b), 33_000_000}, {pub(c), 33_000_000}})
	forged := []Validator{stored[0], stored[2], stored[1]}
	hdr := headerFor(t, stored)

	sigs := [][]byte{
		ed25519.Sign(keys[string(forged[0].PubKey)], sb),
		ed25519.Sign(keys[string(forged[1].PubKey)], sb),
		make([]byte, ed25519.SignatureSize),
	}
	f := PFF{Promise: p, Signatures: sigs}

	rep, err := VerifyCertificate(f, forged)
	require.NoError(t, err, "the archived order alone is accepted by the walk")
	assert.Equal(t, 1, rep.InvalidAfterStop)

	_, err = VerifyCertificate(f, stored)
	require.ErrorIs(t, err, ErrCertificateInvalid, "the keeper's order rejects it")

	_, err = checkValset(forged, ValsetEvidence{PromiseHeader: hdr})
	require.ErrorIs(t, err, ErrValsetMismatch)
}
