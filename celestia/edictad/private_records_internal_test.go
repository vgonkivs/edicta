package edictad

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
)

// A rollover under a private mandate archives the PrivatePart, then the
// closed bucket and the new closed set sealed under their blinded keys, and
// no clear bucket or set.
func TestPrivateAllowRecordsOnARollover(t *testing.T) {
	seed := sha256.Sum256([]byte("edictad records test auditor"))
	sk, err := ecdh.X25519().NewPrivateKey(seed[:])
	require.NoError(t, err)
	pub := sk.PublicKey().Bytes()
	m := &policy.Mandate{
		Auditors:  []policy.Auditor{{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "A"}},
		StateSalt: bytes.Repeat([]byte{7}, 32), MandateID: make([]byte, 16),
	}
	p := newPolInfo("g", m, nil)

	bucket, err := policy.EncodeBucket(&policy.Bucket{Format: 1, Index: 3, Count: 1,
		Sums: []policy.Sum{{Asset: "a", Scale: 0, Sum: []byte{5}}}})
	require.NoError(t, err)
	set := policy.ClosedSet{Format: 1, Buckets: []policy.ClosedRef{{Index: 3, Hash: hashOf(policy.HashBucketBytes(bucket))}}}
	setBytes, err := policy.EncodeClosedSet(&set)
	require.NoError(t, err)
	part, err := policy.EncodePrivatePart(&policy.PrivatePart{Format: 1, Salt: make([]byte, 32), DecidedAt: 1})
	require.NoError(t, err)

	verdict := signedPrivateAllow(t, part)
	recs, err := p.allowRecords(bucket, setBytes, verdict, part, commitment.Hash{1})
	require.NoError(t, err)
	var kinds []archive.Kind
	for _, r := range recs {
		kinds = append(kinds, r.Kind())
	}
	assert.Equal(t, []archive.Kind{archive.KindPrivateBlob, archive.KindPrivateBlob, archive.KindPrivateBlob,
		archive.KindPolicyAllow, archive.KindPolicySuccessor}, kinds)

	o, err := privatebox.NewOpener(sk)
	require.NoError(t, err)
	h := policy.NewStateHasher(m)
	for i, want := range []struct {
		kind  policy.PrivateKind
		plain []byte
		key   commitment.Hash
	}{
		{policy.PrivatePartKind, part, policy.PrivateHash(part)},
		{policy.PrivateBucket, bucket, h.BlobKey(policy.PrivateBucket, policy.HashBucketBytes(bucket))},
		{policy.PrivateClosedSet, setBytes, h.BlobKey(policy.PrivateClosedSet, policy.HashClosedSetBytes(setBytes))},
	} {
		r := recs[i].(*archive.PrivateBlobRecord)
		assert.Equal(t, want.kind, r.PlaintextKind)
		assert.Equal(t, want.key[:], r.Hash, "record %d under its (blinded) key", i)
		pt, _, err := o.Open(r.PlaintextKind, r.Envelope)
		require.NoError(t, err)
		assert.Equal(t, want.plain, pt)
	}
	assert.NotEqual(t, hashOf(policy.HashBucketBytes(bucket)), recs[1].(*archive.PrivateBlobRecord).Hash, "never the clear bucket hash")
}

func hashOf(h commitment.Hash) []byte { return h[:] }

// signedPrivateAllow is a private-form allow at genesis for the part.
func signedPrivateAllow(t *testing.T, part []byte) []byte {
	g := policy.GenesisStateHash()
	ph := policy.PrivateHash(part)
	h1 := commitment.Hash{1}
	v := policy.Verdict{
		Format: 1, GateID: "g", MandateHash: make([]byte, 32), CommitmentHash: h1[:],
		ActionHash: make([]byte, 32), AgentPubKey: make([]byte, 32), Outcome: policy.OutcomeAllow,
		NewStateHash: make([]byte, 32), PrivateHash: ph[:], BlindPrevStateHash: g[:],
	}
	canon, err := policy.EncodeVerdict(&v)
	require.NoError(t, err)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sig := ed25519.Sign(key, policy.VerdictSigningMessage(policy.HashVerdict(canon)))
	b, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: v, Signature: sig})
	require.NoError(t, err)
	return b
}
