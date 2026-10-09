package edictad_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
)

var auditorSeed = sha256.Sum256([]byte("edictad private test auditor"))

func auditorKey(t *testing.T) *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(auditorSeed[:])
	require.NoError(t, err)
	return k
}

// newPrivateEnv is newPolicyEnv with auditors in the mandate.
func newPrivateEnv(t *testing.T) *policyEnv {
	p := newPolicyEnv(t)
	pub := auditorKey(t).PublicKey().Bytes()
	p.mandate.Auditors = []policy.Auditor{{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "Alice"}}
	p.mandate.StateSalt = bytes.Repeat([]byte{0x33}, 32)
	p.file = p.sign(p.principal, p.mandate)
	return p
}

func readFile(t *testing.T, path string) []byte {
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func (p *policyEnv) openPrivate(kind policy.PrivateKind, key commitment.Hash) []byte {
	p.t.Helper()
	rec, err := p.real.PrivateBlob(bg, kind, key)
	require.NoError(p.t, err)
	o, err := privatebox.NewOpener(auditorKey(p.t))
	require.NoError(p.t, err)
	pt, _, err := o.Open(kind, rec.Envelope)
	require.NoError(p.t, err)
	return pt
}

func TestPrivateMandateIsPublishedSealed(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	assert.Equal(t, []archive.Kind{archive.KindPrivateBlob, archive.KindPrivateBlob}, p.fs.puts,
		"the mandate and the genesis closed set, both sealed; never kind 7")
	_, mh, err := policy.VerifyMandate(readFile(t, p.file))
	require.NoError(t, err)
	_, err = p.real.Mandate(bg, mh)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, h, err := policy.DecodeSignedMandate(p.openPrivate(policy.PrivateMandate, mh))
	require.NoError(t, err)
	assert.Equal(t, mh, h)

	set := policy.EmptyClosedSet()
	b, err := policy.EncodeClosedSet(&set)
	require.NoError(t, err)
	key := policy.NewStateHasher(p.mandate).BlobKey(policy.PrivateClosedSet, policy.HashClosedSetBytes(b))
	assert.Equal(t, b, p.openPrivate(policy.PrivateClosedSet, key), "the genesis set under its blinded key")
}

func TestPrivateAllowWritesSealedRecordsInOrder(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)

	d := p.send(1, 1_000_000)
	st, _, body := p.authorizeRaw(d)
	require.Equal(t, 200, st)
	assert.Equal(t, []archive.Kind{
		archive.KindPrivateBlob, archive.KindDecision, archive.KindPrivateBlob,
		archive.KindPolicyAllow, archive.KindPolicySuccessor, archive.KindAuthorization,
	}, kindsOf(p.fs.puts, n), "the action before the decision, the PrivatePart before the allow")

	dec, err := p.real.Decision(bg, d.hash)
	require.NoError(t, err)
	assert.EqualValues(t, archive.FormPrivate, dec.Form)
	assert.Nil(t, dec.Action)
	assert.Nil(t, dec.ActionSalt)

	allow, err := p.real.PolicyAllow(bg, d.hash)
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(allow.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	require.True(t, sv.Verdict.Private())
	part := p.openPrivate(policy.PrivatePartKind, commitment.Hash(sv.Verdict.PrivateHash))
	assert.False(t, bytes.Contains(body, part), "an answer never carries the PrivatePart")
	pp, err := policy.DecodePrivatePart(part)
	require.NoError(t, err)
	merged, err := policy.MergeVerdict(&sv.Verdict, pp)
	require.NoError(t, err)
	assert.Equal(t, "celestia/tia-transfer/v1", merged.Extractor)

	ent := p.registryKeys()
	require.Len(t, ent, 1)
	assert.Equal(t, part, ent[0].PrivatePart, "the registry keeps the clear PrivatePart for the repair")
}

func TestPrivateDenyHidesTheReasonAndDedups(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	n := len(p.fs.puts)

	d := p.send(1, 6_000_000)
	st, _, body := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	assert.True(t, hasCode(body, "policy.ErrAmountAboveMax"), "the caller learns the reason")
	assert.Equal(t, []archive.Kind{
		archive.KindPrivateBlob, archive.KindDecision, archive.KindPrivateBlob, archive.KindPolicyDeny, archive.KindRejection,
	}, kindsOf(p.fs.puts, n))
	_, err := p.real.Rejection(bg, d.hash, "ErrDenied")
	require.NoError(t, err, "the private marker")
	_, err = p.real.Rejection(bg, d.hash, "ErrAmountAboveMax")
	require.ErrorIs(t, err, archive.ErrNotFound, "no public reason")

	// Retries refused for the same reason write no second deny, even when
	// they race; the marker write is still issued.
	n = len(p.fs.puts)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _, _ := p.authorizeRaw(d)
			assert.GreaterOrEqual(t, st, 400)
		}()
	}
	wg.Wait()
	tail := kindsOf(p.fs.puts, n)
	count := func(k archive.Kind) int {
		c := 0
		for _, x := range tail {
			if x == k {
				c++
			}
		}
		return c
	}
	assert.Zero(t, count(archive.KindPolicyDeny))
	assert.Equal(t, 4, count(archive.KindRejection))
	assert.Equal(t, 4, count(archive.KindPrivateBlob), "only the decision's sealed action, rewritten idempotently")
}

func TestPrivateDenyMarkerIsRepairedOnARetry(t *testing.T) {
	p := newPrivateEnv(t)
	p.startPolicy()
	p.fs.failKind(archive.KindRejection, errArchiveDown)
	d := p.send(1, 6_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	_, err := p.real.Rejection(bg, d.hash, "ErrDenied")
	require.ErrorIs(t, err, archive.ErrNotFound)

	p.fs.failKind(archive.KindRejection, nil)
	st, _, _ = p.authorizeRaw(d)
	require.GreaterOrEqual(t, st, 400)
	_, err = p.real.Rejection(bg, d.hash, "ErrDenied")
	require.NoError(t, err, "a dedup hit still writes the marker")
	assert.Equal(t, 1, p.fs.putCount(archive.KindPolicyDeny))
}

func TestPrivateSweepRewritesTheChain(t *testing.T) {
	p := newPrivateEnv(t)
	p.fs.failKind(archive.KindPolicyAllow, errArchiveDown)
	p.startPolicy()
	d := p.send(1, 1_000_000)
	st, _, _ := p.authorizeRaw(d)
	require.Equal(t, 200, st)
	_, err := p.real.PolicyAllow(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = p.real.Authorization(bg, d.hash)
	require.ErrorIs(t, err, archive.ErrNotFound, "no Authorization record ahead of its verdict")

	// The retry queue dies with the process; the next start's sweep
	// rewrites the chain from the registry entry.
	_ = p.srv.Shutdown(bg)
	p.fs.failKind(archive.KindPolicyAllow, nil)
	p.startPolicy()
	allow, err := p.real.PolicyAllow(bg, d.hash)
	require.NoError(t, err)
	sv, _, err := policy.VerifyVerdict(allow.SignedVerdict, p.gatePub)
	require.NoError(t, err)
	p.openPrivate(policy.PrivatePartKind, commitment.Hash(sv.Verdict.PrivateHash))
	_, err = p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
}
