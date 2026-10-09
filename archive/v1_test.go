package archive_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

func signedAuthV1(t *testing.T, mode, deadline uint64) []byte {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	a := commitment.Authorization{Version: 1, CommitmentHash: make([]byte, 32), ActionHash: make([]byte, 32),
		GateID: "gate-1", Expires: 100, Path: commitment.PathDA, Mode: mode, AnchorDeadline: deadline}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	sig := ed25519.Sign(priv, commitment.AuthorizationSigningMessageFor(1, commitment.HashAuthorizationFor(1, canon)))
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return b
}

func TestAuthorizationRecordV1(t *testing.T) {
	k2 := &archive.K2Inputs{DA: commitment.DACelestiaBlob, CheckedAt: 50, BlockTime: 40, BlobRetentionS: 14400}
	rec := &archive.AuthorizationRecord{SignedAuthorization: signedAuthV1(t, commitment.ModeStrict, 0), AuthorizedAt: 50, K2: k2}
	b, err := archive.Encode(rec)
	require.NoError(t, err, "a strict Authorization v1 is a valid record")
	got, err := archive.Decode(b)
	require.NoError(t, err)
	assert.Equal(t, rec.SignedAuthorization, got.(*archive.AuthorizationRecord).SignedAuthorization)

	fast := &archive.AuthorizationRecord{SignedAuthorization: signedAuthV1(t, commitment.ModeFast, 7), AuthorizedAt: 50, K2: k2}
	_, err = archive.Encode(fast)
	require.ErrorIs(t, err, commitment.ErrMissingField, "fast mode needs its K2 window")
}

func TestMandateRefusalsAreMarkers(t *testing.T) {
	for _, n := range []string{"ErrMandateRefMissing", "ErrMandateMismatch"} {
		assert.True(t, archive.IsVerdict(n), n)
		assert.False(t, archive.IsPolicyDeny(n), n)
	}
	for _, n := range []string{"ErrVersionNotAccepted", "ErrAnchorPending"} {
		assert.False(t, archive.IsVerdict(n), "%s comes before any decision record", n)
	}
}
