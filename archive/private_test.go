package archive_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// The reads of the policy archive vectors: a reader recomputes the deny
// segment from the verdict (private iff key 19 is present), so a record
// under the other form's path is corrupt.
func TestPolicyArchiveReads(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/policy/archive.json")
	require.NoError(t, err)
	var d struct {
		Reads []struct {
			ID     string  `json:"id"`
			Path   string  `json:"path"`
			Record string  `json:"record_cbor_hex"`
			Expect *string `json:"expect_error"`
		} `json:"reads"`
		PrivateOnly []string `json:"marker_names_private_only"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Len(t, d.Reads, 3)
	for _, r := range d.Reads {
		t.Run(r.ID, func(t *testing.T) {
			_, err := archive.ParseKey(r.Path)
			require.NoError(t, err, "the path itself is canonical")
			b, err := hex.DecodeString(r.Record)
			require.NoError(t, err)
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			p, err := archive.KeyPath(rec)
			require.NoError(t, err)
			if r.Expect == nil {
				assert.Equal(t, r.Path, p)
				return
			}
			assert.Equal(t, "archive.ErrCorrupt", *r.Expect)
			assert.NotEqual(t, r.Path, p, "a reader reports the record under this path corrupt")
		})
	}
	assert.Equal(t, []string{"ErrDenied"}, d.PrivateOnly)
	assert.True(t, archive.IsVerdict("ErrDenied"))
}

func TestPrivateKeys(t *testing.T) {
	h := commitment.Hash{0xab}
	seg := archive.PrivateDenySegment(h)
	assert.Equal(t, "private-ab"+strings.Repeat("00", 31), seg)
	p, err := archive.PolicyDenyPath(h, seg)
	require.NoError(t, err)
	k, err := archive.ParseKey(p)
	require.NoError(t, err)
	assert.Equal(t, archive.KindPolicyDeny, k)

	for kind := policy.PrivateMandate; kind <= policy.PrivateAction; kind++ {
		p, err := archive.PrivateBlobPath(kind, h)
		require.NoError(t, err)
		k, err := archive.ParseKey(p)
		require.NoError(t, err)
		assert.Equal(t, archive.KindPrivateBlob, k)
	}
	_, err = archive.PrivateBlobPath(6, h)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)
	hx := hex.EncodeToString(h[:])
	for _, bad := range []string{"private/0/" + hx, "private/6/" + hx, "private/1/" + strings.ToUpper(hx), "private/1",
		"policy-deny/" + hx + "/private-" + hx[:62], "policy-deny/" + hx + "/private" + hx, "policy-deny/" + hx + "/Private-" + hx} {
		_, err := archive.ParseKey(bad)
		assert.Error(t, err, bad)
	}
}

func TestPrivateBlobIdentityIsTheKey(t *testing.T) {
	a := &archive.PrivateBlobRecord{PlaintextKind: policy.PrivatePartKind, Hash: make([]byte, 32), Envelope: []byte{1}}
	b := &archive.PrivateBlobRecord{PlaintextKind: policy.PrivatePartKind, Hash: make([]byte, 32), Envelope: []byte{2}}
	c := &archive.PrivateBlobRecord{PlaintextKind: policy.PrivateBucket, Hash: make([]byte, 32), Envelope: []byte{1}}
	assert.True(t, archive.SameIdentity(a, b), "another envelope of one plaintext is the same record")
	assert.False(t, archive.SameIdentity(a, c))

	// The envelope cap depends on the plaintext kind.
	big := &archive.PrivateBlobRecord{PlaintextKind: policy.PrivateAction, Hash: make([]byte, 32), Envelope: make([]byte, policy.MaxPrivateActionEnvelope)}
	_, err := archive.Encode(big)
	require.NoError(t, err)
	big.PlaintextKind = policy.PrivatePartKind
	_, err = archive.Encode(big)
	require.ErrorIs(t, err, commitment.ErrFieldSize)
}
