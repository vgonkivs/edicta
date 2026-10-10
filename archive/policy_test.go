package archive_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

type policyArchiveDoc struct {
	Kinds map[string]struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Cap  string `json:"cap"`
	} `json:"kinds"`
	Reserved []string `json:"reserved_kinds"`
	Markers  []string `json:"marker_names"`
	Cases    []struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Path   string `json:"path"`
		KeyHex string `json:"key_hex"`
		Record string `json:"record_cbor_hex"`
	} `json:"cases"`
	Reject []struct {
		ID     string `json:"id"`
		Record string `json:"record_cbor_hex"`
		Err    string `json:"expect_error"`
		Cause  string `json:"cause"`
	} `json:"reject"`
}

func loadPolicyArchive(t testing.TB) policyArchiveDoc {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/policy/archive.json")
	require.NoError(t, err)
	var d policyArchiveDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	return d
}

func TestPolicyArchiveCases(t *testing.T) {
	d := loadPolicyArchive(t)
	require.NotEmpty(t, d.Cases)
	for _, c := range d.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b, err := hex.DecodeString(c.Record)
			require.NoError(t, err)
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			k, err := strconv.ParseUint(c.Kind, 10, 64)
			require.NoError(t, err)
			assert.Equal(t, archive.Kind(k), rec.Kind())
			assert.Equal(t, d.Kinds[c.Kind].Name, rec.Kind().String())
			path, err := archive.KeyPath(rec)
			require.NoError(t, err)
			assert.Equal(t, c.Path, path)
			assert.True(t, strings.HasSuffix(path, c.KeyHex) || strings.Contains(path, c.KeyHex))
			pk, err := archive.ParseKey(path)
			require.NoError(t, err)
			assert.Equal(t, rec.Kind(), pk)
			again, err := archive.Encode(rec)
			require.NoError(t, err)
			assert.Equal(t, b, again)
			assert.True(t, archive.SameIdentity(rec, rec))
		})
	}
}

func TestPolicyArchiveReject(t *testing.T) {
	d := loadPolicyArchive(t)
	require.NotEmpty(t, d.Reject)
	causes := map[string]error{
		"ErrInvalidEnum": commitment.ErrInvalidEnum, "ErrUnknownKey": commitment.ErrUnknownKey,
		"ErrWrongType": commitment.ErrWrongType, "ErrMandateInvalid": policy.ErrMandateInvalid,
		"ErrStateInvalid": policy.ErrStateInvalid, "ErrUnsupportedVersion": commitment.ErrUnsupportedVersion,
		"ErrInvalidString": commitment.ErrInvalidString, "ErrFieldSize": commitment.ErrFieldSize,
		"ErrMissingField": commitment.ErrMissingField, "ErrTrailingData": commitment.ErrTrailingData,
	}
	for _, c := range d.Reject {
		t.Run(c.ID, func(t *testing.T) {
			b, err := hex.DecodeString(c.Record)
			require.NoError(t, err)
			_, err = archive.Decode(b)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			cause, ok := causes[c.Cause]
			require.True(t, ok, c.Cause)
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestPolicyMarkerNamesAndKeys(t *testing.T) {
	d := loadPolicyArchive(t)
	assert.Len(t, archive.Verdicts(), 33)
	for _, n := range d.Markers {
		assert.True(t, archive.IsVerdict(n), n)
		assert.True(t, archive.IsPolicyDeny(n), n)
	}
	assert.False(t, archive.IsPolicyDeny("ErrNonceUsed"))
	h := strings.Repeat("ab", 32)
	for _, ok := range []string{"mandate/" + h, "policy-allow/" + h, "policy-deny/" + h + "/ErrPeriodLimit",
		"policy-bucket/" + h, "policy-closed/" + h, "policy-successor/" + h} {
		_, err := archive.ParseKey(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"mandate/" + h + "/x", "policy-deny/" + h, "policy-deny/" + h + "/ErrNonceUsed",
		"policy-allow/" + strings.ToUpper(h), "policy-closed/abc"} {
		_, err := archive.ParseKey(bad)
		assert.Error(t, err, bad)
	}
}
