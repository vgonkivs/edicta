package fsarchive_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/commitment"
)

func policyRecords(t *testing.T) map[string]archive.Record {
	t.Helper()
	raw, err := os.ReadFile("../../spec/vectors/policy/verify.json")
	require.NoError(t, err)
	var d struct {
		Records map[string]string `json:"records"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	out := map[string]archive.Record{}
	for p, h := range d.Records {
		b, err := hex.DecodeString(h)
		require.NoError(t, err)
		rec, err := archive.Decode(b)
		require.NoError(t, err)
		out[p] = rec
	}
	return out
}

func keyHash(t *testing.T, path string) commitment.Hash {
	t.Helper()
	var h commitment.Hash
	b, err := hex.DecodeString(path[strings.LastIndex(path, "/")+1:])
	if err != nil || len(b) != 32 {
		b, err = hex.DecodeString(strings.Split(path, "/")[1])
		require.NoError(t, err)
	}
	copy(h[:], b)
	return h
}

func TestPolicyRecordsWriteOnceAndPreconditions(t *testing.T) {
	recs := policyRecords(t)
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, nil)
	require.NoError(t, err)
	ctx := t.Context()

	var mandate, bucket, closed, allow, deny, succ string
	for p := range recs {
		switch {
		case strings.HasPrefix(p, "mandate/"):
			mandate = p
		case strings.HasPrefix(p, "policy-bucket/"):
			bucket = p
		case strings.HasPrefix(p, "policy-closed/"):
			closed = p
		case strings.HasPrefix(p, "policy-allow/"):
			allow = p
		case strings.HasPrefix(p, "policy-deny/"):
			deny = p
		case strings.HasPrefix(p, "policy-successor/"):
			succ = p
		}
	}

	for _, p := range []string{mandate, bucket, closed} {
		out, err := s.Put(ctx, recs[p])
		require.NoError(t, err, p)
		assert.Equal(t, archive.Written, out)
		out, err = s.Put(ctx, recs[p])
		require.NoError(t, err)
		assert.Equal(t, archive.Unchanged, out)
	}

	// The decision of the vector is not in this store.
	_, err = s.Put(ctx, recs[allow])
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Put(ctx, recs[deny])
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Put(ctx, recs[succ])
	require.ErrorIs(t, err, archive.ErrNotFound)

	m, err := s.Mandate(ctx, keyHash(t, mandate))
	require.NoError(t, err)
	assert.Equal(t, recs[mandate], archive.Record(m))
	_, err = s.PolicyBucket(ctx, keyHash(t, bucket))
	require.NoError(t, err)
	_, err = s.PolicyClosed(ctx, keyHash(t, closed))
	require.NoError(t, err)
	_, err = s.PolicyAllow(ctx, keyHash(t, allow))
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.PolicyDeny(ctx, keyHash(t, deny), "ErrNonceUsed")
	require.ErrorIs(t, err, archive.ErrNotFound)

	// The same records over HTTP.
	srv := httptest.NewServer(httparchive.NewHandler(s))
	defer srv.Close()
	c, err := httparchive.NewClient(srv.URL, nil)
	require.NoError(t, err)
	cm, err := c.Mandate(ctx, keyHash(t, mandate))
	require.NoError(t, err)
	assert.Equal(t, m, cm)
	_, err = c.PolicyBucket(ctx, keyHash(t, bucket))
	require.NoError(t, err)
	cl, err := c.PolicyClosed(ctx, keyHash(t, closed))
	require.NoError(t, err)
	assert.Equal(t, recs[closed], archive.Record(cl))
	_, err = c.PolicyAllow(ctx, keyHash(t, allow))
	require.ErrorIs(t, err, archive.ErrNotFound)

	// A corrupt file under a key is reported, never replaced.
	require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(mandate)), []byte{0xa0}, 0o644))
	_, err = s.Mandate(ctx, keyHash(t, mandate))
	require.ErrorIs(t, err, archive.ErrCorrupt)
}
