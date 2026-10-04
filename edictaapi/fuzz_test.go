package edictaapi_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
)

func seedRequests(f *testing.F) {
	pv := loadPubVectors(f)
	for _, c := range append(append([]pubCase{}, pv.Cases...), pv.Reject...) {
		if c.BlobPattern != "" {
			continue
		}
		f.Add(c.request(f))
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff})
}

func FuzzDecodePublishRequest(f *testing.F) {
	seedRequests(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := edictaapi.DecodePublishRequest(b, 1<<20)
		if err != nil {
			known := false
			for _, s := range sentinels {
				if errors.Is(err, s) {
					known = true
					break
				}
			}
			require.True(t, known, "decoder error is not a sentinel: %v", err)
			return
		}
		require.GreaterOrEqual(t, len(req.Blob), 1)
		require.LessOrEqual(t, len(req.Blob), 1<<20)
		require.GreaterOrEqual(t, len(req.AgentID), 1)
		require.LessOrEqual(t, len(req.AgentID), 64)
		require.Len(t, req.Signature, 64)
		require.GreaterOrEqual(t, req.RequestedAt, uint64(1))
		require.LessOrEqual(t, req.RequestedAt, uint64(1<<63-1))
		again, err := edictaapi.EncodePublishRequest(req)
		require.NoError(t, err)
		require.Equal(t, b, again, "accepted input is canonical")
	})
}

// FuzzPublishHandler: arbitrary bodies never panic, answer 500, and answer every non-200 with a well-formed error body.
func FuzzPublishHandler(f *testing.F) {
	seedRequests(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		e := newEnv(t, nil)
		e.pub.result, _ = testRef(t)
		rec := e.post("/v0/publish", b)
		require.NotEqual(t, http.StatusInternalServerError, rec.Code, "%x", b)
		if rec.Code != 200 {
			parseErr(t, rec.Body.Bytes())
		}
		if e.pub.count() > 0 {
			// only the genuine vector requests may pass; any acceptance must be of a well-formed signed request
			require.Equal(t, 200, rec.Code)
		}
	})
}
