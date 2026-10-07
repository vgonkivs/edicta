package httparchive_test

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// FuzzClientBody feeds arbitrary bodies as the answer to a decision read. A
// body is either refused as corrupt or is the record of the key it was asked
// under.
func FuzzClientBody(f *testing.F) {
	fx := archivefix.Load(f)
	for _, c := range fx.Cases {
		b, err := archive.Encode(c.Record)
		require.NoError(f, err)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa0})

	d := fx.Cases["decision_minimal_lmt"].Record.(*archive.DecisionRecord)
	sc, err := commitment.DecodeSigned(d.Envelope)
	require.NoError(f, err)
	h, err := commitment.HashOf(&sc.Commitment)
	require.NoError(f, err)
	want := "decision/" + hex.EncodeToString(h[:])

	var mu sync.Mutex
	var current []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		b := current
		mu.Unlock()
		_, _ = w.Write(b)
	}))
	f.Cleanup(srv.Close)
	c, err := httparchive.NewClient(srv.URL, srv.Client())
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, body []byte) {
		mu.Lock()
		current = body
		mu.Unlock()
		got, err := c.Decision(bg, h)
		if err != nil {
			assert.ErrorIs(t, err, archive.ErrCorrupt)
			assert.NotErrorIs(t, err, archive.ErrNotFound)
			return
		}
		key, kerr := archive.KeyPath(got)
		require.NoError(t, kerr)
		assert.Equal(t, want, key)
	})
}
