package httparchive_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/commitment"
)

// reads names every record read of the client and what it is asked under.
type read struct {
	name string
	key  string
	cap  int
	call func(c *httparchive.Client) error
}

func readsOf(t *testing.T, w *world) []read {
	t.Helper()
	pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	ev := w.fx.Cases["evidence_da2_minimal_lmt"].Record.(*archive.EvidenceRecord)
	return []read{
		{"payload", w.fx.Cases["payload_da2_minimal_lmt"].Key, 1<<27 + 4096, func(c *httparchive.Client) error {
			_, err := c.Payload(bg, pay.DA, pay.Commitment)
			return err
		}},
		{"evidence", w.fx.Cases["evidence_da2_minimal_lmt"].Key, 1 << 25, func(c *httparchive.Client) error {
			_, err := c.Evidence(bg, ev.DA, ev.Commitment)
			return err
		}},
		{"decision", w.fx.Cases["decision_minimal_lmt"].Key, 69632, func(c *httparchive.Client) error {
			_, err := c.Decision(bg, w.hash)
			return err
		}},
		{"authorization", w.fx.Cases["authorization_minimal_lmt_da"].Key, 512, func(c *httparchive.Client) error {
			_, err := c.Authorization(bg, w.hash)
			return err
		}},
	}
}

func TestNewClientChecksTheBaseURL(t *testing.T) {
	for _, base := range []string{
		"http://127.0.0.1:8080", "https://archive.example", "https://archive.example/", "https://archive.example///",
		"http://archive.example:9000/records/v0",
	} {
		_, err := httparchive.NewClient(base, nil)
		assert.NoError(t, err, base)
	}
	for _, base := range []string{
		"", "archive.example", "ftp://archive.example", "file:///tmp/archive", "ws://archive.example",
		"http://user@archive.example", "http://user:pw@archive.example", "http://archive.example?x=1",
		"http://archive.example/?", "http://archive.example#frag", "http:///path", "http://", "://x", "\x00",
	} {
		_, err := httparchive.NewClient(base, nil)
		assert.Error(t, err, "%q", base)
	}
}

func TestClientAsksForTheCanonicalPath(t *testing.T) {
	w := newWorld(t, fullSet...)
	h := w.handler()
	srv := serve(t, h)
	c, err := httparchive.NewClient(srv.URL+"/records/v0///", srv.Client())
	require.NoError(t, err)

	pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	_, err = c.Decision(bg, w.hash)
	assert.ErrorIs(t, err, archive.ErrNotFound, "the handler is mounted at the root, so the prefixed path is absent")
	_, err = c.Payload(bg, pay.DA, pay.Commitment)
	assert.ErrorIs(t, err, archive.ErrNotFound)

	got := srv.paths()
	require.Len(t, got, 2)
	assert.Equal(t, "GET /records/v0/"+w.fx.Cases["decision_minimal_lmt"].Key, got[0])
	assert.Equal(t, "GET /records/v0/"+w.fx.Cases["payload_da2_minimal_lmt"].Key, got[1])
}

func TestClientRoundTripOverTheHandler(t *testing.T) {
	w := newWorld(t, fullSet...)
	c, _ := w.client(t, nil)
	ro := w.store

	pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	wantP, err := ro.Payload(bg, pay.DA, pay.Commitment)
	require.NoError(t, err)
	gotP, err := c.Payload(bg, pay.DA, pay.Commitment)
	require.NoError(t, err)
	assert.Equal(t, wantP, gotP)

	ev := w.fx.Cases["evidence_da2_minimal_lmt"].Record.(*archive.EvidenceRecord)
	wantE, err := ro.Evidence(bg, ev.DA, ev.Commitment)
	require.NoError(t, err)
	gotE, err := c.Evidence(bg, ev.DA, ev.Commitment)
	require.NoError(t, err)
	assert.Equal(t, wantE, gotE)

	wantD, err := ro.Decision(bg, w.hash)
	require.NoError(t, err)
	gotD, err := c.Decision(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, wantD, gotD)

	wantA, err := ro.Authorization(bg, w.hash)
	require.NoError(t, err)
	gotA, err := c.Authorization(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, wantA, gotA)
}

func TestClientStreamsThePayloadRecord(t *testing.T) {
	w := newWorld(t, fullSet...)
	c, _ := w.client(t, nil)
	pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)

	rc, err := c.PayloadReader(bg, pay.DA, pay.Commitment)
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	want, err := archive.Encode(pay)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	_, err = c.PayloadReader(bg, commitment.DAFibre, make([]byte, 32))
	assert.ErrorIs(t, err, archive.ErrNotFound)
}

func TestClientIgnoresContentType(t *testing.T) {
	w := newWorld(t, fullSet...)
	for _, ct := range []string{"text/html", "application/json", ""} {
		c, _ := w.client(t, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(&typeRewriter{ResponseWriter: rw, ct: ct}, r)
			})
		})
		_, err := c.Decision(bg, w.hash)
		assert.NoError(t, err, "content type %q", ct)
	}
}

type typeRewriter struct {
	http.ResponseWriter
	ct string
}

func (t *typeRewriter) WriteHeader(code int) {
	if t.ct == "" {
		t.Header().Del("Content-Type")
		t.Header()["Content-Type"] = nil
	} else {
		t.Header().Set("Content-Type", t.ct)
	}
	t.ResponseWriter.WriteHeader(code)
}

func (t *typeRewriter) Write(b []byte) (int, error) {
	t.WriteHeader(http.StatusOK)
	return t.ResponseWriter.Write(b)
}

func TestClientStatusMapping(t *testing.T) {
	w := newWorld(t, fullSet...)
	statuses := []struct {
		code   int
		absent bool
	}{
		{http.StatusNotFound, true}, {http.StatusGone, true},
		{http.StatusBadRequest, false}, {http.StatusUnauthorized, false}, {http.StatusForbidden, false},
		{http.StatusMethodNotAllowed, false}, {http.StatusRequestTimeout, false}, {http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false}, {http.StatusBadGateway, false}, {http.StatusServiceUnavailable, false},
		{http.StatusGatewayTimeout, false}, {http.StatusNoContent, false}, {http.StatusPartialContent, false},
		{http.StatusNotModified, false}, {http.StatusMovedPermanently, false}, {http.StatusFound, false},
		{http.StatusTemporaryRedirect, false}, {http.StatusPermanentRedirect, false},
	}
	for _, r := range readsOf(t, w) {
		for _, st := range statuses {
			t.Run(r.name+"/"+http.StatusText(st.code), func(t *testing.T) {
				c, _ := w.client(t, override(map[string]func(http.ResponseWriter){"/" + r.key: status(st.code)}))
				err := r.call(c)
				require.Error(t, err)
				if st.absent {
					assert.ErrorIs(t, err, archive.ErrNotFound)
					assert.NotErrorIs(t, err, httparchive.ErrFault)
					return
				}
				assert.ErrorIs(t, err, httparchive.ErrFault)
				assert.NotErrorIs(t, err, archive.ErrNotFound, "a fault is never absent")
				assert.NotErrorIs(t, err, archive.ErrCorrupt)
			})
		}
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	w := newWorld(t, fullSet...)
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.handler().ServeHTTP(rw, r)
	}))
	t.Cleanup(target.Close)
	redirector := serve(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, target.URL+r.URL.Path, http.StatusFound)
	}))

	for _, hc := range []*http.Client{nil, {}, redirector.Client()} {
		c, err := httparchive.NewClient(redirector.URL, hc)
		require.NoError(t, err)
		_, err = c.Decision(bg, w.hash)
		require.ErrorIs(t, err, httparchive.ErrFault)
		assert.NotErrorIs(t, err, archive.ErrNotFound)
	}
	assert.Zero(t, hits.Load(), "the redirect target is never asked")
}

func TestClientTransportFaults(t *testing.T) {
	w := newWorld(t, fullSet...)
	dec := "/" + w.fx.Cases["decision_minimal_lmt"].Key

	t.Run("server is down", func(t *testing.T) {
		srv := serve(t, w.handler())
		c, err := httparchive.NewClient(srv.URL, srv.Client())
		require.NoError(t, err)
		srv.Close()
		_, err = c.Decision(bg, w.hash)
		require.ErrorIs(t, err, httparchive.ErrFault)
		assert.NotErrorIs(t, err, archive.ErrNotFound)
	})
	t.Run("body cut short", func(t *testing.T) {
		c, _ := w.client(t, override(map[string]func(http.ResponseWriter){dec: func(rw http.ResponseWriter) {
			rw.Header().Set("Content-Length", "1000")
			_, _ = rw.Write([]byte("short"))
		}}))
		_, err := c.Decision(bg, w.hash)
		require.ErrorIs(t, err, httparchive.ErrFault)
		assert.NotErrorIs(t, err, archive.ErrCorrupt, "a cut body is a fault, not a damaged record")
		assert.NotErrorIs(t, err, archive.ErrNotFound)
	})
	t.Run("cancelled context", func(t *testing.T) {
		c, _ := w.client(t, nil)
		ctx, cancel := context.WithCancel(bg)
		cancel()
		_, err := c.Decision(ctx, w.hash)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, archive.ErrNotFound)
	})
}

func TestClientSizeCapsPerKind(t *testing.T) {
	w := newWorld(t, fullSet...)
	for _, r := range readsOf(t, w) {
		t.Run(r.name, func(t *testing.T) {
			if r.cap > 1<<26 && testing.Short() {
				t.Skip("streams more than 128 MiB")
			}
			p := "/" + r.key
			over, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: zeros(int64(r.cap) + 1)}))
			err := r.call(over)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			assert.ErrorIs(t, err, httparchive.ErrTooLarge)
			assert.NotErrorIs(t, err, archive.ErrNotFound)

			at, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: zeros(int64(r.cap))}))
			err = r.call(at)
			require.ErrorIs(t, err, archive.ErrCorrupt, "a body at the cap is read, then fails strict decoding")
			assert.NotErrorIs(t, err, httparchive.ErrTooLarge)
		})
	}
}

func TestClientSizeCapOfAMarker(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt")
	marker := "/rejection/" + hex.EncodeToString(w.hash[:]) + "/ErrNonceUsed"

	over, _ := w.client(t, override(map[string]func(http.ResponseWriter){marker: zeros(257)}))
	_, err := over.State(bg, w.hash)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.ErrorIs(t, err, httparchive.ErrTooLarge)

	at, _ := w.client(t, override(map[string]func(http.ResponseWriter){marker: zeros(256)}))
	_, err = at.State(bg, w.hash)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, httparchive.ErrTooLarge)
}

func TestClientDecodesStrictlyAndChecksTheKey(t *testing.T) {
	w := newWorld(t, fullSet...)
	enc := func(id string) []byte {
		b, err := archive.Encode(w.fx.Cases[id].Record)
		require.NoError(t, err)
		return b
	}
	valid := enc("decision_minimal_lmt")
	otherDecision := enc("decision_fibre_small_payload")
	tests := []struct {
		name string
		body []byte
	}{
		{"garbage", []byte("not cbor at all")},
		{"empty", nil},
		{"one byte", []byte{0xa0}},
		{"truncated", valid[:len(valid)-1]},
		{"trailing byte", append(append([]byte(nil), valid...), 0)},
		{"another decision under this key", otherDecision},
		{"an evidence record under a decision key", enc("evidence_da2_minimal_lmt")},
		{"a payload record under a decision key", enc("payload_da2_minimal_lmt")},
		{"an authorization under a decision key", enc("authorization_minimal_lmt_da")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := "/" + w.fx.Cases["decision_minimal_lmt"].Key
			c, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: body(tc.body)}))
			_, err := c.Decision(bg, w.hash)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			assert.NotErrorIs(t, err, archive.ErrNotFound)
			assert.NotErrorIs(t, err, httparchive.ErrFault)
		})
	}

	t.Run("every vector reject under every key", func(t *testing.T) {
		for _, rj := range w.fx.Rejects {
			for _, r := range readsOf(t, w) {
				c, _ := w.client(t, override(map[string]func(http.ResponseWriter){"/" + r.key: body(rj.CBOR)}))
				err := r.call(c)
				assert.ErrorIs(t, err, archive.ErrCorrupt, "%s as %s", rj.ID, r.name)
			}
		}
	})
	t.Run("payload of another commitment", func(t *testing.T) {
		other := enc("payload_da2_256k")
		p := "/" + w.fx.Cases["payload_da2_minimal_lmt"].Key
		c, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: body(other)}))
		pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
		_, err := c.Payload(bg, pay.DA, pay.Commitment)
		assert.ErrorIs(t, err, archive.ErrCorrupt)
	})
}

func TestClientReturnsATamperedPayloadAndLeavesTheRecomputeToTheVerifier(t *testing.T) {
	fx := newWorld(t).fx
	dir := t.TempDir()
	permissive, err := openPermissive(dir)
	require.NoError(t, err)
	pay := *fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	pay.Blob = append([]byte(nil), pay.Blob...)
	pay.Blob[len(pay.Blob)-1] ^= 1
	_, err = permissive.Put(bg, &pay)
	require.NoError(t, err)

	srv := serve(t, httparchive.NewHandler(permissive))
	c, err := httparchive.NewClient(srv.URL, srv.Client())
	require.NoError(t, err)
	got, err := c.Payload(bg, pay.DA, pay.Commitment)
	require.NoError(t, err, "decoding and the key check pass; the DA commitment is the verifier's job")
	assert.Equal(t, pay.Blob, got.Blob)
	assert.NotEqual(t, fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord).Blob, got.Blob)
}

func TestClientIsSafeForConcurrentReaders(t *testing.T) {
	w := newWorld(t, fullSet...)
	c, _ := w.client(t, nil)
	pay := w.fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)

	const n = 8
	errs := make(chan error, 4*n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Decision(bg, w.hash)
			errs <- err
			_, err = c.Payload(bg, pay.DA, pay.Commitment)
			errs <- err
			st, err := c.State(bg, w.hash)
			errs <- err
			if err == nil && st.State != archive.StateAuthorized {
				err = errors.New("state is not authorized")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}
