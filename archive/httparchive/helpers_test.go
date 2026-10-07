package httparchive_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/archivefix"
)

var bg = context.Background()

// verdicts are the 13 marker names a state derivation must probe.
var verdicts = []string{
	"ErrActionMismatch", "ErrAnchorNotFound", "ErrAnchorTooOld", "ErrArchiveRecomputeUnsupported",
	"ErrDACommitmentMismatch", "ErrExpired", "ErrIssuedBeforeAnchor", "ErrNonceUsed", "ErrNotYetValid",
	"ErrPayloadHashMismatch", "ErrPayloadSizeMismatch", "ErrPayloadUnavailable", "ErrRetentionUnavailable",
}

type acceptAll struct{}

func (acceptAll) Check(commitment.PayloadRef, []byte) error { return nil }

func committers(fx *archivefix.Fixture) map[commitment.DA]gate.DACommitter {
	return map[commitment.DA]gate.DACommitter{
		commitment.DAFibre:        fx.FibreCommitter(),
		commitment.DACelestiaBlob: blobv1.New(),
	}
}

// world is an fsarchive with the records of the minimal_lmt decision, served
// over HTTP by the real handler.
type world struct {
	fx    *archivefix.Fixture
	dir   string
	store *fsarchive.Store
	hash  commitment.Hash
}

func put(t *testing.T, s *fsarchive.Store, fx *archivefix.Fixture, ids ...string) {
	t.Helper()
	for _, id := range ids {
		_, err := s.Put(bg, fx.Cases[id].Record)
		require.NoError(t, err, id)
	}
}

func newWorld(t *testing.T, ids ...string) *world {
	t.Helper()
	fx := archivefix.Load(t)
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, committers(fx))
	require.NoError(t, err)
	put(t, s, fx, ids...)
	d := fx.Cases["decision_minimal_lmt"].Record.(*archive.DecisionRecord)
	sc, err := commitment.DecodeSigned(d.Envelope)
	require.NoError(t, err)
	h, err := commitment.HashOf(&sc.Commitment)
	require.NoError(t, err)
	return &world{fx: fx, dir: dir, store: s, hash: h}
}

var fullSet = []string{
	"payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt", "authorization_minimal_lmt_da",
}

// server records every request.
type server struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []string
}

func (s *server) paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...)
}

func serve(t *testing.T, h http.Handler) *server {
	t.Helper()
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (w *world) handler() http.Handler {
	ro, err := fsarchive.OpenReadOnly(w.dir, committers(w.fx))
	if err != nil {
		panic(err)
	}
	return httparchive.NewHandler(ro)
}

func (w *world) client(t *testing.T, wrap func(http.Handler) http.Handler) (*httparchive.Client, *server) {
	t.Helper()
	h := w.handler()
	if wrap != nil {
		h = wrap(h)
	}
	srv := serve(t, h)
	c, err := httparchive.NewClient(srv.URL, srv.Client())
	require.NoError(t, err)
	return c, srv
}

// override answers the listed paths itself and passes the rest on.
func override(answers map[string]func(http.ResponseWriter)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f, ok := answers[r.URL.Path]; ok {
				f(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func body(b []byte) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = w.Write(b) }
}

// zeros streams n zero bytes.
func zeros(n int64) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = io.CopyN(w, zeroReader{}, n) }
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func path(t *testing.T, c archivefix.Case) string {
	t.Helper()
	return "/" + c.Key
}

func openPermissive(dir string) (*fsarchive.Store, error) {
	return fsarchive.Open(dir, map[commitment.DA]gate.DACommitter{
		commitment.DAFibre:        acceptAll{},
		commitment.DACelestiaBlob: acceptAll{},
	})
}
