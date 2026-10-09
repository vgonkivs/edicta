package httparchive_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

type fakeSource struct {
	mu     sync.Mutex
	recs   map[string][]byte
	err    error
	calls  []string
	closed int
}

func (f *fakeSource) Raw(_ context.Context, key string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.recs[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, key)
	}
	return &closeCounter{Reader: strings.NewReader(string(b)), f: f}, nil
}

type closeCounter struct {
	io.Reader
	f *fakeSource
}

func (c *closeCounter) Close() error {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	c.f.closed++
	return nil
}

func sourceOfVectors(t *testing.T) (*fakeSource, *archivefix.Fixture) {
	t.Helper()
	fx := archivefix.Load(t)
	f := &fakeSource{recs: map[string][]byte{}}
	for id, c := range fx.Cases {
		b, err := archive.Encode(c.Record)
		require.NoError(t, err, id)
		f.recs[c.Key] = b
	}
	return f, fx
}

func do(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestHandlerServesEveryRecordVerbatim(t *testing.T) {
	src, fx := sourceOfVectors(t)
	h := httparchive.NewHandler(src)
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			rec := do(h, http.MethodGet, "/"+c.Key)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, src.recs[c.Key], rec.Body.Bytes())
			assert.Equal(t, "application/cbor", rec.Header().Get("Content-Type"))

			head := do(h, http.MethodHead, "/"+c.Key)
			assert.Equal(t, http.StatusOK, head.Code)
			assert.Empty(t, head.Body.Bytes())
		})
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	assert.Equal(t, len(src.calls), src.closed, "every opened record is closed")
}

func TestHandlerAnswersGetAndHeadOnly(t *testing.T) {
	src, fx := sourceOfVectors(t)
	h := httparchive.NewHandler(src)
	key := "/" + fx.Cases["decision_minimal_lmt"].Key
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodTrace, "PROPFIND",
	} {
		rec := do(h, m, key)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, m)
	}
	assert.Empty(t, src.calls, "a refused method never reaches the store")
}

func TestHandlerServesOnlyCanonicalKeys(t *testing.T) {
	src, fx := sourceOfVectors(t)
	h := httparchive.NewHandler(src)
	dec := fx.Cases["decision_minimal_lmt"].Key
	hexpart := strings.TrimPrefix(dec, "decision/")
	rej := fx.Cases["rejection_minimal_lmt_not_yet_valid"].Key

	paths := []string{
		"/",
		"/decision",
		"/decision/",
		"/payload/",
		"/payload/2/",
		"/rejection/" + hexpart + "/",
		"/rejection/" + hexpart,
		"/" + dec + "/",
		"//" + dec,
		"/decision//" + hexpart,
		"/decision/../" + dec,
		"/decision/./" + hexpart,
		"/../" + dec,
		"/decision/" + strings.ToUpper(hexpart),
		"/decision/." + hexpart[1:],
		"/.tmp-" + hexpart,
		"/decision/.tmp-" + hexpart,
		"/.hidden",
		"/.git/config",
		"/secret/" + hexpart,
		"/payload/02/" + hexpart,
		"/payload/3/" + hexpart,
		"/authorization/2/" + hexpart,
		"/" + strings.Replace(rej, "ErrNotYetValid", "errnotyetvalid", 1),
		"/" + strings.Replace(rej, "ErrNotYetValid", "ErrNothing", 1),
		"/" + dec + "/x",
	}
	for _, p := range paths {
		rec := do(h, http.MethodGet, p)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%q", p)
		assert.Contains(t, rec.Header().Get("Cache-Control"), "no-store", "%q", p)
	}
	assert.Empty(t, src.calls, "a path that is not a canonical key never reaches the store")
}

func TestHandlerNeverLetsAnAbsentRecordBeCached(t *testing.T) {
	src, fx := sourceOfVectors(t)
	h := httparchive.NewHandler(src)
	absent := strings.Replace(fx.Cases["decision_minimal_lmt"].Key, "2024a4", "2024a5", 1)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := do(h, m, "/"+absent)
		require.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Cache-Control"), "no-store")
	}
}

func TestHandlerReportsAStoreFaultAsAFaultNotAsAbsent(t *testing.T) {
	src, fx := sourceOfVectors(t)
	src.err = errors.New("disk on fire")
	h := httparchive.NewHandler(src)
	rec := do(h, http.MethodGet, "/"+fx.Cases["decision_minimal_lmt"].Key)
	assert.GreaterOrEqual(t, rec.Code, 500)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
	assert.NotEqual(t, http.StatusGone, rec.Code)
	assert.NotContains(t, rec.Body.String(), "disk on fire", "no internal detail leaks")
}

func TestHandlerMapsWrappedNotFoundToNotFound(t *testing.T) {
	src, fx := sourceOfVectors(t)
	src.err = fmt.Errorf("fsarchive: %w", archive.ErrNotFound)
	rec := do(httparchive.NewHandler(src), http.MethodGet, "/"+fx.Cases["decision_minimal_lmt"].Key)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandlerOverFsarchiveServesWhatIsStoredAndNothingElse(t *testing.T) {
	w := newWorld(t, fullSet...)
	h := w.handler()
	c := w.fx.Cases["decision_minimal_lmt"]

	rec := do(h, http.MethodGet, "/"+c.Key)
	require.Equal(t, http.StatusOK, rec.Code)
	want, err := archive.Encode(c.Record)
	require.NoError(t, err)
	assert.Equal(t, want, rec.Body.Bytes())

	for _, k := range []string{
		w.fx.Cases["decision_fibre_small_payload"].Key,
		w.fx.Cases["rejection_minimal_lmt_not_yet_valid"].Key,
		w.fx.Cases["payload_da1_live"].Key,
	} {
		assert.Equal(t, http.StatusNotFound, do(h, http.MethodGet, "/"+k).Code, k)
	}
}
