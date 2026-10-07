package httparchive_test

import (
	"encoding/hex"
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/httparchive"
)

func markerPath(w *world, name string) string {
	return "/rejection/" + hex.EncodeToString(w.hash[:]) + "/" + name
}

func TestStateAuthorized(t *testing.T) {
	w := newWorld(t, fullSet...)
	c, srv := w.client(t, nil)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAuthorized, st.State)

	got := srv.paths()
	assert.Contains(t, got, "GET /"+w.fx.Cases["decision_minimal_lmt"].Key)
	assert.Contains(t, got, "GET /"+w.fx.Cases["authorization_minimal_lmt_da"].Key)
}

func TestStateAbsent(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt")
	c, _ := w.client(t, nil)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateAbsent, st.State)
	assert.Empty(t, st.Rejections)
}

func TestStatePendingProbesEveryMarkerOnce(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt")
	c, srv := w.client(t, nil)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StatePending, st.State)
	assert.Empty(t, st.Rejections)

	want := []string{
		"GET /" + w.fx.Cases["decision_minimal_lmt"].Key,
		"GET /authorization/" + hex.EncodeToString(w.hash[:]),
	}
	for _, v := range verdicts {
		want = append(want, "GET "+markerPath(w, v))
	}
	got := srv.paths()
	sort.Strings(got)
	sort.Strings(want)
	assert.Equal(t, want, got, "the decision, the Authorization and one read per verdict name, and nothing else")
	assert.Len(t, verdicts, 13)
}

func TestStateRejected(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt",
		"rejection_minimal_lmt_not_yet_valid", "rejection_minimal_lmt_payload_unavailable")
	c, _ := w.client(t, nil)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StateRejected, st.State)
	assert.ElementsMatch(t, []string{"ErrNotYetValid", "ErrPayloadUnavailable"}, st.Rejections)

	local, err := w.store.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, local, st, "the derivation equals the local one")
}

func TestStateHiddenAuthorizationIsPendingNeverAuthorized(t *testing.T) {
	w := newWorld(t, fullSet...)
	hide := override(map[string]func(http.ResponseWriter){
		"/" + w.fx.Cases["authorization_minimal_lmt_da"].Key: status(http.StatusNotFound),
	})
	c, _ := w.client(t, hide)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StatePending, st.State)
}

func TestStateHiddenMarkerTurnsRejectedIntoPending(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt",
		"rejection_minimal_lmt_not_yet_valid")
	hide := override(map[string]func(http.ResponseWriter){markerPath(w, "ErrNotYetValid"): status(http.StatusGone)})
	c, _ := w.client(t, hide)
	st, err := c.State(bg, w.hash)
	require.NoError(t, err)
	assert.Equal(t, archive.StatePending, st.State, "the archive is trusted for availability only: withholding is possible, forging is not")
}

func TestStateNeedsEveryReadToAnswer(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt")
	faultPaths := map[string]string{
		"decision":      "/" + w.fx.Cases["decision_minimal_lmt"].Key,
		"authorization": "/authorization/" + hex.EncodeToString(w.hash[:]),
	}
	for _, v := range verdicts {
		faultPaths["marker "+v] = markerPath(w, v)
	}
	for name, p := range faultPaths {
		for _, code := range []int{http.StatusServiceUnavailable, http.StatusForbidden, http.StatusTooManyRequests, http.StatusFound} {
			t.Run(name+"/"+http.StatusText(code), func(t *testing.T) {
				c, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: status(code)}))
				st, err := c.State(bg, w.hash)
				require.ErrorIs(t, err, httparchive.ErrFault)
				assert.NotErrorIs(t, err, archive.ErrNotFound)
				assert.Equal(t, archive.DecisionState{}, st, "no state is reported when a read faulted")
			})
		}
	}
}

func TestStateCorruptAuthorizationIsCorruptNotPending(t *testing.T) {
	w := newWorld(t, "payload_da2_minimal_lmt", "evidence_da2_minimal_lmt", "decision_minimal_lmt")
	p := "/authorization/" + hex.EncodeToString(w.hash[:])
	c, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: body([]byte("garbage"))}))
	_, err := c.State(bg, w.hash)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, archive.ErrNotFound)
}

func TestStateCorruptDecisionIsCorrupt(t *testing.T) {
	w := newWorld(t, fullSet...)
	p := "/" + w.fx.Cases["decision_minimal_lmt"].Key
	c, _ := w.client(t, override(map[string]func(http.ResponseWriter){p: body([]byte("garbage"))}))
	_, err := c.State(bg, w.hash)
	require.ErrorIs(t, err, archive.ErrCorrupt)
}
