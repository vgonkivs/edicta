package verifier_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/verifier"
)

// overHTTP serves the rig's archive through the real handler, lets hide
// replace answers by path, and points the verifier at the client.
func (r *rig) overHTTP(t *testing.T, hide map[string]int) {
	t.Helper()
	h := httparchive.NewHandler(r.store)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if code, ok := hide[req.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		h.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	c, err := httparchive.NewClient(srv.URL, srv.Client())
	require.NoError(t, err)
	r.deps.Archive = c
}

func pathOf(t *testing.T, rec archive.Record) string {
	t.Helper()
	k, err := archive.KeyPath(rec)
	require.NoError(t, err)
	return "/" + k
}

func (r *rig) paths(t *testing.T) (decision, authorization, payload, evidence string) {
	t.Helper()
	d := "/decision/" + hex.EncodeToString(r.p.hash[:])
	a := "/authorization/" + hex.EncodeToString(r.p.hash[:])
	pay := pathOf(t, &archive.PayloadRecord{DA: r.p.da, Commitment: r.p.payloadRef})
	ev := pathOf(t, &archive.EvidenceRecord{DA: r.p.da, Commitment: r.p.payloadRef})
	return d, a, pay, ev
}

func TestVerifyOverHTTPEqualsVerifyOverTheDirectory(t *testing.T) {
	r := newRig(t, newParts(t))
	local := r.verify(t)
	require.Equal(t, verifier.VerdictValid, local.Verdict)

	r.overHTTP(t, nil)
	remote := r.verify(t)
	assert.Equal(t, local, remote)
}

func TestVerifyOverHTTPWithholdingNeverGivesValid(t *testing.T) {
	d, a, pay, ev := newRig(t, newParts(t)).paths(t)
	tests := []struct {
		name    string
		hide    string
		verdict verifier.Verdict
		check   verifier.CheckName
		sent    error
	}{
		{"decision", d, verifier.VerdictInvalid, verifier.CheckDecision, verifier.ErrDecisionNotFound},
		{"payload", pay, verifier.VerdictInvalid, verifier.CheckPayload, verifier.ErrArchiveIncomplete},
		{"evidence", ev, verifier.VerdictInvalid, verifier.CheckAnchor, verifier.ErrArchiveIncomplete},
	}
	for _, tc := range tests {
		for _, code := range []int{http.StatusNotFound, http.StatusGone} {
			t.Run(tc.name+"/"+http.StatusText(code), func(t *testing.T) {
				r := newRig(t, newParts(t))
				r.overHTTP(t, map[string]int{tc.hide: code})
				rep := r.verify(t)
				c := failed(t, rep, tc.check)
				assert.ErrorIs(t, c.Err, tc.sent)
				assert.Equal(t, tc.verdict, rep.Verdict)
			})
		}
	}
	t.Run("authorization", func(t *testing.T) {
		r := newRig(t, newParts(t))
		r.overHTTP(t, map[string]int{a: http.StatusNotFound})
		rep := r.verify(t)
		assert.Equal(t, archive.StatePending, rep.State)
		assert.Equal(t, verifier.VerdictNotAuthorized, rep.Verdict)
		assert.False(t, rep.AuthorizationVerified)
	})
}

func TestVerifyOverHTTPAFaultGivesNoVerdict(t *testing.T) {
	d, a, pay, ev := newRig(t, newParts(t)).paths(t)
	for name, p := range map[string]string{"decision": d, "authorization": a, "payload": pay, "evidence": ev} {
		for _, code := range []int{http.StatusServiceUnavailable, http.StatusForbidden, http.StatusTooManyRequests} {
			t.Run(name+"/"+http.StatusText(code), func(t *testing.T) {
				r := newRig(t, newParts(t))
				r.overHTTP(t, map[string]int{p: code})
				rep, err := r.verifier(t).Verify(context.Background(), r.p.hash)
				require.Error(t, err)
				assert.ErrorIs(t, err, httparchive.ErrFault)
				assert.Equal(t, verifier.Report{}, rep, "a fault is not a finding")
			})
		}
	}
	t.Run("a marker read of a pending decision", func(t *testing.T) {
		p := newParts(t)
		p.auth = nil
		r := newRig(t, p)
		r.overHTTP(t, map[string]int{"/rejection/" + hex.EncodeToString(p.hash[:]) + "/ErrExpired": http.StatusServiceUnavailable})
		_, err := r.verifier(t).Verify(context.Background(), p.hash)
		require.ErrorIs(t, err, httparchive.ErrFault)
	})
}

func TestVerifyOverHTTPHiddenMarkerIsPendingNotRejected(t *testing.T) {
	p := newParts(t)
	p.auth = nil
	p.markers = []string{"ErrExpired"}
	r := newRig(t, p)

	r.overHTTP(t, nil)
	rep := r.verify(t)
	assert.Equal(t, archive.StateRejected, rep.State)
	assert.Equal(t, []string{"ErrExpired"}, rep.Rejections)

	r.overHTTP(t, map[string]int{"/rejection/" + hex.EncodeToString(p.hash[:]) + "/ErrExpired": http.StatusNotFound})
	rep = r.verify(t)
	assert.Equal(t, archive.StatePending, rep.State)
	assert.Equal(t, verifier.VerdictNotAuthorized, rep.Verdict)
}

func TestVerifyOverHTTPTamperedPayloadFailsThePayloadCheck(t *testing.T) {
	p := newParts(t)
	p.permissive = true
	p.blob = append([]byte(nil), p.blob...)
	p.blob[len(p.blob)-1] ^= 1
	r := newRig(t, p)
	r.overHTTP(t, nil)

	rep := r.verify(t)
	c := failed(t, rep, verifier.CheckPayload)
	requireOnly(t, c.Err, verifier.ErrPayloadInvalid)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
}
