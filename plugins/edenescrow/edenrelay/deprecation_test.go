// SPDX-License-Identifier: Apache-2.0

package edenrelay_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrelay"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestDeprecated(t *testing.T) {
	header := http.Header{}
	header.Set("Deprecation", "true")
	assert.True(t, edenrelay.Deprecated(header, nil), "the header")
	for body, want := range map[string]bool{
		`{"deprecation":true}`:                     true,
		`{"txHash":"0x12", "deprecation" : true }`: true,
		`{"deprecation":"true"}`:                   false,
		`{"deprecation":false}`:                    false,
		`{"result":{"deprecation":true}}`:          false,
		`deprecation: true`:                        false,
		``:                                         false,
	} {
		assert.Equal(t, want, edenrelay.Deprecated(http.Header{}, []byte(body)), body)
	}
}

func TestHoustonRelayLogsTheDeprecationMarkerOncePerProcess(t *testing.T) {
	signed := []byte{0x02, 0xc0, 0x01}
	railRef := edenescrow.RailRef(signed)
	var mu sync.Mutex
	answer := func(w http.ResponseWriter) {}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		answer(w)
	}))
	defer srv.Close()
	set := func(f func(w http.ResponseWriter)) {
		mu.Lock()
		defer mu.Unlock()
		answer = f
	}
	var logs syncBuffer
	rl, err := edenrelay.NewHoustonRelay(edenrelay.HoustonConfig{BaseURL: srv.URL, Timeout: time.Second}, srv.Client(),
		slog.New(slog.NewTextHandler(&logs, nil)))
	require.NoError(t, err)
	send := func() error { return rl.Send(context.Background(), signed, railRef, [32]byte{0xab}) }

	edenrelay.ResetDeprecationLog()
	set(func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"txHash":"0x`+railRef+`"}`) })
	require.NoError(t, send())
	assert.NotContains(t, logs.String(), "deprecated", "no marker, no line")

	set(func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"deprecation":true,"txHash":"0x`+railRef+`"}`) })
	require.NoError(t, send(), "the marker changes nothing else")
	set(func(w http.ResponseWriter) {
		w.Header().Set("Deprecation", "true")
		_, _ = io.WriteString(w, `{"txHash":"0x`+railRef+`"}`)
	})
	require.NoError(t, send(), "the header alone is the marker, the body carries none")
	assert.Equal(t, 1, strings.Count(logs.String(), "marks its relay deprecated"), logs.String())
	set(func(w http.ResponseWriter) {
		w.Header().Set("Deprecation", "true")
		http.Error(w, "failed to broadcast transaction", http.StatusBadRequest)
	})
	require.ErrorIs(t, send(), edenrelay.ErrRelayFault, "an error with the marker is still a fault")
	set(func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"deprecation":true}`) })
	require.NoError(t, send())
	assert.Equal(t, 1, strings.Count(logs.String(), "marks its relay deprecated"), logs.String())
}
