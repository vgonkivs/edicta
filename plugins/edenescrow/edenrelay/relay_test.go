// SPDX-License-Identifier: Apache-2.0

package edenrelay_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrelay"
)

func TestHoustonRelayConfig(t *testing.T) {
	for _, u := range []string{"http://pay.example", "https://user@pay.example", "https://pay.example/?a=b", "https://", "pay.example"} {
		c := edenrelay.HoustonConfig{BaseURL: u}
		c.ApplyDefaults()
		assert.Error(t, c.ValidateBasic(), u)
	}
	c := edenrelay.HoustonConfig{BaseURL: "https://pay.example/base/", Timeout: 61 * time.Second}
	assert.Error(t, c.ValidateBasic())
	c.Timeout = 0
	c.ApplyDefaults()
	assert.Equal(t, edenrelay.DefaultServerTimeout, c.Timeout)
	require.NoError(t, c.ValidateBasic())
}

func TestHoustonRelay(t *testing.T) {
	signed := []byte{0x02, 0xc0, 0x01}
	railRef := edenescrow.RailRef(signed)
	pid := [32]byte{0xab}
	var mu sync.Mutex
	answer := func(w http.ResponseWriter) {}
	var got []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/base"+edenrelay.RelayPath || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		got = b
		answer(w)
	}))
	defer srv.Close()
	rl, err := edenrelay.NewHoustonRelay(edenrelay.HoustonConfig{BaseURL: srv.URL + "/base/", Timeout: 200 * time.Millisecond}, srv.Client(), nil)
	require.NoError(t, err)
	set := func(f func(w http.ResponseWriter)) {
		mu.Lock()
		defer mu.Unlock()
		answer = f
	}
	send := func() error { return rl.Send(context.Background(), signed, railRef, pid) }

	set(func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"txHash":"0x`+strings.ToUpper(railRef)+`"}`) })
	require.NoError(t, send())
	var body map[string]string
	require.NoError(t, json.Unmarshal(got, &body))
	assert.Equal(t, map[string]string{"signedTx": "0x" + hex.EncodeToString(signed), "paymentId": "0x" + hex.EncodeToString(pid[:])}, body)

	set(func(w http.ResponseWriter) {})
	require.NoError(t, send(), "an empty success")

	faults := map[string]func(w http.ResponseWriter){
		"error status": func(w http.ResponseWriter) { http.Error(w, "failed to broadcast transaction", http.StatusBadRequest) },
		"other hash": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"result":{"hash":"0x`+strings.Repeat("1", 64)+`"}}`)
		},
		"short hash":      func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"transactionHash":"0x12"}`) },
		"hash not string": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"tx":{"txHash":12}}`) },
		"error member":    func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"error":"failed to broadcast transaction"}`) },
		"not json":        func(w http.ResponseWriter) { _, _ = io.WriteString(w, `ok`) },
		"trailing data":   func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{} {}`) },
		"answer too long": func(w http.ResponseWriter) {
			_, _ = io.WriteString(w, `{"a":"`+strings.Repeat("x", edenrelay.MaxRelayAnswer)+`"}`)
		},
		"timeout": func(w http.ResponseWriter) { time.Sleep(400 * time.Millisecond) },
		"redirect to http": func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://evil.example/")
			w.WriteHeader(http.StatusFound)
		},
	}
	for name, f := range faults {
		set(f)
		err := send()
		require.ErrorIs(t, err, edenrelay.ErrRelayFault, name)
	}
}

func TestHoustonRelayTellsWhetherTheRequestLeft(t *testing.T) {
	signed := []byte{0x02, 0xc0, 0x01}
	railRef := edenescrow.RailRef(signed)
	var reads atomic.Int32
	var answer atomic.Value
	answer.Store(func(http.ResponseWriter) {})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		reads.Add(1)
		answer.Load().(func(http.ResponseWriter))(w)
	}))
	defer srv.Close()
	relay := func(base string) *edenrelay.HoustonRelay {
		rl, err := edenrelay.NewHoustonRelay(edenrelay.HoustonConfig{BaseURL: base, Timeout: 200 * time.Millisecond}, srv.Client(), nil)
		require.NoError(t, err)
		return rl
	}

	answer.Store(func(w http.ResponseWriter) { time.Sleep(400 * time.Millisecond) })
	err := relay(srv.URL).Send(context.Background(), signed, railRef, [32]byte{})
	require.ErrorIs(t, err, edenrelay.ErrRelayFault)
	assert.NotErrorIs(t, err, edenrelay.ErrNotSent, "the server read the request; only the answer is missing")
	assert.Equal(t, int32(1), reads.Load())

	answer.Store(func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) })
	err = relay(srv.URL).Send(context.Background(), signed, railRef, [32]byte{})
	require.ErrorIs(t, err, edenrelay.ErrRelayFault)
	assert.NotErrorIs(t, err, edenrelay.ErrNotSent, "an error status is an answer")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = relay(srv.URL).Send(cancelled, signed, railRef, [32]byte{})
	require.ErrorIs(t, err, edenrelay.ErrRelayFault)
	assert.ErrorIs(t, err, edenrelay.ErrNotSent, "a call cancelled before it started")
	assert.Equal(t, int32(2), reads.Load())

	gone := httptest.NewTLSServer(http.NotFoundHandler())
	base := gone.URL
	gone.Close()
	err = relay(base).Send(context.Background(), signed, railRef, [32]byte{})
	require.ErrorIs(t, err, edenrelay.ErrRelayFault)
	assert.ErrorIs(t, err, edenrelay.ErrNotSent, "no connection")
}

func TestCheckRelayAnswer(t *testing.T) {
	rail := strings.Repeat("ab", 32)
	for _, ok := range []string{"", "  ", `{}`, `{"txHash":"0x` + rail + `"}`, `{"result":{"transactionHash":"0x` + rail + `"},"error":null}`, `{"success":true}`} {
		assert.NoError(t, edenrelay.CheckRelayAnswer([]byte(ok), rail), ok)
	}
	for _, bad := range []string{`[]`, `null`, `{"hash":"` + rail + `"}`, `{"transaction":{"hash":"0x` + strings.Repeat("cd", 32) + `"}}`, `{"txHash":"0x` + strings.Repeat("zz", 32) + `"}`} {
		assert.True(t, errors.Is(edenrelay.CheckRelayAnswer([]byte(bad), rail), edenrelay.ErrRelayFault), bad)
	}
}
