// SPDX-License-Identifier: Apache-2.0

package edenrelay_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrelay"
)

func TestHoustonRelayMatchesTheRecordedExchange(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(testkit.SpecPath(t, "vectors/profiles/eden-escrow/live/mainnet-paymentid", name))
		require.NoError(t, err)
		return b
	}
	signed, err := hex.DecodeString(strings.TrimPrefix(string(read("deposit-signed.hex")), "0x"))
	require.NoError(t, err)
	const railRef = "a99035d9722a158784459d9b1a69f26451b3ebbc8af3a4f5233e7fff2c0f7b75"
	var pid [32]byte
	_, err = hex.Decode(pid[:], []byte("5b6d992c5e3090d174e4fedb3f1ab47ef2f9f6e5cc0f25abb425c56c79c1a9a5"))
	require.NoError(t, err)
	answer := read("body-deposit-send.json")

	var got []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.Header().Set("Deprecation", "true")
		_, _ = w.Write(answer)
	}))
	defer srv.Close()
	relay, err := edenrelay.NewHoustonRelay(edenrelay.HoustonConfig{BaseURL: srv.URL, Timeout: edenrelay.DefaultServerTimeout}, srv.Client(), nil)
	require.NoError(t, err)
	require.NoError(t, relay.Send(context.Background(), signed, railRef, pid))
	assert.Equal(t, string(bytes.TrimSuffix(read("body-deposit-send-request.json"), []byte("\n"))), string(got),
		"the relay posts the reference client's body")

	require.NoError(t, edenrelay.CheckRelayAnswer(answer, railRef), "the recorded answer names the rail_ref")
	h := http.Header{}
	h.Set("deprecation", "true")
	assert.True(t, edenrelay.Deprecated(h, answer), "the marker is the header")
	assert.False(t, edenrelay.Deprecated(http.Header{}, answer), "the recorded body carries no marker")
}
