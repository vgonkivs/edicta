package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rpcError(code int, msg string) func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge) {
	return func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge) {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, id, code, msg)
	}
}

func TestDownloadRawReturnsTheResultUndecoded(t *testing.T) {
	for _, result := range []string{`{"data":"ZQ=="}`, `{"Data":"ZQ=="}`, `{"data":"ZQ==","x":1}`} {
		fb := startBridge(t, func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge) {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
		})
		got, err := fb.bridge(t, BridgeLimits{}).DownloadRaw(tctx(t), [33]byte{}, 10)
		require.NoError(t, err, result)
		assert.JSONEq(t, result, string(got), "a wrong shape reaches the probe, which decides")
	}
}

func TestDownloadRawClassifiesRefusalsAsIncompatible(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge){
		"http 401": func(w http.ResponseWriter, _ json.RawMessage, _ *fakeBridge) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		},
		"missing permission": rpcError(-32000, "missing permission to invoke 'Download' (need 'read')"),
		"method not found":   rpcError(-32601, "method not found"),
		"wrong parameters":   rpcError(-32602, "invalid params"),
		"parameter decoding": rpcError(-32700, "parse error"),
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			fb := startBridge(t, reply)
			_, err := fb.bridge(t, BridgeLimits{}).DownloadRaw(tctx(t), [33]byte{}, 10)
			require.ErrorIs(t, err, ErrBridgeIncompatible)
		})
	}
}

func TestDownloadRawDoesNotCallTransportFailuresIncompatible(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, id json.RawMessage, _ *fakeBridge){
		"other rpc error": rpcError(-32000, "internal failure"),
		"blob not found":  rpcError(-32000, "blob: not found"),
		"http 500": func(w http.ResponseWriter, _ json.RawMessage, _ *fakeBridge) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
		"http 503": func(w http.ResponseWriter, _ json.RawMessage, _ *fakeBridge) {
			http.Error(w, "busy", http.StatusServiceUnavailable)
		},
		"garbage body": func(w http.ResponseWriter, _ json.RawMessage, _ *fakeBridge) { _, _ = w.Write([]byte("not json")) },
		"answer above the wire limit": func(w http.ResponseWriter, id json.RawMessage, fb *fakeBridge) {
			fb.stream(w, id, `{"data":"`, `"}}`)
		},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			fb := startBridge(t, reply)
			_, err := fb.bridge(t, BridgeLimits{}).DownloadRaw(tctx(t), [33]byte{}, 10)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrBridgeIncompatible)
		})
	}
	t.Run("cancelled context", func(t *testing.T) {
		fb := startBridge(t, rpcError(-32601, "method not found"))
		b := fb.bridge(t, BridgeLimits{})
		ctx, cancel := context.WithCancel(tctx(t))
		cancel()
		_, err := b.DownloadRaw(ctx, [33]byte{}, 10)
		require.ErrorIs(t, err, ErrUnavailable)
		assert.NotErrorIs(t, err, ErrBridgeIncompatible, "a cancelled call says nothing about the bridge")
	})
	t.Run("no raw client", func(t *testing.T) {
		_, err := (&FibreBridge{}).DownloadRaw(tctx(t), [33]byte{}, 10)
		require.ErrorIs(t, err, ErrUnavailable)
	})
}
