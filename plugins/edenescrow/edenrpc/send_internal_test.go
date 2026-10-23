// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/evm"
)

func TestPendingNonce(t *testing.T) {
	s, c := newRPCServer(t)
	s.set("eth_getTransactionCount", `"0x7"`)
	n, err := c.PendingNonce(context.Background(), [20]byte{0x01})
	require.NoError(t, err)
	assert.Equal(t, uint64(7), n)

	s.set("eth_getTransactionCount", `"0x07"`)
	_, err = c.PendingNonce(context.Background(), [20]byte{0x01})
	require.Error(t, err, "a non-minimal quantity")
}

func TestLatestNonceAsksForLatest(t *testing.T) {
	s, c := newRPCServer(t)
	var tag string
	s.setAnswer(func(id json.RawMessage, method string, params []json.RawMessage) (string, bool) {
		if method != "eth_getTransactionCount" {
			return "", false
		}
		require.Len(t, params, 2)
		require.NoError(t, json.Unmarshal(params[1], &tag))
		return `{"jsonrpc":"2.0","id":` + string(id) + `,"result":"0x9"}`, true
	})
	n, err := c.LatestNonce(context.Background(), [20]byte{0x01})
	require.NoError(t, err)
	assert.Equal(t, uint64(9), n)
	assert.Equal(t, "latest", tag)
}

func TestSendRawTransactionNeedsTheHashOfTheBytesSent(t *testing.T) {
	s, c := newRPCServer(t)
	signed := []byte{0x02, 0xc0}
	h := evm.Keccak256(signed)
	var sentParam string
	s.setAnswer(func(id json.RawMessage, method string, params []json.RawMessage) (string, bool) {
		if method != "eth_sendRawTransaction" {
			return "", false
		}
		require.Len(t, params, 1)
		require.NoError(t, json.Unmarshal(params[0], &sentParam))
		return `{"jsonrpc":"2.0","id":` + string(id) + `,"result":"0x` + hex.EncodeToString(h[:]) + `"}`, true
	})
	got, err := c.SendRawTransaction(context.Background(), signed)
	require.NoError(t, err)
	assert.Equal(t, h, got)
	assert.Equal(t, "0x02c0", sentParam)

	s.setAnswer(nil)
	s.set("eth_sendRawTransaction", `"0x`+hex.EncodeToString(make([]byte, 32))+`"`)
	_, err = c.SendRawTransaction(context.Background(), signed)
	require.Error(t, err, "the node answered another hash")

	_, err = c.SendRawTransaction(context.Background(), nil)
	require.Error(t, err)
}
