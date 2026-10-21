// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// maxRawTx bounds a transaction this client sends; a form T deposit is a few
// hundred bytes.
const maxRawTx = 64 << 10

// PendingNonce is eth_getTransactionCount at pending: the nonce the next
// transaction of addr needs.
func (c *Client) PendingNonce(ctx context.Context, addr [20]byte) (uint64, error) {
	return c.txCount(ctx, addr, "pending")
}

// LatestNonce is eth_getTransactionCount at latest: how many transactions
// of addr the chain executed.
func (c *Client) LatestNonce(ctx context.Context, addr [20]byte) (uint64, error) {
	return c.txCount(ctx, addr, "latest")
}

func (c *Client) txCount(ctx context.Context, addr [20]byte, tag string) (uint64, error) {
	if err := c.checkChain(ctx); err != nil {
		return 0, err
	}
	res, err := c.call(ctx, c.cfg.MaxResponse, "eth_getTransactionCount", "0x"+hex.EncodeToString(addr[:]), tag)
	if err != nil {
		return 0, err
	}
	var s string
	if err := json.Unmarshal(res, &s); err != nil {
		return 0, malformed("eth_getTransactionCount: %v", err)
	}
	return quantity64(s)
}

// SendRawTransaction is eth_sendRawTransaction. The node's answer must name
// the keccak-256 of the bytes sent; any other hash means the node took
// something else.
func (c *Client) SendRawTransaction(ctx context.Context, signed []byte) ([32]byte, error) {
	if len(signed) == 0 || len(signed) > maxRawTx {
		return [32]byte{}, fmt.Errorf("edenrpc: raw transaction of %d bytes", len(signed))
	}
	if err := c.checkChain(ctx); err != nil {
		return [32]byte{}, err
	}
	res, err := c.call(ctx, c.cfg.MaxResponse, "eth_sendRawTransaction", "0x"+hex.EncodeToString(signed))
	if err != nil {
		return [32]byte{}, err
	}
	var s string
	if err := json.Unmarshal(res, &s); err != nil {
		return [32]byte{}, malformed("eth_sendRawTransaction: %v", err)
	}
	var got [32]byte
	if err := fixed(s, got[:]); err != nil {
		return [32]byte{}, err
	}
	if want := keccak(signed); got != want {
		return [32]byte{}, malformed("eth_sendRawTransaction answered hash %x, not %x", got, want)
	}
	return got, nil
}
