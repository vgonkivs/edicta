// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/vgonkivs/edicta/edenexec"
)

// Defaults and bounds of a client.
const (
	DefaultTimeout     = 30 * time.Second
	DefaultMaxResponse = 4 << 20
	DefaultMaxBlock    = 32 << 20
	// MaxResponseLimit bounds both limits.
	MaxResponseLimit = 256 << 20
	// maxCode bounds eth_getCode; contract code is at most a few tens of
	// kilobytes.
	maxCode = 1 << 20
	// maxFallbackReceipts bounds the per-transaction receipt reads of a
	// node without eth_getBlockReceipts.
	maxFallbackReceipts = 4096
)

// codeMethodNotFound is the JSON-RPC error of an unknown method.
const codeMethodNotFound = -32601

// Config is one Eden JSON-RPC endpoint.
type Config struct {
	URL   string
	Class edenexec.SourceClass
	// ExpectChainID, when set, is checked once before any other call.
	ExpectChainID uint64
	Timeout       time.Duration
	// MaxResponse bounds one answer; MaxBlock bounds a full block or its
	// receipts.
	MaxResponse int64
	MaxBlock    int64
}

// ApplyDefaults fills the zero fields.
func (c *Config) ApplyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxResponse == 0 {
		c.MaxResponse = DefaultMaxResponse
	}
	if c.MaxBlock == 0 {
		c.MaxBlock = DefaultMaxBlock
	}
}

// ValidateBasic checks the fields alone.
func (c Config) ValidateBasic() error {
	if _, err := hostOf(c.URL); err != nil {
		return err
	}
	switch {
	case c.Class != edenexec.ClassPublicRPC && c.Class != edenexec.ClassOwnNode:
		return fmt.Errorf("edenrpc: source class %d", c.Class)
	case c.Timeout <= 0:
		return errors.New("edenrpc: timeout must be positive")
	case c.MaxResponse < 1024 || c.MaxResponse > MaxResponseLimit:
		return fmt.Errorf("edenrpc: MaxResponse %d is not in 1024..%d", c.MaxResponse, MaxResponseLimit)
	case c.MaxBlock < c.MaxResponse || c.MaxBlock > MaxResponseLimit:
		return fmt.Errorf("edenrpc: MaxBlock %d is not in MaxResponse..%d", c.MaxBlock, MaxResponseLimit)
	}
	return nil
}

// hostOf is the normalized host of an http or https URL: lower case, without
// a trailing dot. Two sources on one host are one operator.
func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("edenrpc: URL does not parse")
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return "", fmt.Errorf("edenrpc: URL %q needs an http or https scheme", raw)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", fmt.Errorf("edenrpc: URL %q has no host", raw)
	}
	return host, nil
}

// Client is an edenexec.Source over Eden's eth_* JSON-RPC.
type Client struct {
	cfg  Config
	name string
	hc   *http.Client
	id   atomic.Uint64

	mu        sync.Mutex
	chainSeen bool
}

var _ edenexec.Source = (*Client)(nil)

// New returns a client. A nil hc uses one with the configured timeout that
// follows no redirect.
func New(cfg Config, hc *http.Client) (*Client, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	name, _ := hostOf(cfg.URL)
	if hc == nil {
		hc = newHTTPClient(cfg.Timeout)
	}
	return &Client{cfg: cfg, name: name, hc: hc}, nil
}

// newHTTPClient follows no redirect: a source is identified by its host,
// and a redirect would let one operator answer for another.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Client) Name() string                { return c.name }
func (c *Client) Class() edenexec.SourceClass { return c.cfg.Class }

// rpcError is an error answer of the endpoint.
type rpcError struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, trunc(e.Message)) }

type envelope struct {
	JSONRPC *string         `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

// call sends one request and returns its result, null included.
func (c *Client) call(ctx context.Context, limit int64, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	id := c.id.Add(1)
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", method, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%s: answer larger than %d bytes", method, limit)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", method, resp.StatusCode)
	}
	return parseEnvelope(raw, id)
}

// parseEnvelope reads a JSON-RPC 2.0 answer to the request with this id:
// exactly one of result and error.
func parseEnvelope(raw []byte, id uint64) (json.RawMessage, error) {
	if err := checkStrict(raw); err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, malformed("envelope: %v", err)
	}
	switch {
	case env.JSONRPC == nil || *env.JSONRPC != "2.0":
		return nil, malformed("not a JSON-RPC 2.0 answer")
	case string(env.ID) != strconv.FormatUint(id, 10):
		return nil, malformed("answer id %s, request id %d", trunc(string(env.ID)), id)
	case env.Error != nil && env.Result != nil:
		return nil, malformed("answer has both a result and an error")
	case env.Error != nil:
		return nil, env.Error
	case env.Result == nil:
		return nil, malformed("answer has no result")
	}
	return env.Result, nil
}

func isNull(r json.RawMessage) bool { return string(r) == "null" }

func hashParam(h [32]byte) string { return "0x" + hex.EncodeToString(h[:]) }

// checkChain asks eth_chainId once when the client is bound to a chain.
func (c *Client) checkChain(ctx context.Context) error {
	if c.cfg.ExpectChainID == 0 {
		return nil
	}
	c.mu.Lock()
	seen := c.chainSeen
	c.mu.Unlock()
	if seen {
		return nil
	}
	id, err := c.ChainID(ctx)
	if err != nil {
		return err
	}
	if id != c.cfg.ExpectChainID {
		return fmt.Errorf("%w: %s serves chain %d, not %d", edenexec.ErrChainConfig, c.name, id, c.cfg.ExpectChainID)
	}
	c.mu.Lock()
	c.chainSeen = true
	c.mu.Unlock()
	return nil
}

func (c *Client) quantity(ctx context.Context, method string) (uint64, error) {
	res, err := c.call(ctx, c.cfg.MaxResponse, method)
	if err != nil {
		return 0, err
	}
	var s string
	if err := json.Unmarshal(res, &s); err != nil {
		return 0, malformed("%s: %v", method, err)
	}
	return quantity64(s)
}

// ChainID is eth_chainId.
func (c *Client) ChainID(ctx context.Context) (uint64, error) { return c.quantity(ctx, "eth_chainId") }

// Head is eth_blockNumber.
func (c *Client) Head(ctx context.Context) (uint64, error) {
	if err := c.checkChain(ctx); err != nil {
		return 0, err
	}
	return c.quantity(ctx, "eth_blockNumber")
}

// Transaction is eth_getTransactionByHash; null is edenexec.ErrNotFound.
func (c *Client) Transaction(ctx context.Context, hash [32]byte) (edenexec.TxView, error) {
	if err := c.checkChain(ctx); err != nil {
		return edenexec.TxView{}, err
	}
	res, err := c.call(ctx, c.cfg.MaxResponse, "eth_getTransactionByHash", hashParam(hash))
	if err != nil {
		return edenexec.TxView{}, err
	}
	if isNull(res) {
		return edenexec.TxView{}, edenexec.ErrNotFound
	}
	return DecodeTransaction(res)
}

// Receipt is eth_getTransactionReceipt; null is edenexec.ErrNotFound.
func (c *Client) Receipt(ctx context.Context, hash [32]byte) (edenexec.ReceiptView, error) {
	if err := c.checkChain(ctx); err != nil {
		return edenexec.ReceiptView{}, err
	}
	res, err := c.call(ctx, c.cfg.MaxResponse, "eth_getTransactionReceipt", hashParam(hash))
	if err != nil {
		return edenexec.ReceiptView{}, err
	}
	if isNull(res) {
		return edenexec.ReceiptView{}, edenexec.ErrNotFound
	}
	return DecodeReceipt(res)
}

func (c *Client) block(ctx context.Context, blockHash [32]byte, full bool) (edenexec.HeaderView, []json.RawMessage, error) {
	if err := c.checkChain(ctx); err != nil {
		return edenexec.HeaderView{}, nil, err
	}
	limit := c.cfg.MaxResponse
	if full {
		limit = c.cfg.MaxBlock
	}
	res, err := c.call(ctx, limit, "eth_getBlockByHash", hashParam(blockHash), full)
	if err != nil {
		return edenexec.HeaderView{}, nil, err
	}
	if isNull(res) {
		return edenexec.HeaderView{}, nil, edenexec.ErrNotFound
	}
	h, txs, err := DecodeBlock(res)
	if err != nil {
		return edenexec.HeaderView{}, nil, err
	}
	if h.Hash != blockHash {
		return edenexec.HeaderView{}, nil, malformed("asked for block %x, served %x", blockHash, h.Hash)
	}
	return h, txs, nil
}

// Header is eth_getBlockByHash without the transaction objects. The served
// hash must be the one asked for; whether the fields hash to it is
// edenexec.VerifyBlock's job.
func (c *Client) Header(ctx context.Context, blockHash [32]byte) (edenexec.HeaderView, error) {
	h, _, err := c.block(ctx, blockHash, false)
	return h, err
}

// BlockTransactions rebuilds every transaction of the block from
// eth_getBlockByHash with the transaction objects. Each must rebuild to the
// hash it is served with and name this block and its position.
func (c *Client) BlockTransactions(ctx context.Context, blockHash [32]byte) ([][]byte, error) {
	_, raws, err := c.block(ctx, blockHash, true)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(raws))
	for i, raw := range raws {
		tx, err := DecodeTransaction(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i, err)
		}
		if !tx.Included || tx.BlockHash != blockHash || tx.Index != uint64(i) {
			return nil, malformed("transaction %d names another block or position", i)
		}
		b, err := edenexec.RebuildSigned(tx)
		if err != nil {
			return nil, fmt.Errorf("transaction %d: %w", i, err)
		}
		if keccak(b) != tx.Hash {
			return nil, malformed("transaction %d does not rebuild to its hash", i)
		}
		out = append(out, b)
	}
	return out, nil
}

// BlockReceipts encodes every receipt of the block, from eth_getBlockReceipts
// or, on a node without it, one eth_getTransactionReceipt per transaction.
func (c *Client) BlockReceipts(ctx context.Context, blockHash [32]byte) ([][]byte, error) {
	if err := c.checkChain(ctx); err != nil {
		return nil, err
	}
	res, err := c.call(ctx, c.cfg.MaxBlock, "eth_getBlockReceipts", hashParam(blockHash))
	var re *rpcError
	if errors.As(err, &re) && re.Code == codeMethodNotFound {
		return c.receiptsOneByOne(ctx, blockHash)
	}
	if err != nil {
		return nil, err
	}
	if isNull(res) {
		return nil, edenexec.ErrNotFound
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(res, &raws); err != nil {
		return nil, malformed("eth_getBlockReceipts: %v", err)
	}
	views := make([]edenexec.ReceiptView, 0, len(raws))
	for i, raw := range raws {
		rc, err := DecodeReceipt(raw)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		views = append(views, rc)
	}
	return encodeReceipts(views, blockHash)
}

func (c *Client) receiptsOneByOne(ctx context.Context, blockHash [32]byte) ([][]byte, error) {
	_, raws, err := c.block(ctx, blockHash, false)
	if err != nil {
		return nil, err
	}
	if len(raws) > maxFallbackReceipts {
		return nil, fmt.Errorf("edenrpc: %d transactions, at most %d receipts are read one by one", len(raws), maxFallbackReceipts)
	}
	views := make([]edenexec.ReceiptView, 0, len(raws))
	for i, raw := range raws {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, malformed("transaction %d is not a hash", i)
		}
		var h [32]byte
		if err := fixed(s, h[:]); err != nil {
			return nil, err
		}
		rc, err := c.Receipt(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		if rc.TxHash != h {
			return nil, malformed("receipt %d names another transaction", i)
		}
		views = append(views, rc)
	}
	return encodeReceipts(views, blockHash)
}

func encodeReceipts(views []edenexec.ReceiptView, blockHash [32]byte) ([][]byte, error) {
	out := make([][]byte, 0, len(views))
	for i, rc := range views {
		if rc.BlockHash != blockHash || rc.Index != uint64(i) {
			return nil, malformed("receipt %d names another block or position", i)
		}
		b, err := edenexec.ReceiptEncoding(rc)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// CodeHash is keccak256 of eth_getCode at latest.
func (c *Client) CodeHash(ctx context.Context, addr [20]byte) ([32]byte, error) {
	if err := c.checkChain(ctx); err != nil {
		return [32]byte{}, err
	}
	res, err := c.call(ctx, 2*maxCode+1024, "eth_getCode", "0x"+hex.EncodeToString(addr[:]), "latest")
	if err != nil {
		return [32]byte{}, err
	}
	var s string
	if err := json.Unmarshal(res, &s); err != nil {
		return [32]byte{}, malformed("eth_getCode: %v", err)
	}
	code, err := data(s)
	if err != nil {
		return [32]byte{}, err
	}
	return keccak(code), nil
}

func keccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	h.Sum(out[:0])
	return out
}
