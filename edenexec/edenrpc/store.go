// SPDX-License-Identifier: Apache-2.0

package edenrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/edenexec"
)

// GetBlockPath is the Connect route of ev-node's StoreService.GetBlock,
// read from the ev-node v1.1.4 proto (package evnode.v1).
const GetBlockPath = "/evnode.v1.StoreService/GetBlock"

// maxStoreAnswer bounds a GetBlock answer: a signed header and the block's
// data.
const maxStoreAnswer = 64 << 20

// StoreConfig is the operator's own ev-node.
type StoreConfig struct {
	// URL is the node's RPC base, for example http://127.0.0.1:7331.
	URL     string
	Timeout time.Duration
}

// ApplyDefaults fills the zero fields.
func (c *StoreConfig) ApplyDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
}

// ValidateBasic checks the fields alone.
func (c StoreConfig) ValidateBasic() error {
	if _, err := hostOf(c.URL); err != nil {
		return err
	}
	if c.Timeout <= 0 {
		return errors.New("edenrpc: timeout must be positive")
	}
	return nil
}

// Store is an edenexec.DAStatus over ev-node's StoreService, speaking the
// Connect protocol with JSON bodies. Its answer is the node's word, reported
// and never used to decide anything.
type Store struct {
	cfg  StoreConfig
	name string
	hc   *http.Client
}

var _ edenexec.DAStatus = (*Store)(nil)

// NewStore returns a store client. A nil hc uses one with the configured
// timeout that follows no redirect.
func NewStore(cfg StoreConfig, hc *http.Client) (*Store, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	name, _ := hostOf(cfg.URL)
	if hc == nil {
		hc = newHTTPClient(cfg.Timeout)
	}
	return &Store{cfg: cfg, name: name, hc: hc}, nil
}

func (s *Store) Name() string { return s.name }

// DataDAHeight asks GetBlock for the Eden block at height and returns the
// Celestia height its data was included at. Proto3 JSON leaves a zero out,
// so a missing height means not included yet.
func (s *Store) DataDAHeight(ctx context.Context, height uint64) (uint64, bool, error) {
	body, err := json.Marshal(map[string]string{"height": strconv.FormatUint(height, 10)})
	if err != nil {
		return 0, false, err
	}
	url := strings.TrimRight(s.cfg.URL, "/") + GetBlockPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := s.hc.Do(req)
	if err != nil {
		return 0, false, fmt.Errorf("GetBlock: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxStoreAnswer+1))
	if err != nil {
		return 0, false, fmt.Errorf("GetBlock: read: %w", err)
	}
	if len(raw) > maxStoreAnswer {
		return 0, false, fmt.Errorf("GetBlock: answer larger than %d bytes", maxStoreAnswer)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("GetBlock: HTTP %d", resp.StatusCode)
	}
	return parseDAHeight(raw)
}

// parseDAHeight reads dataDaHeight (or its proto name data_da_height, never
// both) as a decimal string or number.
func parseDAHeight(raw []byte) (uint64, bool, error) {
	if err := checkStrict(raw); err != nil {
		return 0, false, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, false, malformed("GetBlock: %v", err)
	}
	v, camel := m["dataDaHeight"]
	if snake, ok := m["data_da_height"]; ok {
		if camel {
			return 0, false, malformed("GetBlock: data DA height named twice")
		}
		v = snake
	} else if !camel {
		return 0, false, nil
	}
	s := string(v)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false, malformed("GetBlock: data DA height %q", trunc(string(v)))
	}
	h, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false, malformed("GetBlock: data DA height %q", trunc(string(v)))
	}
	return h, h > 0, nil
}
