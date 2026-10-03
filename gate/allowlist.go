package gate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/vgonkivs/prior/commitment"
)

// StaticAllowlist is an immutable map from agent id to public key.
type StaticAllowlist struct {
	keys map[string][32]byte
	set  map[[32]byte]struct{}
}

var _ Allowlist = (*StaticAllowlist)(nil)

func validID(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// NewStaticAllowlist checks every id and key: ID charset 1..64, a valid
// public key, no key under two ids.
func NewStaticAllowlist(entries map[string][]byte) (*StaticAllowlist, error) {
	a := &StaticAllowlist{keys: make(map[string][32]byte, len(entries)), set: make(map[[32]byte]struct{}, len(entries))}
	for id, k := range entries {
		if !validID(id, 64) {
			return nil, fmt.Errorf("gate: allowlist: invalid agent id %q", id)
		}
		if err := commitment.CheckPublicKey(k); err != nil {
			return nil, fmt.Errorf("gate: allowlist: agent %q: %w", id, err)
		}
		var key [32]byte
		copy(key[:], k)
		if _, dup := a.set[key]; dup {
			return nil, fmt.Errorf("gate: allowlist: key of agent %q listed twice", id)
		}
		a.keys[id] = key
		a.set[key] = struct{}{}
	}
	return a, nil
}

// LoadAllowlistJSON reads {"version":0,"agents":[{"agent_id":"...","pubkey":"<64 hex>"}]}.
func LoadAllowlistJSON(r io.Reader) (*StaticAllowlist, error) {
	var doc struct {
		Version uint64 `json:"version"`
		Agents  []struct {
			AgentID string `json:"agent_id"`
			PubKey  string `json:"pubkey"`
		} `json:"agents"`
	}
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("gate: allowlist: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("gate: allowlist: data after the document")
	}
	if doc.Version != 0 {
		return nil, fmt.Errorf("gate: allowlist: unsupported version %d", doc.Version)
	}
	m := make(map[string][]byte, len(doc.Agents))
	for _, ag := range doc.Agents {
		if _, dup := m[ag.AgentID]; dup {
			return nil, fmt.Errorf("gate: allowlist: duplicate agent id %q", ag.AgentID)
		}
		k, err := hex.DecodeString(ag.PubKey)
		if err != nil {
			return nil, fmt.Errorf("gate: allowlist: agent %q: %w", ag.AgentID, err)
		}
		m[ag.AgentID] = k
	}
	return NewStaticAllowlist(m)
}

func (a *StaticAllowlist) PubKey(_ context.Context, agentID string) ([32]byte, error) {
	k, ok := a.keys[agentID]
	if !ok {
		return [32]byte{}, ErrAgentNotAllowed
	}
	return k, nil
}

// HasKey reports whether any agent is listed with key.
func (a *StaticAllowlist) HasKey(key [32]byte) bool {
	_, ok := a.set[key]
	return ok
}
