package edictad

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/gate"
)

const seedLen = 32

// readSeed reads the raw gate key seed. It cannot use secret.FromFile: that
// trims a trailing newline, which may be a legitimate seed byte.
func readSeed(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("edictad: gate key file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("edictad: gate key file is not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("edictad: gate key file: %w", secret.ErrPermissions)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("edictad: gate key file: %w", err)
	}
	defer clear(b)
	if len(b) != seedLen {
		return nil, fmt.Errorf("edictad: gate key file must hold exactly %d bytes", seedLen)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

type agentsFile struct {
	Agents []struct {
		AgentID string `toml:"agent_id"`
		PubKey  string `toml:"pubkey"`
	} `toml:"agents"`
}

func loadAllowlist(path string) (*gate.StaticAllowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("edictad: agents file: %w", err)
	}
	var f agentsFile
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&f); err != nil {
		return nil, errors.New("edictad: agents file is not valid TOML of [[agents]] with agent_id and pubkey")
	}
	m := make(map[string][]byte, len(f.Agents))
	for _, a := range f.Agents {
		if _, dup := m[a.AgentID]; dup {
			return nil, fmt.Errorf("edictad: agents file: duplicate agent id %q", a.AgentID)
		}
		k, err := hex.DecodeString(a.PubKey)
		if err != nil {
			return nil, fmt.Errorf("edictad: agents file: agent %q: pubkey is not hex", a.AgentID)
		}
		m[a.AgentID] = k
	}
	return gate.NewStaticAllowlist(m)
}
