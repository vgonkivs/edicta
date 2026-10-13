// Package config is the one configuration file of every Edicta binary,
// edicta.toml: sections, network presets, strict loading and validation.
//
// Secrets never appear in the file, only the paths of the files that hold
// them. Unknown keys are an error.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ErrConfig wraps every configuration refusal. Messages name keys, never values.
var ErrConfig = errors.New("config: invalid configuration")

// EnvHome names the environment variable that points at the Edicta home
// directory. It is the only environment variable the binaries read.
const EnvHome = "EDICTA_HOME"

// FileName is the name of the configuration file inside the home directory.
const FileName = "edicta.toml"

// Home returns the Edicta home: $EDICTA_HOME, else ~/.edicta.
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return filepath.Abs(h)
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("%w: no home directory: set %s", ErrConfig, EnvHome)
	}
	return filepath.Join(u, ".edicta"), nil
}

// DefaultPath is the configuration file used when --config is not given.
func DefaultPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, FileName), nil
}

// Modes of Network.Mode.
const (
	ModeSelfHosted = "self-hosted"
	ModeHosted     = "hosted"
)

// Config is the whole file. A nil section is absent.
type Config struct {
	Network   Network    `toml:"network"`
	Agent     *Agent     `toml:"agent"`
	Gate      *Gate      `toml:"gate"`
	Recorder  *Recorder  `toml:"recorder"`
	Publisher *Publisher `toml:"publisher"`
	Archive   Archive    `toml:"archive"`
	Signer    *Signer    `toml:"signer"`
	Capture   *Capture   `toml:"capture"`
	Verify    *Verify    `toml:"verify"`
}

func cfgErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
}

// Parse decodes data, applies the key overrides ("section.key" to a TOML
// value, a bare word being a string) and refuses unknown keys. It applies no
// defaults and checks no values.
func Parse(data []byte, overrides map[string]string) (Config, error) {
	var tree map[string]any
	if err := toml.Unmarshal(data, &tree); err != nil {
		return Config{}, tomlErr(err)
	}
	if tree == nil {
		tree = map[string]any{}
	}
	for k, v := range overrides {
		if err := setPath(tree, strings.Split(k, "."), parseValue(v)); err != nil {
			return Config{}, cfgErr("override %q: %v", k, err)
		}
	}
	raw, err := toml.Marshal(tree)
	if err != nil {
		return Config{}, cfgErr("override: %v", err)
	}
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw)).DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, tomlErr(err)
	}
	return c, nil
}

// Load reads path and parses it like Parse.
func Load(path string, overrides map[string]string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("%w: reading %s: %w", ErrConfig, path, err)
	}
	return Parse(data, overrides)
}

// LoadValid is Load, then ApplyDefaults with p, then ValidateBasic.
func LoadValid(path string, overrides map[string]string, p Presets) (Config, error) {
	c, err := Load(path, overrides)
	if err != nil {
		return Config{}, err
	}
	if err := c.ApplyDefaults(p); err != nil {
		return Config{}, err
	}
	if err := c.ValidateBasic(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func tomlErr(err error) error {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		keys := make([]string, 0, len(strict.Errors))
		for _, e := range strict.Errors {
			keys = append(keys, strings.Join(e.Key(), "."))
		}
		return cfgErr("unknown keys %q; secrets are read from files named by *_file keys, never inline", keys)
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, col := de.Position()
		return cfgErr("invalid TOML at line %d column %d: %s", row, col, de.Error())
	}
	return cfgErr("invalid TOML: %v", err)
}

// parseValue reads v as a TOML value, and as a plain string if it is none.
func parseValue(v string) any {
	var m map[string]any
	if err := toml.Unmarshal([]byte("v = "+v), &m); err == nil {
		if x, ok := m["v"]; ok {
			return x
		}
	}
	return v
}

func setPath(tree map[string]any, path []string, v any) error {
	for i, k := range path {
		if k == "" {
			return errors.New("empty key")
		}
		if i == len(path)-1 {
			tree[k] = v
			return nil
		}
		next, ok := tree[k]
		if !ok {
			m := map[string]any{}
			tree[k] = m
			tree = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not a table", strings.Join(path[:i+1], "."))
		}
		tree = m
	}
	return nil
}

// IsEdictaConfig reports whether data is an edicta.toml (it names a Celestia
// network under [network]) rather than a legacy edictad.toml.
func IsEdictaConfig(data []byte) bool {
	var probe struct {
		Network struct {
			Celestia string `toml:"celestia"`
		} `toml:"network"`
	}
	return toml.Unmarshal(data, &probe) == nil && probe.Network.Celestia != ""
}
