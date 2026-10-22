package initcmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/engine/policy"
)

// Names of the files init writes in the home, next to edicta.toml.
const (
	AllowlistFile = "agents.toml"
	MandateFile   = "mandate.cbor"
	ArchiveDir    = "archive"
	RegistryFile  = "registry.db"
)

// What the starter stack authorizes: x402 exact payments on the settlement
// chain, measured in its USDC.
const (
	X402ActionType = "application/vnd.edicta.x402.exact-evm.v1+cbor"
	X402Kind       = "x402-payment"
	// USDCScale is the decimals of USDC on every supported chain.
	USDCScale = 6
	// DefaultAgentID names the agent in the allowlist and the config.
	DefaultAgentID = "agent-1"
)

// Conservative starter limits, in USDC base units: 0.10 USDC per payment
// and 1 USDC per rolling hour.
const (
	DefaultMaxPerPayment uint64 = 100_000
	DefaultMaxPerHour    uint64 = 1_000_000
)

// The starter mandate starts a little in the past, so a block time slightly
// behind the local clock is already inside it, and runs for a month.
const (
	mandateBackdate = 5 * time.Minute
	mandateLifetime = 30 * 24 * time.Hour
)

// maxMandateBytes and maxConfigBytes bound the read of an existing mandate
// and config file.
const (
	maxMandateBytes = 1 << 20
	maxConfigBytes  = 1 << 20
)

// File is a file init writes once and then leaves alone.
type File struct {
	Path   string
	Status Status
}

// Mandate is the signed starter mandate.
type Mandate struct {
	Path string
	// Hash is the hex mandate hash.
	Hash   string
	GateID string
	// Text is the mandate as policy.Render shows it to the principal.
	Text   string
	Status Status
}

// existingConfig loads the config file of the home when there is one. A file
// that does not load and validate is unusable and left alone, and so is one
// written for another network or mode than the run sets up.
func existingConfig(home string, n config.Network, p config.Presets) (*config.Config, error) {
	path := filepath.Join(home, config.FileName)
	found, err := exists(path)
	if err != nil || !found {
		return nil, err
	}
	b, err := readBounded(path, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrExisting, path, err)
	}
	c, err := config.Parse(b, nil)
	if err == nil {
		err = c.ApplyDefaults(p)
	}
	if err == nil {
		err = c.ValidateBasic()
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrExisting, path, err)
	}
	switch old := c.Network; {
	case old.Celestia != n.Celestia || old.Settlement != n.Settlement:
		return nil, fmt.Errorf("%w: %s is for %s+%s: run init with that preset, or move the file away", ErrConfig, path, old.Celestia, old.Settlement)
	case old.Mode != n.Mode:
		return nil, fmt.Errorf("%w: %s is for a %s stack and init sets up a %s one: move the file away", ErrConfig, path, old.Mode, n.Mode)
	}
	return &c, nil
}

// readBounded reads a regular file of at most max bytes.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("longer than %d bytes", max)
	}
	return b, nil
}

type mandateParams struct {
	principalPath string
	principal     ed25519.PublicKey
	gateID        string
	agent         ed25519.PublicKey
	asset         string
	perPayment    uint64
	perHour       uint64
	now           time.Time
}

// usdcAsset is the asset name the x402 extractor reports for the chain's
// USDC: the contract in lower case.
func usdcAsset(chainID uint64, contract string) string {
	return fmt.Sprintf("eip155:%d/erc20:%s", chainID, strings.ToLower(contract))
}

// readMandate loads the mandate file when there is one; sm is nil when there
// is none.
func readMandate(path string) (Mandate, *policy.SignedMandate, error) {
	found, err := exists(path)
	if err != nil || !found {
		return Mandate{Path: path}, nil, err
	}
	b, err := readBounded(path, maxMandateBytes)
	if err != nil {
		return Mandate{Path: path}, nil, fmt.Errorf("%w: mandate %s: %w", ErrExisting, path, err)
	}
	m, sm, err := mandateOf(path, b)
	if err != nil {
		return m, nil, fmt.Errorf("%w: mandate %s: %w", ErrExisting, path, err)
	}
	m.Status = Exists
	return m, sm, nil
}

// ensureMandate signs a new starter mandate with the principal key and
// writes it, or reads the one another writer put there first.
func ensureMandate(path string, p mandateParams) (Mandate, *policy.SignedMandate, error) {
	b, err := signStarterMandate(p)
	if err != nil {
		return Mandate{Path: path}, nil, err
	}
	err = keyfile.WriteNew(path, b)
	if errors.Is(err, keyfile.ErrExists) {
		return readMandate(path)
	}
	if err != nil {
		return Mandate{Path: path}, nil, fmt.Errorf("init: mandate: %w", err)
	}
	m, sm, err := mandateOf(path, b)
	if err != nil {
		return m, nil, fmt.Errorf("init: the new mandate does not verify: %w", err)
	}
	m.Status = Created
	return m, sm, nil
}

func mandateOf(path string, b []byte) (Mandate, *policy.SignedMandate, error) {
	sm, h, err := policy.VerifyMandate(b)
	if err != nil {
		return Mandate{Path: path}, nil, err
	}
	return Mandate{Path: path, Hash: hex.EncodeToString(h[:]), GateID: sm.Mandate.GateID, Text: policy.Render(&sm.Mandate)}, sm, nil
}

// mandatePrincipal is the principal that signed sm, as a key to compare with
// the other roles; a wallet principal has no Ed25519 key.
func mandatePrincipal(sm *policy.SignedMandate, path string) Ed25519Key {
	k := Ed25519Key{Role: "principal", Path: path + " (its principal)"}
	if sm.Mandate.SigType == 0 {
		k.Public = ed25519.PublicKey(sm.Mandate.Principal)
	}
	return k
}

// principalOf reports the principal that signed sm next to the local key
// file: the file is the principal's key, holds another key, or is absent
// because the key was moved off the machine.
func principalOf(sm *policy.SignedMandate, file Ed25519Key) (Ed25519Key, string) {
	id := sm.Mandate.PrincipalID()
	k := mandatePrincipal(sm, "")
	k.Path = file.Path
	switch {
	case file.Status == "":
		k.Path, k.Status = "", Offline
	case k.Public != nil && k.Public.Equal(file.Public):
		k.Status = file.Status
	default:
		k.Status = Mismatch
	}
	return k, id.String()
}

func signStarterMandate(p mandateParams) ([]byte, error) {
	id, err := keyfile.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	now := p.now.Unix()
	m := &policy.Mandate{
		Format:    1,
		Principal: p.principal,
		GateID:    p.gateID,
		Agents:    [][]byte{p.agent},
		NotBefore: uint64(now - int64(mandateBackdate/time.Second)),
		NotAfter:  uint64(now + int64(mandateLifetime/time.Second)),
		Kinds:     []string{X402Kind},
		Assets: []policy.AssetRule{{
			Asset:        p.asset,
			Scale:        USDCScale,
			PerActionMax: policy.AmountFromUint64(p.perPayment),
			Periods:      []policy.PeriodLimit{{Hours: 1, Max: policy.AmountFromUint64(p.perHour)}},
		}},
		MandateID: id,
		Version:   1,
	}
	priv, err := keyfile.ReadSeed(p.principalPath, "principal")
	if err != nil {
		return nil, fmt.Errorf("init: principal key: %w", err)
	}
	defer clear(priv)
	b, _, err := policy.SignMandate(priv, m)
	if err != nil {
		return nil, fmt.Errorf("init: mandate: %w", err)
	}
	return b, nil
}

func allowlistBytes(agentID string, pub ed25519.PublicKey) []byte {
	return fmt.Appendf(nil, "[[agents]]\nagent_id = %q\npubkey = %q\n", agentID, hex.EncodeToString(pub))
}

// ensureFile writes data to path unless path exists.
func ensureFile(path string, data []byte) (File, error) {
	f := File{Path: path}
	found, err := exists(path)
	if err != nil {
		return f, err
	}
	if found {
		f.Status = Exists
		return f, nil
	}
	switch err := keyfile.WriteNew(path, data); {
	case err == nil:
		f.Status = Created
	case errors.Is(err, keyfile.ErrExists):
		f.Status = Exists
	default:
		return f, fmt.Errorf("init: %s: %w", filepath.Base(path), err)
	}
	return f, nil
}

// The starter config file. Only the keys init decides are written; the
// endpoints come from the presets named in [network], so a newer preset
// reaches the stack and doctor reports the version change.
type starterConfig struct {
	Network   map[string]any `toml:"network"`
	Agent     starterAgent   `toml:"agent"`
	Gate      starterGate    `toml:"gate"`
	Recorder  starterAccount `toml:"recorder"`
	Publisher starterAccount `toml:"publisher"`
	Archive   starterArchive `toml:"archive"`
	Signer    *starterSigner `toml:"signer,omitempty"`
}

type starterAgent struct {
	ID      string `toml:"id"`
	KeyFile string `toml:"key_file"`
	GateURL string `toml:"gate_url"`
}

type starterGate struct {
	GateID        string   `toml:"gate_id"`
	KeyFile       string   `toml:"key_file"`
	RegistryPath  string   `toml:"registry_path"`
	AllowlistFile string   `toml:"allowlist_file"`
	MandateFile   string   `toml:"mandate_file,omitempty"`
	ActionTypes   []string `toml:"action_types"`
	ExecutorKeys  []string `toml:"executor_keys"`
}

type starterAccount struct {
	KeyringDir     string `toml:"keyring_dir"`
	KeyName        string `toml:"key_name"`
	PassphraseFile string `toml:"passphrase_file"`
	Namespace      string `toml:"namespace"`
}

type starterArchive struct {
	Dir string `toml:"dir"`
}

type starterSigner struct {
	PinnedGateKeys []string    `toml:"pinned_gate_keys"`
	PayerBackend   string      `toml:"payer_backend"`
	PayerKeyFile   string      `toml:"payer_key_file"`
	PayerAddress   string      `toml:"payer_address"`
	Risk           starterRisk `toml:"risk"`
}

type starterRisk struct {
	MaxPerPayment uint64 `toml:"max_per_payment"`
	MaxPerHour    uint64 `toml:"max_per_hour"`
}

const configHeader = `# Written by edicta init. No key material is in this file, only the paths of
# the files that hold it. Endpoints come from the presets named in
# [network]; a key written here wins over the preset.

`

// configBytes renders the starter config and checks that it loads the way
// every binary will load it.
func configBytes(s starterConfig, p config.Presets) ([]byte, error) {
	body, err := toml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("init: config file: %w", err)
	}
	b := append([]byte(configHeader), body...)
	c, err := config.Parse(b, nil)
	if err == nil {
		err = c.ApplyDefaults(p)
	}
	if err == nil {
		err = c.ValidateBasic()
	}
	if err != nil {
		return nil, fmt.Errorf("init: the config file init built does not validate: %w", err)
	}
	return b, nil
}

// networkTable is the [network] section as written: the preset names and
// versions, and the keys the run overrode.
func networkTable(n config.Network, overrides map[string]string) (map[string]any, error) {
	tree := map[string]any{"network": map[string]any{
		"celestia":                  n.Celestia,
		"settlement":                n.Settlement,
		"mode":                      n.Mode,
		"celestia_preset_version":   int64(n.CelestiaPresetVersion),
		"settlement_preset_version": int64(n.SettlementPresetVersion),
	}}
	if err := config.ApplyOverrides(tree, overrides); err != nil {
		return nil, err
	}
	net, ok := tree["network"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: [network] is not a table", ErrConfig)
	}
	return net, nil
}
