// Package initcmd is `edicta init`: it checks that the preset's endpoints
// answer and are on the right chains, then creates the keys, the starter
// mandate, the allowlist and edicta.toml of a self-hosted stack in the Edicta
// home. It never overwrites a file: a re-run reports what exists and creates
// only what is missing.
package initcmd

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/keyfile"
)

// Sentinel errors of a run.
var (
	// ErrConfig is an invalid option.
	ErrConfig = errors.New("init: invalid options")
	// ErrPreflight means a preflight check failed; nothing was written.
	ErrPreflight = errors.New("init: preflight failed")
	// ErrExisting means a file or keyring init would create is already there
	// but cannot be used. It is left as it is.
	ErrExisting = errors.New("init: existing key is unusable")
)

// LockFile is the file in the home that a run holds an exclusive lock on.
const LockFile = ".edicta-init.lock"

// DefaultPreset is the Celestia network and the settlement chain init sets up
// when no preset is given.
const DefaultPreset = config.CelestiaMocha + "+" + config.SettlementBaseSepolia

// Config holds the options of one run.
type Config struct {
	// Home is the Edicta home directory; it is created when missing.
	Home string
	// Preset is "<celestia network>+<settlement chain>", for example
	// "mocha+base-sepolia" or "mocha+none".
	Preset string
	// Overrides are "network.key" to a TOML value, as in --set. They are
	// written to edicta.toml with the preset names.
	Overrides map[string]string
	// MaxPerPayment and MaxPerHour are the starter mandate's limits and the
	// signer's own, in USDC base units.
	MaxPerPayment, MaxPerHour uint64
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Config) ApplyDefaults() {
	if c.Preset == "" {
		c.Preset = DefaultPreset
	}
	if c.MaxPerPayment == 0 {
		c.MaxPerPayment = DefaultMaxPerPayment
	}
	if c.MaxPerHour == 0 {
		c.MaxPerHour = DefaultMaxPerHour
	}
}

// ValidateBasic checks the stateless fields.
func (c Config) ValidateBasic() error {
	if c.Home == "" {
		return fmt.Errorf("%w: home directory is required", ErrConfig)
	}
	if _, _, err := splitPreset(c.Preset); err != nil {
		return err
	}
	switch {
	case c.MaxPerPayment == 0 || c.MaxPerHour == 0:
		return fmt.Errorf("%w: the per-payment and hourly limits must be above zero", ErrConfig)
	case c.MaxPerPayment > c.MaxPerHour:
		return fmt.Errorf("%w: the per-payment limit is above the hourly limit", ErrConfig)
	}
	for k := range c.Overrides {
		switch {
		case k == "network.celestia" || k == "network.settlement":
			return fmt.Errorf("%w: --set %s: pick the network with --preset", ErrConfig, k)
		case !strings.HasPrefix(k, "network.") || k == "network.":
			// Only the network is read before the keys exist; the other
			// sections come with the config file.
			return fmt.Errorf("%w: --set %s: init accepts only network.* keys", ErrConfig, k)
		}
	}
	return nil
}

func splitPreset(p string) (celestia, settlement string, err error) {
	celestia, settlement, ok := strings.Cut(p, "+")
	if !ok || !presetName(celestia) || !presetName(settlement) {
		return "", "", fmt.Errorf("%w: preset must be <celestia network>+<settlement chain>, for example %q", ErrConfig, DefaultPreset)
	}
	return celestia, settlement, nil
}

func presetName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Status says whether a run created an item or found it.
type Status string

// The two outcomes of an item.
const (
	Created Status = "created"
	Exists  Status = "exists"
)

// Ed25519Key is one signing seed file.
type Ed25519Key struct {
	Role   string
	Path   string
	Public ed25519.PublicKey
	Status Status
}

// Account is one Celestia account kept in its own file keyring.
type Account struct {
	Role           string
	KeyringDir     string
	KeyName        string
	PassphraseFile string
	Address        string
	Status         Status
}

// Payer is the secp256k1 key that signs payments on the settlement chain.
type Payer struct {
	Path    string
	Address string
	Status  Status
}

// Result is what a run found and created. It holds no secret: paths, public
// keys and addresses only.
type Result struct {
	Home string
	// Network is the preset-filled network section, with the preset
	// versions, as the config file will record it.
	Network          config.Network
	CelestiaFaucet   string
	SettlementFaucet string
	Preflight        doctor.Report

	Agent, Gate, Executor Ed25519Key
	Recorder, Publisher   Account
	// Payer, Principal and Mandate are zero when there is no settlement
	// chain: the starter mandate limits a payment asset.
	Payer     *Payer
	Principal Ed25519Key
	Mandate   *Mandate

	AgentID, GateID string
	Allowlist       File
	ArchiveDir      string
	// Config is edicta.toml. RecorderNamespace and PublisherNamespace are
	// the ones it records; they are set only once it is on disk.
	Config                                File
	RecorderNamespace, PublisherNamespace string
	// NextCommand is what to run after init.
	NextCommand string
}

// Run checks the network, then creates whatever is missing in the home. A
// failed preflight returns ErrPreflight and touches nothing on disk. env
// carries the probes of the preflight; presets nil means the built-in ones.
func Run(ctx context.Context, c Config, env *doctor.Env, presets config.Presets) (Result, error) {
	c.ApplyDefaults()
	if err := c.ValidateBasic(); err != nil {
		return Result{}, err
	}
	if env == nil {
		return Result{}, fmt.Errorf("%w: no preflight probes", ErrConfig)
	}
	if presets == nil {
		presets = config.Builtin{}
	}
	home, err := filepath.Abs(c.Home)
	if err != nil {
		return Result{}, fmt.Errorf("%w: home directory: %w", ErrConfig, err)
	}
	res := Result{Home: home}
	cfg, err := c.network(presets, &res)
	if err != nil {
		return res, err
	}
	res.Network = cfg.Network
	if fi, err := os.Stat(home); err == nil && !fi.IsDir() {
		return res, fmt.Errorf("%w: home %s is not a directory", ErrConfig, home)
	}
	cfgPath := filepath.Join(home, config.FileName)
	old, err := existingConfig(cfgPath, presets)
	if err != nil {
		return res, err
	}
	if old != nil && (old.Network.Celestia != cfg.Network.Celestia || old.Network.Settlement != cfg.Network.Settlement) {
		return res, fmt.Errorf("%w: %s is for %s+%s: run init with that preset, or move the file away", ErrConfig, cfgPath, old.Network.Celestia, old.Network.Settlement)
	}

	res.Preflight = doctor.Run(ctx, cfg, doctor.PreflightChecks(env))
	if res.Preflight.Failed() {
		return res, fmt.Errorf("%w: fix the failed checks, then run init again", ErrPreflight)
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	if err := keyfile.MkdirSync(home); err != nil {
		return res, fmt.Errorf("init: home directory: %w", err)
	}
	// A symlinked home is the user's choice; the directory it names is
	// what others must not be able to change.
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		return res, fmt.Errorf("init: home directory: %w", err)
	}
	if err := keyfile.CheckDir(resolved); err != nil {
		return res, fmt.Errorf("init: home directory: %w", err)
	}
	// Two runs on one home would delete each other's temporary files and
	// race for the same names.
	unlock, err := keyfile.LockDir(home, LockFile)
	if err != nil {
		return res, fmt.Errorf("init: %w", err)
	}
	defer unlock()
	keys := filepath.Join(home, "keys")
	if err := keyfile.MkdirSync(keys); err != nil {
		return res, fmt.Errorf("init: keys directory: %w", err)
	}
	if err := keyfile.CheckDir(keys); err != nil {
		return res, fmt.Errorf("init: keys directory: %w", err)
	}
	if err := removeLeftovers(home, keys); err != nil {
		return res, err
	}
	seeds := []*Ed25519Key{&res.Agent, &res.Gate, &res.Executor}
	for i, role := range []string{"agent", "gate", "executor"} {
		if *seeds[i], err = ensureSeed(filepath.Join(keys, role+".ed25519"), role); err != nil {
			return res, err
		}
	}
	if res.Recorder, err = ensureAccount(home, "recorder"); err != nil {
		return res, err
	}
	if res.Publisher, err = ensureAccount(home, "publisher"); err != nil {
		return res, err
	}
	settle := cfg.Network.Settlement != config.SettlementNone
	if settle {
		p, err := ensurePayer(filepath.Join(keys, "payer.secp256k1"))
		if err != nil {
			return res, err
		}
		res.Payer = &p
		if res.Principal, err = ensureSeed(filepath.Join(keys, "principal.ed25519"), "principal"); err != nil {
			return res, err
		}
	}

	// The names already on disk win: edicta.toml first, then the mandate.
	res.AgentID, res.GateID = DefaultAgentID, "gate-"+hex.EncodeToString(res.Gate.Public[:8])
	if old != nil {
		res.AgentID = old.Agent.ID
		if old.Gate != nil {
			res.GateID = old.Gate.GateID
		}
	}
	if settle {
		m, err := ensureMandate(filepath.Join(home, MandateFile), mandateParams{
			principalPath: res.Principal.Path,
			principal:     res.Principal.Public,
			gateID:        res.GateID,
			agent:         res.Agent.Public,
			asset:         usdcAsset(cfg.Network.EVM.ChainID, cfg.Network.EVM.USDC.Address),
			perPayment:    c.MaxPerPayment,
			perHour:       c.MaxPerHour,
			now:           envNow(env),
		})
		if err != nil {
			return res, err
		}
		res.Mandate = &m
		if old == nil {
			res.GateID = m.GateID
		}
	}
	if res.Allowlist, err = ensureFile(filepath.Join(home, AllowlistFile), allowlistBytes(res.AgentID, res.Agent.Public)); err != nil {
		return res, err
	}
	res.ArchiveDir = filepath.Join(home, ArchiveDir)
	if err := keyfile.MkdirSync(res.ArchiveDir); err != nil {
		return res, fmt.Errorf("init: archive directory: %w", err)
	}

	res.Config = File{Path: cfgPath, Status: Exists}
	if old == nil {
		recNS, pubNS, err := newNamespaces()
		if err != nil {
			return res, err
		}
		b, err := c.starterConfig(&res, cfg.Network, recNS, pubNS, presets)
		if err != nil {
			return res, err
		}
		if res.Config, err = ensureFile(cfgPath, b); err != nil {
			return res, err
		}
		if res.Config.Status == Exists {
			// Another writer got there first; its namespaces are the ones
			// that count.
			if old, err = existingConfig(cfgPath, presets); err != nil {
				return res, err
			}
		} else {
			res.RecorderNamespace, res.PublisherNamespace = recNS, pubNS
		}
	}
	if old != nil {
		if old.Recorder != nil {
			res.RecorderNamespace = old.Recorder.Namespace
		}
		if old.Publisher != nil {
			res.PublisherNamespace = old.Publisher.Namespace
		}
	}
	res.NextCommand = nextCommand(cfgPath)
	return res, nil
}

func envNow(env *doctor.Env) time.Time {
	if env.Now != nil {
		return env.Now()
	}
	return time.Now()
}

func (c Config) starterConfig(res *Result, n config.Network, recNS, pubNS string, p config.Presets) ([]byte, error) {
	network, err := networkTable(n, c.Overrides)
	if err != nil {
		return nil, err
	}
	s := starterConfig{
		Network: network,
		Agent: starterAgent{
			ID: res.AgentID, KeyFile: res.Agent.Path, GateURL: "http://" + config.DefaultGateListen,
		},
		Gate: starterGate{
			GateID:        res.GateID,
			KeyFile:       res.Gate.Path,
			RegistryPath:  filepath.Join(res.Home, RegistryFile),
			AllowlistFile: res.Allowlist.Path,
			ActionTypes:   []string{X402ActionType},
			ExecutorKeys:  []string{hex.EncodeToString(res.Executor.Public)},
		},
		Recorder: starterAccount{
			KeyringDir: res.Recorder.KeyringDir, KeyName: res.Recorder.KeyName,
			PassphraseFile: res.Recorder.PassphraseFile, Namespace: recNS,
		},
		Publisher: starterAccount{
			KeyringDir: res.Publisher.KeyringDir, KeyName: res.Publisher.KeyName,
			PassphraseFile: res.Publisher.PassphraseFile, Namespace: pubNS,
		},
		Archive: starterArchive{Dir: res.ArchiveDir},
	}
	if res.Mandate != nil {
		s.Gate.MandateFile = res.Mandate.Path
	}
	if res.Payer != nil {
		s.Signer = &starterSigner{
			PinnedGateKeys: []string{hex.EncodeToString(res.Gate.Public)},
			PayerBackend:   config.BackendFile,
			PayerKeyFile:   res.Payer.Path,
			PayerAddress:   res.Payer.Address,
			Risk:           starterRisk{MaxPerPayment: c.MaxPerPayment, MaxPerHour: c.MaxPerHour},
		}
	}
	return configBytes(s, p)
}

// nextCommand is the doctor call that reads this config file.
func nextCommand(cfgPath string) string {
	if def, err := config.DefaultPath(); err == nil && def == cfgPath {
		return "edicta doctor"
	}
	return "edicta doctor --config " + shellQuote(cfgPath)
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// network builds the network section the preflight checks: the presets,
// then the overrides, then the preset defaults.
func (c Config) network(p config.Presets, res *Result) (config.Config, error) {
	celestia, settlement, err := splitPreset(c.Preset)
	if err != nil {
		return config.Config{}, err
	}
	cp, err := p.Celestia(celestia)
	if err != nil {
		return config.Config{}, err
	}
	sp, err := p.Settlement(settlement)
	if err != nil {
		return config.Config{}, err
	}
	doc := "[network]\ncelestia = " + strconv.Quote(celestia) + "\nsettlement = " + strconv.Quote(settlement) + "\n"
	cfg, err := config.Parse([]byte(doc), c.Overrides)
	if err != nil {
		return config.Config{}, err
	}
	if err := cfg.ApplyDefaults(p); err != nil {
		return config.Config{}, err
	}
	if err := cfg.Network.ValidateBasic(); err != nil {
		return config.Config{}, err
	}
	cfg.Network.CelestiaPresetVersion = cp.Version
	cfg.Network.SettlementPresetVersion = sp.Version
	res.CelestiaFaucet, res.SettlementFaucet = cp.FaucetURL, sp.FaucetURL
	return cfg, nil
}

// removeLeftovers deletes what an interrupted run left behind. Those
// temporary files hold keys whose public half was never shown.
func removeLeftovers(dirs ...string) error {
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("init: %w", err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), keyfile.TempPrefix) {
				if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
					return fmt.Errorf("init: removing a leftover temporary file: %w", err)
				}
			}
		}
	}
	return nil
}
