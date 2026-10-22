// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package initcmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/plugins/banksend/bankaction"
)

// The dev chains. Their ids exist only in builds with the edictadev tag, so a
// production binary never sees a configuration for them as anything but an
// unknown custom chain.
const (
	DevCelestiaChainID = "edicta-dev-1"
	DevEdenChainID     = uint64(31337)
	DevGateID          = "edicta-dev-gate"
	// DevNamespaceID is the ten id bytes of the dev Recorder namespace.
	DevNamespaceID = "edictadev1"
)

// Files the dev init writes in the home, next to the ones the starter writes.
const (
	DevMarkerFile     = "DEV-ONLY.txt"
	DevEdictadFile    = "edictad.toml"
	DevTokenFile      = "api.token"
	DevAccountsFile   = "accounts.env"
	devPayerKey       = "payer.secp256k1"
	devFacilitatorKey = "facilitator.secp256k1"
)

const devMarker = `DEV ONLY. Every key in this directory was generated for the local docker
compose stack. The Celestia chain id is edicta-dev-1 and the Eden chain id is
31337. Never fund these keys on a public network and never copy them to one.
`

// DevConfig is what the dev init needs to know about the stack.
type DevConfig struct {
	Home string
	// Endpoints as the containers reach them.
	BridgeAddr, ConsensusGRPCAddr, CometRPC, EdenRPC string
	// FastDelay is the fast_mode_max_delay of the dev mandate, in blocks.
	FastDelay uint64
	// Now stamps the mandate; zero means time.Now.
	Now time.Time
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *DevConfig) ApplyDefaults() {
	if c.BridgeAddr == "" {
		c.BridgeAddr = "http://celestia-bridge:26658"
	}
	if c.ConsensusGRPCAddr == "" {
		c.ConsensusGRPCAddr = "celestia:9090"
	}
	if c.CometRPC == "" {
		c.CometRPC = "http://celestia:26657"
	}
	if c.EdenRPC == "" {
		c.EdenRPC = "http://eden-reth:8545"
	}
	if c.FastDelay == 0 {
		c.FastDelay = 20
	}
	if c.Now.IsZero() {
		c.Now = time.Now()
	}
}

// ValidateBasic checks the stateless fields.
func (c DevConfig) ValidateBasic() error {
	if c.Home == "" {
		return fmt.Errorf("%w: home directory is required", ErrConfig)
	}
	if c.FastDelay < 4 || c.FastDelay > 100 {
		return fmt.Errorf("%w: fast delay must be 4..100 blocks", ErrConfig)
	}
	return nil
}

// DevResult holds public facts only.
type DevResult struct {
	Home                            string
	Agent, Gate, Executor           Ed25519Key
	Principal                       Ed25519Key
	Recorder, Funder                Account
	Payer, Facilitator              Payer
	Namespace                       string
	MandateHash                     string
	EdictadConfig, EdictaConfig     File
	AccountsFile, TokenFile, Marker File
}

// DevNamespace is the fixed dev Recorder namespace, hex.
func DevNamespace() string {
	ns := make([]byte, namespaceLen)
	copy(ns[namespaceLen-len(DevNamespaceID):], DevNamespaceID)
	return hex.EncodeToString(ns)
}

// RunDev creates the dev keys, the mandate that consents to fast mode, the
// allowlist, edictad.toml (fast mode on a celestia_blob chain), edicta.toml
// for the command line tools, and accounts.env with the public addresses the
// genesis files need. It never overwrites a file, so a re-run reuses the
// keys. No network is touched.
func RunDev(c DevConfig) (DevResult, error) {
	c.ApplyDefaults()
	if err := c.ValidateBasic(); err != nil {
		return DevResult{}, err
	}
	home, err := filepath.Abs(c.Home)
	if err != nil {
		return DevResult{}, fmt.Errorf("%w: home directory: %w", ErrConfig, err)
	}
	if err := refuseForeignHome(home); err != nil {
		return DevResult{}, err
	}
	if err := keyfile.MkdirSync(home); err != nil {
		return DevResult{}, fmt.Errorf("init: home directory: %w", err)
	}
	root, err := keyfile.ResolveDir(home)
	if err != nil {
		return DevResult{}, fmt.Errorf("init: home directory: %w", err)
	}
	unlock, err := keyfile.LockDir(root, LockFile)
	if err != nil {
		return DevResult{}, fmt.Errorf("init: %w", err)
	}
	defer unlock()

	res := DevResult{Home: root, Namespace: DevNamespace()}
	keys := filepath.Join(root, "keys")
	if err := keyfile.MkdirSync(keys); err != nil {
		return res, fmt.Errorf("init: keys directory: %w", err)
	}
	if err := keyfile.CheckDir(keys); err != nil {
		return res, fmt.Errorf("init: keys directory: %w", err)
	}
	if err := removeLeftovers(root, keys); err != nil {
		return res, err
	}
	if res.Marker, err = ensureFile(filepath.Join(root, DevMarkerFile), []byte(devMarker)); err != nil {
		return res, err
	}
	seeds := []*Ed25519Key{&res.Agent, &res.Gate, &res.Executor, &res.Principal}
	for i, role := range []string{"agent", "gate", "executor", "principal"} {
		if *seeds[i], err = ensureSeed(filepath.Join(keys, role+".ed25519"), role); err != nil {
			return res, err
		}
	}
	if err := checkRoles(res.Agent, res.Gate, res.Executor, res.Principal); err != nil {
		return res, err
	}
	if res.Recorder, err = ensureAccount(root, "recorder"); err != nil {
		return res, err
	}
	if res.Funder, err = ensureAccount(root, "funder"); err != nil {
		return res, err
	}
	if res.Payer, err = ensurePayer(filepath.Join(keys, devPayerKey)); err != nil {
		return res, err
	}
	if res.Facilitator, err = ensurePayer(filepath.Join(keys, devFacilitatorKey)); err != nil {
		return res, err
	}

	mandatePath := filepath.Join(root, MandateFile)
	m, sm, err := readMandate(mandatePath)
	if err != nil {
		return res, err
	}
	if sm == nil {
		if res.Principal.Status != Created {
			return res, fmt.Errorf("%w: the principal key %s already exists and is not signed with: remove it or use a fresh dev home", ErrExisting, res.Principal.Path)
		}
		b, err := signDevMandate(res, keys, c)
		if err != nil {
			return res, err
		}
		if err := keyfile.WriteNew(mandatePath, b); err != nil && !errors.Is(err, keyfile.ErrExists) {
			return res, fmt.Errorf("init: mandate: %w", err)
		}
		if m, sm, err = readMandate(mandatePath); err != nil {
			return res, err
		}
	}
	if sm.Mandate.GateID != DevGateID {
		return res, fmt.Errorf("%w: mandate %s is bound to gate %q, not the dev gate", ErrExisting, mandatePath, sm.Mandate.GateID)
	}
	res.MandateHash = m.Hash

	if _, err = ensureFile(filepath.Join(root, AllowlistFile), allowlistBytes(DefaultAgentID, res.Agent.Public)); err != nil {
		return res, err
	}
	archive := filepath.Join(root, ArchiveDir)
	if err := keyfile.MkdirSync(archive); err != nil {
		return res, fmt.Errorf("init: archive directory: %w", err)
	}
	if res.TokenFile, err = ensureToken(filepath.Join(root, DevTokenFile)); err != nil {
		return res, err
	}

	edictadTOML, err := devEdictadConfig(root, res, c)
	if err != nil {
		return res, err
	}
	if res.EdictadConfig, err = ensureFile(filepath.Join(root, DevEdictadFile), edictadTOML); err != nil {
		return res, err
	}
	edictaTOML, err := devEdictaConfig(root, res, c)
	if err != nil {
		return res, err
	}
	if res.EdictaConfig, err = ensureFile(filepath.Join(root, config.FileName), edictaTOML); err != nil {
		return res, err
	}
	accounts := fmt.Sprintf("RECORDER_ADDRESS=%s\nFUNDER_ADDRESS=%s\nPAYER_ADDRESS=%s\nFACILITATOR_ADDRESS=%s\n",
		res.Recorder.Address, res.Funder.Address, res.Payer.Address, res.Facilitator.Address)
	if res.AccountsFile, err = ensureFile(filepath.Join(root, DevAccountsFile), []byte(accounts)); err != nil {
		return res, err
	}
	return res, nil
}

// ensureToken creates a random bearer token file once.
func ensureToken(path string) (File, error) {
	b, err := keyfile.RandomBytes(24)
	if err != nil {
		return File{Path: path}, err
	}
	return ensureFile(path, []byte(hex.EncodeToString(b)+"\n"))
}

// signDevMandate signs the dev mandate: Celestia bank sends in utia on the dev
// chain, the stand-in for the Eden escrow action until its extractor exists,
// with fast mode consented to.
func signDevMandate(res DevResult, keys string, c DevConfig) ([]byte, error) {
	id, err := keyfile.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	now := c.Now.Unix()
	const perAction = 1_000_000_000
	m := &policy.Mandate{
		Format:    1,
		Principal: res.Principal.Public,
		GateID:    DevGateID,
		Agents:    [][]byte{res.Agent.Public},
		NotBefore: uint64(now - int64(mandateBackdate/time.Second)),
		NotAfter:  uint64(now + int64(mandateLifetime/time.Second)),
		Kinds:     []string{"transfer"},
		Assets: []policy.AssetRule{{
			Asset:        "cosmos:" + DevCelestiaChainID + "/utia",
			Scale:        6,
			PerActionMax: policy.AmountFromUint64(perAction),
		}},
		MandateID:        id,
		Version:          1,
		FastModeMaxDelay: c.FastDelay,
	}
	priv, err := keyfile.ReadSeed(filepath.Join(keys, "principal.ed25519"), "principal")
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

func devEdictadConfig(root string, res DevResult, c DevConfig) ([]byte, error) {
	q := strconv.Quote
	b := fmt.Appendf(nil, `# DEV ONLY. Written by edicta-devinit; see DEV-ONLY.txt. Fast mode needs this
# legacy layout: edicta.toml cannot enable it yet.

[network]
da = "celestia_blob"
chain_id = %s
min_app_version = 10
max_app_version = 10

[network.bridge]
addr = %s
tls = false

[network.consensus_grpc]
addr = %s
tls = false

[archive]
dir = %s

[recorder]
enabled = true
namespace = %s
keyring_dir = %s
keyring_backend = "file"
key_name = %s
passphrase_file = %s
max_blob_bytes = 65536
fast = true
fast_dedicated_account = true
fast_timeout_blocks = 100

[recorder.quota]
blobs_per_hour = 3600
bytes_per_day = 268435456

[gate]
gate_id = %s
key_file = %s
registry_path = %s
action_types = [%s]
allowlist_file = %s
executor_keys = [%s]
anchor_verifier = "self"

[gate.fast]
enabled = true
own_node = true
intent_source = "archive"
pending_namespaces = [%s]

[policy]
mandate_file = %s

[http]
listen = "0.0.0.0:8080"
authorize_token_file = %s
record_token_file = %s
allow_insecure = true
`,
		q(DevCelestiaChainID), q(c.BridgeAddr), q(c.ConsensusGRPCAddr),
		q(filepath.Join(root, ArchiveDir)),
		q(res.Namespace), q(res.Recorder.KeyringDir), q(res.Recorder.KeyName), q(res.Recorder.PassphraseFile),
		q(DevGateID), q(res.Gate.Path), q(filepath.Join(root, RegistryFile)), q(bankaction.ActionType),
		q(filepath.Join(root, AllowlistFile)), q(hex.EncodeToString(res.Executor.Public)),
		q(res.Namespace), q(filepath.Join(root, MandateFile)),
		q(res.TokenFile.Path), q(res.TokenFile.Path))
	if _, err := edictad.ParseConfig(b); err != nil {
		return nil, fmt.Errorf("init: the dev edictad.toml does not load: %w", err)
	}
	return b, nil
}

// devEdictaConfig is edicta.toml for the command line tools and the signer:
// the dev Celestia chain and the dev Eden chain as a custom settlement.
func devEdictaConfig(root string, res DevResult, c DevConfig) ([]byte, error) {
	s := devEdictaTOML{
		Network: map[string]any{
			"celestia":   config.Custom,
			"settlement": config.Custom,
			"chain_id":   DevCelestiaChainID,
			"bridge":     map[string]any{"addr": c.BridgeAddr},
			"consensus_grpc": map[string]any{
				"addr": c.ConsensusGRPCAddr,
			},
			"comet_rpc": []string{c.CometRPC},
			"evm": map[string]any{
				"chain_id": int64(DevEdenChainID),
				"rpc":      []string{c.EdenRPC},
				// Placeholder: the dev Eden chain has no USDC. The escrow
				// profile replaces the payment asset.
				"usdc": map[string]any{
					"address": "0x" + strings.Repeat("00", 19) + "01",
					"name":    "DEV-PLACEHOLDER", "version": "1",
				},
			},
		},
		Agent: starterAgent{ID: DefaultAgentID, KeyFile: res.Agent.Path, GateURL: "http://edictad:8080"},
		Gate: starterGate{
			GateID: DevGateID, KeyFile: res.Gate.Path, RegistryPath: filepath.Join(root, RegistryFile),
			AllowlistFile: filepath.Join(root, AllowlistFile), MandateFile: filepath.Join(root, MandateFile),
			ActionTypes:  []string{bankaction.ActionType},
			ExecutorKeys: []string{hex.EncodeToString(res.Executor.Public)},
		},
		Recorder: starterAccount{
			KeyringDir: res.Recorder.KeyringDir, KeyName: res.Recorder.KeyName,
			PassphraseFile: res.Recorder.PassphraseFile, Namespace: res.Namespace,
		},
		Archive: starterArchive{Dir: filepath.Join(root, ArchiveDir)},
		Signer: &starterSigner{
			PinnedGateKeys: []string{hex.EncodeToString(res.Gate.Public)},
			PayerBackend:   config.BackendFile,
			PayerKeyFile:   filepath.Join(root, "keys", devPayerKey),
			PayerAddress:   res.Payer.Address,
			Risk:           starterRisk{MaxPerPayment: DefaultMaxPerPayment, MaxPerHour: DefaultMaxPerHour},
		},
	}
	body, err := toml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("init: edicta.toml: %w", err)
	}
	b := append([]byte("# DEV ONLY. Written by edicta-devinit; see DEV-ONLY.txt.\n\n"), body...)
	cfg, err := config.Parse(b, nil)
	if err == nil {
		err = cfg.ApplyDefaults(config.Builtin{})
	}
	if err == nil {
		err = cfg.ValidateBasic()
	}
	if err != nil {
		return nil, fmt.Errorf("init: the dev edicta.toml does not validate: %w", err)
	}
	return b, nil
}

// devEdictaTOML is starterConfig without the publisher, which the dev stack
// does not run.
type devEdictaTOML struct {
	Network  map[string]any `toml:"network"`
	Agent    starterAgent   `toml:"agent"`
	Gate     starterGate    `toml:"gate"`
	Recorder starterAccount `toml:"recorder"`
	Archive  starterArchive `toml:"archive"`
	Signer   *starterSigner `toml:"signer,omitempty"`
}

// refuseForeignHome refuses a non-empty directory that is not a dev home, so
// a production home is never written into.
func refuseForeignHome(home string) error {
	entries, err := os.ReadDir(home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("init: home directory: %w", err)
	case len(entries) == 0:
		return nil
	}
	if _, err := os.Lstat(filepath.Join(home, DevMarkerFile)); err != nil {
		return fmt.Errorf("%w: %s is not empty and has no %s: the dev init writes only into its own home", ErrConfig, home, DevMarkerFile)
	}
	return nil
}
