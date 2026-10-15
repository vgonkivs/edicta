package initcmd_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/initcmd"
	"github.com/vgonkivs/edicta/celestia/keyfile"
	"github.com/vgonkivs/edicta/celestia/node"
)

var testNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

type fakeNet struct{ comet string }

func (fakeNet) LookupHost(context.Context, string) ([]string, error) {
	return []string{"192.0.2.1"}, nil
}
func (fakeNet) DialTCP(context.Context, string) error         { return nil }
func (fakeNet) DialTLS(context.Context, string, string) error { return nil }
func (n fakeNet) HTTPGet(_ context.Context, u string) (doctor.Response, error) {
	if strings.HasSuffix(u, "/status") {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","result":{"node_info":{"network":%q},"sync_info":{"latest_block_height":"100","catching_up":false}}}`, n.comet)
		return doctor.Response{Status: 200, Body: []byte(body)}, nil
	}
	return doctor.Response{Status: 200}, nil
}

type fakeChain struct{ id string }

func (c fakeChain) ConsensusChainID(context.Context) (string, error) { return c.id, nil }
func (c fakeChain) BridgeHead(context.Context) (node.Header, error) {
	return node.Header{ChainID: c.id, Height: 100, Time: testNow, AppVersion: node.DefaultMinAppVersion}, nil
}
func (fakeChain) LatestHeight(context.Context) (uint64, error) { return 100, nil }
func (fakeChain) FibreParams(context.Context) (node.FibreParams, error) {
	return node.FibreParams{}, node.ErrNotFound
}
func (fakeChain) Escrow(context.Context, string) (node.Escrow, error) { return node.Escrow{}, nil }
func (fakeChain) MinGasPrice(context.Context) (*big.Rat, error)      { return big.NewRat(1, 1000), nil }
func (fakeChain) Balance(context.Context, string, string) (uint64, error) {
	return 0, nil
}
func (fakeChain) Close() error { return nil }

type fakeEVM struct{ id uint64 }

func (e fakeEVM) ChainID(context.Context, string) (uint64, error) { return e.id, nil }
func (fakeEVM) USDCBalance(context.Context, string, string, string) (*big.Int, error) {
	return big.NewInt(0), nil
}

// healthyEnv answers every preflight probe as a mocha + base-sepolia stack
// would; chainID changes what the Celestia nodes claim to be.
func healthyEnv(chainID string) *doctor.Env {
	return &doctor.Env{
		Now: func() time.Time { return testNow },
		Net: fakeNet{comet: chainID},
		OpenChain: func(context.Context, config.Network) (doctor.Chain, error) {
			return fakeChain{id: chainID}, nil
		},
		EVM: fakeEVM{id: 84532},
	}
}

func run(t *testing.T, home string, env *doctor.Env) (initcmd.Result, error) {
	t.Helper()
	return initcmd.Run(context.Background(), initcmd.Config{Home: home}, env, nil)
}

// tree maps every path under root to its bytes; a directory maps to nil.
func tree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = nil
			return nil
		}
		b, err := os.ReadFile(p)
		out[rel] = b
		return err
	})
	require.NoError(t, err)
	return out
}

func TestEmptyHomeCreatesEveryKey(t *testing.T) {
	home := filepath.Join(t.TempDir(), "edicta")
	res, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.False(t, res.Preflight.Failed())

	for _, k := range []initcmd.Ed25519Key{res.Agent, res.Gate, res.Executor} {
		assert.Equal(t, initcmd.Created, k.Status, k.Role)
		priv, err := keyfile.ReadSeed(k.Path, k.Role)
		require.NoError(t, err)
		assert.Equal(t, k.Public, priv.Public(), k.Role)
	}
	assert.NotEqual(t, res.Agent.Public, res.Gate.Public)
	assert.NotEqual(t, res.Gate.Public, res.Executor.Public)

	for _, a := range []initcmd.Account{res.Recorder, res.Publisher} {
		assert.Equal(t, initcmd.Created, a.Status, a.Role)
		assert.True(t, strings.HasPrefix(a.Address, "celestia1"), a.Address)
		assert.FileExists(t, a.PassphraseFile)
	}
	assert.NotEqual(t, res.Recorder.Address, res.Publisher.Address)

	require.NotNil(t, res.Payer)
	assert.Equal(t, initcmd.Created, res.Payer.Status)
	addr, err := doctor.PayerAddress(res.Payer.Path)
	require.NoError(t, err)
	assert.Equal(t, addr, res.Payer.Address)

	require.NoError(t, config.CheckNamespace("recorder", res.RecorderNamespace))
	require.NoError(t, config.CheckNamespace("publisher", res.PublisherNamespace))
	assert.NotEqual(t, res.RecorderNamespace, res.PublisherNamespace)

	assert.Equal(t, "mocha-5", res.Network.ChainID)
	assert.Equal(t, uint64(84532), res.Network.EVM.ChainID)
	assert.NotZero(t, res.Network.CelestiaPresetVersion)
	assert.NotZero(t, res.Network.SettlementPresetVersion)

	// Every file is 0600 and every directory 0700; no temporary file stays.
	err = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		assert.False(t, strings.HasPrefix(d.Name(), keyfile.TempPrefix), p)
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		want := os.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		assert.Equal(t, want, fi.Mode().Perm(), p)
		return nil
	})
	require.NoError(t, err)
}

func TestRerunOverwritesNothing(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	before := tree(t, home)

	second, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, before, tree(t, home))

	for _, k := range []initcmd.Ed25519Key{second.Agent, second.Gate, second.Executor} {
		assert.Equal(t, initcmd.Exists, k.Status, k.Role)
	}
	assert.Equal(t, initcmd.Exists, second.Recorder.Status)
	assert.Equal(t, initcmd.Exists, second.Publisher.Status)
	assert.Equal(t, initcmd.Exists, second.Payer.Status)
	assert.Equal(t, first.Agent.Public, second.Agent.Public)
	assert.Equal(t, first.Gate.Public, second.Gate.Public)
	assert.Equal(t, first.Executor.Public, second.Executor.Public)
	assert.Equal(t, first.Recorder.Address, second.Recorder.Address)
	assert.Equal(t, first.Publisher.Address, second.Publisher.Address)
	assert.Equal(t, first.Payer.Address, second.Payer.Address)

	var out bytes.Buffer
	require.NoError(t, second.WriteText(&out))
	assert.NotContains(t, out.String(), string(initcmd.Created))
}

func TestFailedPreflightWritesNothing(t *testing.T) {
	cases := map[string]*doctor.Env{
		"wrong celestia chain": healthyEnv("celestia"),
		"no probes":            {},
		"node down": func() *doctor.Env {
			e := healthyEnv("mocha-5")
			e.OpenChain = func(context.Context, config.Network) (doctor.Chain, error) {
				return nil, errors.New("connection refused")
			}
			return e
		}(),
		"wrong settlement chain": func() *doctor.Env {
			e := healthyEnv("mocha-5")
			e.EVM = fakeEVM{id: 1}
			return e
		}(),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			home := filepath.Join(parent, "edicta")
			_, err := run(t, home, env)
			require.ErrorIs(t, err, initcmd.ErrPreflight)
			assert.NoDirExists(t, home)

			// An existing empty home stays empty.
			require.NoError(t, os.Mkdir(home, 0o700))
			_, err = run(t, home, env)
			require.ErrorIs(t, err, initcmd.ErrPreflight)
			entries, err := os.ReadDir(home)
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

func TestPartialHomeCompletesOnlyTheMissingPieces(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	before := tree(t, home)

	require.NoError(t, os.Remove(first.Gate.Path))
	require.NoError(t, os.RemoveAll(first.Publisher.KeyringDir))
	require.NoError(t, os.Remove(first.Payer.Path))
	// What an interrupted write leaves behind is cleaned up.
	leftover := filepath.Join(home, "keys", keyfile.TempPrefix+"123")
	require.NoError(t, os.WriteFile(leftover, []byte("partial"), 0o600))

	second, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	assert.Equal(t, initcmd.Exists, second.Agent.Status)
	assert.Equal(t, initcmd.Created, second.Gate.Status)
	assert.Equal(t, initcmd.Exists, second.Executor.Status)
	assert.Equal(t, initcmd.Exists, second.Recorder.Status)
	assert.Equal(t, initcmd.Created, second.Publisher.Status)
	assert.Equal(t, initcmd.Created, second.Payer.Status)
	assert.NoFileExists(t, leftover)

	after := tree(t, home)
	for p, b := range before {
		changed := strings.HasPrefix(p, filepath.Base(first.Publisher.KeyringDir)) ||
			p == filepath.Join("keys", "gate.ed25519") || p == filepath.Join("keys", "payer.secp256k1")
		if !changed {
			assert.Equal(t, b, after[p], p)
		}
	}
	assert.NotEqual(t, first.Gate.Public, second.Gate.Public)
	assert.Equal(t, first.Recorder.Address, second.Recorder.Address)
}

func TestUnusableExistingKeyIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	bad := filepath.Join(home, "keys", "gate.ed25519")
	require.NoError(t, os.MkdirAll(filepath.Dir(bad), 0o700))
	require.NoError(t, os.WriteFile(bad, []byte("short"), 0o600))

	_, err := run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrExisting)
	got, err := os.ReadFile(bad)
	require.NoError(t, err)
	assert.Equal(t, "short", string(got))
}

func TestKeyringWithWrongPassphraseIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	first, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(first.Recorder.PassphraseFile))
	require.NoError(t, os.WriteFile(first.Recorder.PassphraseFile, []byte("not-the-passphrase\n"), 0o600))
	before := tree(t, home)

	_, err = run(t, home, healthyEnv("mocha-5"))
	require.ErrorIs(t, err, initcmd.ErrExisting)
	assert.Equal(t, before, tree(t, home))
}

func TestNoSecretInOutput(t *testing.T) {
	home := t.TempDir()
	res, err := run(t, home, healthyEnv("mocha-5"))
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, res.WriteText(&out))
	js, err := json.Marshal(res)
	require.NoError(t, err)
	printed := out.String() + string(js) + fmt.Sprintf("%+v %#v", res, res)

	var secrets [][]byte
	for _, p := range []string{res.Agent.Path, res.Gate.Path, res.Executor.Path, res.Payer.Path} {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		secrets = append(secrets, b)
	}
	for _, p := range []string{res.Recorder.PassphraseFile, res.Publisher.PassphraseFile} {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		secrets = append(secrets, bytes.TrimSuffix(b, []byte("\n")))
	}
	for _, s := range secrets {
		for _, form := range []string{hex.EncodeToString(s), strings.ToUpper(hex.EncodeToString(s)), base64.StdEncoding.EncodeToString(s), string(s)} {
			assert.NotContains(t, printed, form)
		}
	}

	assert.Contains(t, out.String(), res.Recorder.Address)
	assert.Contains(t, out.String(), res.Publisher.Address)
	assert.Contains(t, out.String(), res.Payer.Address)
	assert.Contains(t, out.String(), "fund these addresses")
}

func TestNoSettlementMeansNoPayer(t *testing.T) {
	home := t.TempDir()
	res, err := initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: "mocha+none"}, healthyEnv("mocha-5"), nil)
	require.NoError(t, err)
	assert.Nil(t, res.Payer)
	assert.NoFileExists(t, filepath.Join(home, "keys", "payer.secp256k1"))
}

func TestOverridesReachThePreflight(t *testing.T) {
	var seen config.Network
	env := healthyEnv("mocha-5")
	env.OpenChain = func(_ context.Context, n config.Network) (doctor.Chain, error) {
		seen = n
		return fakeChain{id: "mocha-5"}, nil
	}
	_, err := initcmd.Run(context.Background(), initcmd.Config{
		Home:      t.TempDir(),
		Overrides: map[string]string{"network.consensus_grpc.addr": "localhost:9090"},
	}, env, nil)
	require.NoError(t, err)
	assert.Equal(t, "localhost:9090", seen.ConsensusGRPC.Addr)
}

func TestConfigValidateBasic(t *testing.T) {
	good := initcmd.Config{Home: "/h"}
	good.ApplyDefaults()
	require.NoError(t, good.ValidateBasic())
	assert.Equal(t, initcmd.DefaultPreset, good.Preset)

	for name, c := range map[string]initcmd.Config{
		"no home":           {Preset: initcmd.DefaultPreset},
		"no plus":           {Home: "/h", Preset: "mocha"},
		"empty half":        {Home: "/h", Preset: "mocha+"},
		"bad characters":    {Home: "/h", Preset: "mocha+Base Sepolia"},
		"non-network key":   {Home: "/h", Preset: initcmd.DefaultPreset, Overrides: map[string]string{"recorder.key_name": "x"}},
		"network by --set":  {Home: "/h", Preset: initcmd.DefaultPreset, Overrides: map[string]string{"network.celestia": "custom"}},
		"bare network key":  {Home: "/h", Preset: initcmd.DefaultPreset, Overrides: map[string]string{"network.": "x"}},
		"settlement by set": {Home: "/h", Preset: initcmd.DefaultPreset, Overrides: map[string]string{"network.settlement": "none"}},
	} {
		assert.ErrorIs(t, c.ValidateBasic(), initcmd.ErrConfig, name)
	}
}

func TestUnavailablePresetWritesNothing(t *testing.T) {
	home := filepath.Join(t.TempDir(), "edicta")
	_, err := initcmd.Run(context.Background(), initcmd.Config{Home: home, Preset: "celestia-mainnet+base"}, healthyEnv("mocha-5"), nil)
	require.ErrorIs(t, err, config.ErrPreset)
	assert.NoDirExists(t, home)
}
