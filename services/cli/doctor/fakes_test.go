package doctor_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/keyfile"
	"github.com/vgonkivs/edicta/plugins/celestia/node"
	"github.com/vgonkivs/edicta/services/cli/doctor"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type fakeNet struct {
	mu      sync.Mutex
	lookup  map[string]error // host -> error
	tcp     map[string]error // host:port -> error
	tls     map[string]error
	http    map[string]doctor.Response
	httpErr map[string]error
	dialled []string
}

func newFakeNet() *fakeNet {
	return &fakeNet{lookup: map[string]error{}, tcp: map[string]error{}, tls: map[string]error{}, http: map[string]doctor.Response{}, httpErr: map[string]error{}}
}

func (n *fakeNet) LookupHost(_ context.Context, host string) ([]string, error) {
	if err := n.lookup[host]; err != nil {
		return nil, err
	}
	return []string{"192.0.2.1"}, nil
}

func (n *fakeNet) DialTCP(_ context.Context, hp string) error {
	n.mu.Lock()
	n.dialled = append(n.dialled, "tcp:"+hp)
	n.mu.Unlock()
	return n.tcp[hp]
}

func (n *fakeNet) DialTLS(_ context.Context, hp, sni string) error {
	n.mu.Lock()
	n.dialled = append(n.dialled, "tls:"+hp+":"+sni)
	n.mu.Unlock()
	return n.tls[hp]
}

func (n *fakeNet) HTTPGet(_ context.Context, u string) (doctor.Response, error) {
	if err := n.httpErr[u]; err != nil {
		return doctor.Response{}, err
	}
	if r, ok := n.http[u]; ok {
		return r, nil
	}
	if strings.HasSuffix(u, "/status") {
		return doctor.Response{Status: 200, Body: []byte(cometStatus("mocha-5", 12345, false))}, nil
	}
	if strings.HasSuffix(u, "/supported") {
		return doctor.Response{Status: 200, Body: []byte(`{"kinds":[{"x402Version":1,"scheme":"exact","network":"base-sepolia"}]}`)}, nil
	}
	return doctor.Response{Status: 200}, nil
}

func cometStatus(network string, height uint64, catching bool) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","result":{"node_info":{"network":%q},"sync_info":{"latest_block_height":"%d","catching_up":%t}}}`, network, height, catching)
}

type fakeChain struct {
	consensusID string
	consensusEr error
	head        node.Header
	headErr     error
	height      uint64
	params      node.FibreParams
	paramsErr   error
	escrow      node.Escrow
	escrowErr   error
	price       *big.Rat
	priceErr    error
	balances    map[string]uint64
	closed      bool
}

func (c *fakeChain) ConsensusChainID(context.Context) (string, error) {
	return c.consensusID, c.consensusEr
}
func (c *fakeChain) BridgeHead(context.Context) (node.Header, error) { return c.head, c.headErr }
func (c *fakeChain) LatestHeight(context.Context) (uint64, error)    { return c.height, nil }
func (c *fakeChain) FibreParams(context.Context) (node.FibreParams, error) {
	return c.params, c.paramsErr
}
func (c *fakeChain) Escrow(context.Context, string) (node.Escrow, error) {
	return c.escrow, c.escrowErr
}
func (c *fakeChain) MinGasPrice(context.Context) (*big.Rat, error) { return c.price, c.priceErr }
func (c *fakeChain) Balance(_ context.Context, addr, _ string) (uint64, error) {
	return c.balances[addr], nil
}
func (c *fakeChain) Close() error { c.closed = true; return nil }

type fakeEVM struct {
	ids      map[string]uint64
	errs     map[string]error
	balances map[string]*big.Int // by holder
	balErr   error
}

func (e *fakeEVM) ChainID(_ context.Context, u string) (uint64, error) {
	if err := e.errs[u]; err != nil {
		return 0, err
	}
	return e.ids[u], nil
}

func (e *fakeEVM) USDCBalance(_ context.Context, _, _ string, holder string) (*big.Int, error) {
	if e.balErr != nil {
		return nil, e.balErr
	}
	if b, ok := e.balances[holder]; ok {
		return b, nil
	}
	return big.NewInt(0), nil
}

type fakeClock struct {
	name string
	off  time.Duration
	err  error
}

func (c fakeClock) Name() string { return c.name }
func (c fakeClock) Offset(context.Context) (time.Duration, error) {
	return c.off, c.err
}

type fakeKeyring struct {
	err   map[string]error // by key name
	calls int
}

func (k *fakeKeyring) Address(_ context.Context, _, name, _ string) (string, error) {
	k.calls++
	if err := k.err[name]; err != nil {
		return "", err
	}
	return "celestia1" + name, nil
}

type fakeSigner struct {
	info SignerInfoT
	err  error
}

// SignerInfoT aliases the doctor type for brevity.
type SignerInfoT = doctor.SignerInfo

func (s fakeSigner) Info(context.Context, string) (doctor.SignerInfo, error) { return s.info, s.err }

type fakeSessions struct {
	supported bool
	slack     uint64
	delay     uint64
	has       bool
}

func (s fakeSessions) Supported() bool                                  { return s.supported }
func (s fakeSessions) MinPublishSlackBlocks() uint64                    { return s.slack }
func (s fakeSessions) MaxDelay(*policy.Mandate) (delay uint64, ok bool) { return s.delay, s.has }

// stack is a healthy self-hosted setup on disk plus the fakes that answer for
// it. Tests change one thing and look at one check.
type stack struct {
	t     *testing.T
	dir   string
	cfg   config.Config
	env   *doctor.Env
	net   *fakeNet
	chain *fakeChain
	evm   *fakeEVM
	kr    *fakeKeyring

	gatePub, agentPub, execPub ed25519.PublicKey
	payer                      string
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, data, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func newStack(t *testing.T) *stack {
	t.Helper()
	dir := t.TempDir()
	s := &stack{t: t, dir: dir}
	p := func(parts ...string) string { return filepath.Join(append([]string{dir}, parts...)...) }

	var err error
	s.agentPub, err = keyfile.NewSeed(p("keys", "agent.ed25519"))
	require.NoError(t, err)
	s.gatePub, err = keyfile.NewSeed(p("keys", "gate.ed25519"))
	require.NoError(t, err)
	s.execPub, err = keyfile.NewSeed(p("keys", "executor.ed25519"))
	require.NoError(t, err)
	principalPub, principalPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	scalar := make([]byte, 32)
	scalar[31] = 7
	mustWrite(t, p("keys", "payer.secp256k1"), scalar, 0o600)
	s.payer, err = doctor.PayerAddress(p("keys", "payer.secp256k1"))
	require.NoError(t, err)

	mustWrite(t, p("recorder.pass"), []byte("pass-recorder\n"), 0o600)
	mustWrite(t, p("publisher.pass"), []byte("pass-publisher\n"), 0o600)
	mustWrite(t, p("agents.toml"), []byte(fmt.Sprintf("[[agents]]\nagent_id = \"agent-1\"\npubkey = %q\n", hex.EncodeToString(s.agentPub))), 0o600)

	m := &policy.Mandate{
		Format: 1, Principal: principalPub, GateID: "gate-1", Agents: [][]byte{s.agentPub},
		NotBefore: uint64(testNow.Add(-time.Hour).Unix()), NotAfter: uint64(testNow.Add(30 * 24 * time.Hour).Unix()),
		Kinds: []string{"x402-payment"},
		Assets: []policy.AssetRule{{
			Asset: "eip155:84532/erc20:0x036cbd53842c5426634e7929541ec2318f3dcf7e", Scale: 6,
			PerActionMax: policy.AmountFromUint64(1_000_000),
			Periods:      []policy.PeriodLimit{{Hours: 1, Max: policy.AmountFromUint64(10_000_000)}},
		}},
		MandateID: bytes16(), Version: 1,
	}
	signed, _, err := policy.SignMandate(principalPriv, m)
	require.NoError(t, err)
	mustWrite(t, p("mandate.cbor"), signed, 0o600)

	ns := func(b byte) string {
		return strings.Repeat("00", 19) + hex.EncodeToString([]byte{b}) + strings.Repeat("00", 9)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
[network]
celestia = "mocha"
settlement = "base-sepolia"

[agent]
id = "agent-1"
key_file = %q

[gate]
gate_id = "gate-1"
key_file = %q
registry_path = %q
allowlist_file = %q
mandate_file = %q
action_types = ["application/vnd.edicta.x402.exact-evm.v1+cbor"]
executor_keys = [%q]

[recorder]
keyring_dir = %q
key_name = "recorder"
passphrase_file = %q
namespace = %q

[publisher]
keyring_dir = %q
key_name = "publisher"
passphrase_file = %q
namespace = %q

[archive]
dir = %q

[signer]
pinned_gate_keys = [%q]
payer_key_file = %q
[signer.risk]
max_per_payment = 1000000
max_per_hour = 10000000
`, p("keys", "agent.ed25519"), p("keys", "gate.ed25519"), p("registry.db"), p("agents.toml"), p("mandate.cbor"),
		hex.EncodeToString(s.execPub), p("keyring", "recorder"), p("recorder.pass"), ns(0xab),
		p("keyring", "publisher"), p("publisher.pass"), ns(0xcd), p("archive"),
		hex.EncodeToString(s.gatePub), p("keys", "payer.secp256k1"))), nil)
	require.NoError(t, err)
	require.NoError(t, cfg.ApplyDefaults(nil))
	require.NoError(t, cfg.ValidateBasic())
	s.cfg = cfg

	s.net = newFakeNet()
	s.chain = &fakeChain{
		consensusID: "mocha-5",
		head:        node.Header{ChainID: "mocha-5", Height: 12345, Time: testNow.Add(-3 * time.Second), AppVersion: 10},
		height:      12346,
		params:      node.FibreParams{RetentionS: 14400},
		escrow:      node.Escrow{AvailableUtia: 100_000_000},
		price:       big.NewRat(2, 1000),
		balances:    map[string]uint64{"celestia1recorder": 5_000_000_000, "celestia1publisher": 5_000_000_000},
	}
	s.evm = &fakeEVM{
		ids:      map[string]uint64{},
		errs:     map[string]error{},
		balances: map[string]*big.Int{s.payer: big.NewInt(25_000_000)},
	}
	for _, u := range cfg.Network.EVM.RPC {
		s.evm.ids[u] = 84532
	}
	s.kr = &fakeKeyring{err: map[string]error{}}
	s.env = &doctor.Env{
		Now:       func() time.Time { return testNow },
		Net:       s.net,
		OpenChain: func(context.Context, config.Network) (doctor.Chain, error) { return s.chain, nil },
		EVM:       s.evm,
		Clocks:    []doctor.TimeSource{fakeClock{name: "ntp-a", off: 20 * time.Millisecond}, fakeClock{name: "ntp-b", off: -30 * time.Millisecond}},
		Keyring:   s.kr,
		Signer: fakeSigner{info: doctor.SignerInfo{
			PinnedGateKeys: []string{hex.EncodeToString(s.gatePub)},
			ChainID:        84532,
			USDC:           cfg.Network.EVM.USDC.Address,
			PayerAddress:   s.payer,
		}},
		Sessions: fakeSessions{},
	}
	return s
}

func bytes16() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// run runs every check and returns the report by check name.
func (s *stack) run() map[string]doctor.Item {
	s.t.Helper()
	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{Presets: "mocha v1, base-sepolia v1"}))
	out := map[string]doctor.Item{}
	for _, it := range rep.Items {
		out[it.Name] = it
	}
	return out
}

var errBoom = errors.New("boom")
