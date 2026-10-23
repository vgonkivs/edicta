// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/signer/signerd"
)

// payerKey writes a payer key file derived from label and returns its path
// and address.
func payerKey(t *testing.T, dir, label string) (string, [20]byte) {
	t.Helper()
	k := sha256.Sum256([]byte("signerd payer " + label))
	var s secp256k1.ModNScalar
	s.SetByteSlice(k[:])
	return writeFile(t, dir, label+".key", k[:], 0o600), edenescrow.Address(secp256k1.NewPrivateKey(&s).PubKey())
}

type payerEntry struct {
	agent, file string
	addr        [20]byte
}

func (p payerEntry) toml() string {
	return fmt.Sprintf("\n[[chain.payer]]\nagent_pubkey = %q\nkey_file = %q\naddress = \"0x%x\"\n", p.agent, p.file, p.addr)
}

// twoAgentsText serves agents a and b on mainnet and testnet, each with its
// own payer per chain.
func twoAgentsText(t *testing.T) (string, map[string]payerEntry) {
	t.Helper()
	f, _ := newFiles(t)
	dir := filepath.Dir(f.payer)
	a, b := edPub(sha256.Sum256([]byte("agent a"))), edPub(sha256.Sum256([]byte("agent b")))
	gate := edPub(sha256.Sum256([]byte("gate")))
	ps := map[string]payerEntry{}
	for _, n := range []string{"a714", "b714", "atest", "btest"} {
		file, addr := payerKey(t, dir, n)
		agent := a
		if n[0] == 'b' {
			agent = b
		}
		ps[n] = payerEntry{agent: agent, file: file, addr: addr}
	}
	chain := func(id uint64, x, y payerEntry) string {
		return fmt.Sprintf(`
[[chain]]
chain_id = %d
rpc = "http://127.0.0.1:1"
facilitators = ["0xfac1117a70400000000000000000000000000000"]
max_refund_delay_s = 7200
max_fee_per_gas = "10000"
max_gas = 300000
max_fee_per_action = "3000000000"
`, id) + x.toml() + y.toml()
	}
	text := fmt.Sprintf(`
listen = "127.0.0.1:0"
token_file = %q
store_path = %q
gate_id = "gate1"
gate_pubkey = %q
agent_pubkeys = [%q, %q]
payment_signature_field = "off"

[settlement]
await_level = "L0"

[caps]
max_value_per_action = "1000000000000000000"
max_value_per_hour = "10000000000000000000"
max_fee_per_hour = "1000000000000000"

[record]
gate_url = "http://127.0.0.1:1"
executor_key_file = %q
`, f.token, f.store, gate, a, b, f.executor) + chain(714, ps["a714"], ps["b714"]) + chain(3735928814, ps["atest"], ps["btest"])
	return text, ps
}

func TestConfigOnePayerPerAgentPerChain(t *testing.T) {
	base, ps := twoAgentsText(t)
	require.NoError(t, validate(base))

	cfg, err := signerd.ParseConfig([]byte(base))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	hc, err := cfg.HandlerConfig()
	require.NoError(t, err)
	require.Len(t, hc.Chains, 2)
	for _, p := range hc.Chains {
		assert.Len(t, p.Payers, 2, "chain %d", p.ChainID)
	}

	addr := func(n string) string { return fmt.Sprintf("0x%x", ps[n].addr) }
	file := func(n string) string { return fmt.Sprintf("%q", ps[n].file) }
	cases := map[string]struct {
		mut  func(string) string
		want string
	}{
		"the old per-chain payer_key_file": {func(s string) string {
			return strings.Replace(s, "chain_id = 714\n", "chain_id = 714\npayer_key_file = "+file("a714")+"\n", 1)
		}, "payer_key_file and payer_address are replaced"},
		"the old per-chain payer_address": {func(s string) string {
			return strings.Replace(s, "chain_id = 714\n", "chain_id = 714\npayer_address = \""+addr("a714")+"\"\n", 1)
		}, "payer_key_file and payer_address are replaced"},
		"a served agent without a payer on a chain": {func(s string) string {
			return strings.Replace(s, ps["btest"].toml(), "", 1)
		}, "has no [[chain.payer]]"},
		"a chain without payers": {func(s string) string {
			return strings.Replace(strings.Replace(s, ps["atest"].toml(), "", 1), ps["btest"].toml(), "", 1)
		}, "no [[chain.payer]]"},
		"one key file for two agents": {func(s string) string {
			return strings.Replace(s, "key_file = "+file("b714"), "key_file = "+file("a714"), 1)
		}, "share one key file"},
		"one key file for two chains": {func(s string) string {
			return strings.Replace(s, "key_file = "+file("atest"), "key_file = "+file("a714"), 1)
		}, "share one key file"},
		"one address for two agents": {func(s string) string {
			return strings.Replace(s, "address = \""+addr("b714")+"\"", "address = \""+addr("a714")+"\"", 1)
		}, "share payer address"},
		"one address for two chains, spelled in upper case": {func(s string) string {
			return strings.Replace(s, "address = \""+addr("atest")+"\"", "address = \"0x"+strings.ToUpper(addr("a714")[2:])+"\"", 1)
		}, "share payer address"},
		"a payer for an agent not served": {func(s string) string {
			return strings.Replace(s, "agent_pubkey = \""+ps["b714"].agent+"\"",
				"agent_pubkey = \""+edPub(sha256.Sum256([]byte("stranger")))+"\"", 1)
		}, "not in agent_pubkeys"},
		"two payers for one agent on one chain": {func(s string) string {
			return strings.Replace(s, "agent_pubkey = \""+ps["b714"].agent+"\"", "agent_pubkey = \""+ps["a714"].agent+"\"", 1)
		}, "has two payers on this chain"},
		"a payer without a key file": {func(s string) string {
			return strings.Replace(s, "key_file = "+file("b714"), `key_file = ""`, 1)
		}, "key_file is required"},
		"a payer with a bad address": {func(s string) string {
			return strings.Replace(s, "address = \""+addr("b714")+"\"", `address = "0x01"`, 1)
		}, "must be 0x and 40 hex"},
		"the executor key as a payer": {func(s string) string {
			i := strings.Index(s, "executor_key_file = ")
			j := strings.Index(s[i:], "\n")
			return strings.Replace(s, "key_file = "+file("b714"), s[i+len("executor_"):i+j], 1)
		}, "the payer key file is the executor key file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			text := tc.mut(base)
			require.NotEqual(t, base, text)
			assert.ErrorContains(t, validate(text), tc.want)
		})
	}
}

func TestBuildGivesEachAgentItsOwnPayer(t *testing.T) {
	f, payer := newFiles(t)
	eden := fakeEden(t, escrowCode(t))
	second := edPub(sha256.Sum256([]byte("second agent")))
	file, addr := payerKey(t, filepath.Dir(f.payer), "second")
	text := configText(f, payer, eden.URL)
	text = strings.Replace(text, "agent_pubkeys = [", fmt.Sprintf("agent_pubkeys = [%q, ", second), 1)

	cfg, err := signerd.ParseConfig([]byte(text + payerEntry{agent: second, file: file, addr: addr}.toml()))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.NoError(t, cfg.ValidateBasic())
	d, err := signerd.Build(context.Background(), cfg, quiet)
	require.NoError(t, err)
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, d.Serve(stopped, nil), "closes the store")

	cfg, err = signerd.ParseConfig([]byte(text + payerEntry{agent: second, file: file, addr: payer}.toml()))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.ErrorContains(t, cfg.ValidateBasic(), "share payer address")

	// Two files holding one key, pinned under two addresses: the startup
	// check sees one key serving two agents before any pin is compared.
	copyFile := writeFile(t, filepath.Dir(f.payer), "copy.key", mustRead(t, f.payer), 0o600)
	cfg, err = signerd.ParseConfig([]byte(text + payerEntry{agent: second, file: copyFile, addr: addr}.toml()))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.NoError(t, cfg.ValidateBasic())
	_, err = signerd.Build(context.Background(), cfg, quiet)
	require.ErrorContains(t, err, "serves agent")
}
