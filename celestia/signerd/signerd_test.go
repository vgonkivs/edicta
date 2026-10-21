// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/signerd"
	"github.com/vgonkivs/edicta/edenescrow"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// escrowCode is the recorded runtime code of the 714 escrow.
func escrowCode(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../spec/vectors/profiles/eden-escrow/live/escrow-code.json")
	require.NoError(t, err)
	var f struct {
		Blockscout struct {
			Deployed string `json:"deployed_bytecode"`
		} `json:"blockscout"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	return f.Blockscout.Deployed
}

// fakeEden answers the startup reads of the signer on the loopback.
func fakeEden(t *testing.T, code string) *httptest.Server {
	t.Helper()
	row, _ := edenescrow.Lookup(714)
	escrow := "0x" + hex.EncodeToString(row.Escrow[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := `"0x2ca"`
		if req.Method == "eth_getCode" {
			var addr string
			_ = json.Unmarshal(req.Params[0], &addr)
			res = `"0x"`
			if addr == escrow {
				res = `"` + code + `"`
			}
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, res)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeFile(t *testing.T, dir, name string, b []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, b, mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

type files struct{ token, payer, executor, store string }

func newFiles(t *testing.T) (files, [20]byte) {
	t.Helper()
	dir := t.TempDir()
	payer := sha256.Sum256([]byte("signerd test payer"))
	var s secp256k1.ModNScalar
	s.SetByteSlice(payer[:])
	addr := edenescrow.Address(secp256k1.NewPrivateKey(&s).PubKey())
	exec := sha256.Sum256([]byte("signerd test executor"))
	return files{
		token:    writeFile(t, dir, "api.token", []byte("0123456789abcdef-token\n"), 0o600),
		payer:    writeFile(t, dir, "payer.key", payer[:], 0o600),
		executor: writeFile(t, dir, "executor.key", exec[:], 0o600),
		store:    filepath.Join(dir, "signer.db"),
	}, addr
}

func configText(f files, payer [20]byte, rpc string) string {
	gate := sha256.Sum256([]byte("gate"))
	agent := sha256.Sum256([]byte("agent"))
	return fmt.Sprintf(`
listen = "127.0.0.1:0"
token_file = %q
store_path = %q
gate_id = "gate1"
gate_pubkey = %q
agent_pubkeys = [%q]
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

[[chain]]
chain_id = 714
rpc = %q
own_node = true
broadcaster = "direct"
payer_key_file = %q
payer_address = "0x%x"
facilitators = ["0xfac1117a70400000000000000000000000000000"]
max_refund_delay_s = 7200
max_fee_per_gas = "10000"
max_gas = 300000
max_fee_per_action = "3000000000"
`, f.token, f.store, edPub(gate), edPub(agent), f.executor, rpc, f.payer, payer)
}

func TestBuildServesAfterTheStartupChecks(t *testing.T) {
	f, payer := newFiles(t)
	eden := fakeEden(t, escrowCode(t))
	cfg, err := signerd.ParseConfig([]byte(configText(f, payer, eden.URL)))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.NoError(t, cfg.ValidateBasic())

	ctx, cancel := context.WithCancel(context.Background())
	d, err := signerd.Build(ctx, cfg, quiet)
	require.NoError(t, err)
	addrc := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx, func(a net.Addr) { addrc <- a }) }()
	addr := <-addrc

	req, err := http.NewRequest(http.MethodGet, "http://"+addr.String()+"/v1/health", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef-token")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestBuildRefusesWithoutTheEscrowCode(t *testing.T) {
	f, payer := newFiles(t)
	eden := fakeEden(t, "0x")
	cfg, err := signerd.ParseConfig([]byte(configText(f, payer, eden.URL)))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	_, err = signerd.Build(context.Background(), cfg, quiet)
	require.ErrorContains(t, err, "escrow code")
}

func TestBuildRefusesAReadablePayerKey(t *testing.T) {
	f, payer := newFiles(t)
	require.NoError(t, os.Chmod(f.payer, 0o644))
	eden := fakeEden(t, escrowCode(t))
	cfg, err := signerd.ParseConfig([]byte(configText(f, payer, eden.URL)))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	_, err = signerd.Build(context.Background(), cfg, quiet)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), hex.EncodeToString(mustRead(t, f.payer)), "the key never reaches an error")
}

func TestBuildRefusesAPayerOtherThanThePin(t *testing.T) {
	f, _ := newFiles(t)
	eden := fakeEden(t, escrowCode(t))
	cfg, err := signerd.ParseConfig([]byte(configText(f, [20]byte{0x01}, eden.URL)))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	_, err = signerd.Build(context.Background(), cfg, quiet)
	require.ErrorContains(t, err, "payer")
}

func TestConfigRefusals(t *testing.T) {
	f, payer := newFiles(t)
	base := configText(f, payer, "http://127.0.0.1:1")
	cases := []struct {
		name string
		mut  func(string) string
	}{
		{"unknown key", func(s string) string { return "colour = \"red\"\n" + s }},
		{"remote listen without the flag", func(s string) string {
			return strings.Replace(s, `listen = "127.0.0.1:0"`, `listen = "0.0.0.0:8402"`, 1)
		}},
		{"no token", func(s string) string {
			return strings.Replace(s, "token_file = "+fmt.Sprintf("%q", f.token), `token_file = ""`, 1)
		}},
		{"executor key is the payer key", func(s string) string {
			return strings.Replace(s, "executor_key_file = "+fmt.Sprintf("%q", f.executor), "executor_key_file = "+fmt.Sprintf("%q", f.payer), 1)
		}},
		{"zero cap", func(s string) string {
			return strings.Replace(s, `max_value_per_action = "1000000000000000000"`, `max_value_per_action = "0"`, 1)
		}},
		{"facilitator not an address", func(s string) string {
			return strings.Replace(s, `"0xfac1117a70400000000000000000000000000000"`, `"fac1"`, 1)
		}},
		{"chain outside the table", func(s string) string { return strings.Replace(s, "chain_id = 714", "chain_id = 1", 1) }},
		{"remote without TLS", func(s string) string {
			return strings.Replace(s, `listen = "127.0.0.1:0"`, "listen = \"0.0.0.0:8402\"\nallow_remote = true", 1)
		}},
		{"TLS cert without key", func(s string) string { return "tls_cert_file = \"/c.pem\"\n" + s }},
		{"plain http gate off the loopback", func(s string) string {
			return strings.Replace(s, `gate_url = "http://127.0.0.1:1"`, `gate_url = "http://gate.example:8080"`, 1)
		}},
		{"fee per action above the hourly fee cap", func(s string) string {
			return strings.Replace(s, `max_fee_per_action = "3000000000"`, `max_fee_per_action = "1000000000000001"`, 1)
		}},
		{"admin token is the API token", func(s string) string {
			return fmt.Sprintf("admin_token_file = %q\n", f.token) + s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := signerd.ParseConfig([]byte(tc.mut(base)))
			if err == nil {
				cfg.ApplyDefaults()
				err = cfg.ValidateBasic()
			}
			require.Error(t, err)
		})
	}
	accepted := []string{
		base,
		strings.Replace(base, `listen = "127.0.0.1:0"`, "listen = \"0.0.0.0:8402\"\nallow_remote = true\ninsecure_remote_http = true", 1),
		strings.Replace(base, `listen = "127.0.0.1:0"`, "listen = \"0.0.0.0:8402\"\nallow_remote = true\ntls_cert_file = \"/c.pem\"\ntls_key_file = \"/k.pem\"", 1),
		strings.Replace(base, `gate_url = "http://127.0.0.1:1"`, `gate_url = "https://gate.example"`, 1),
		strings.Replace(base, `gate_url = "http://127.0.0.1:1"`, "gate_url = \"http://gate.example\"\ninsecure_http = true", 1),
	}
	for i, text := range accepted {
		cfg, err := signerd.ParseConfig([]byte(text))
		require.NoError(t, err, i)
		cfg.ApplyDefaults()
		require.NoError(t, cfg.ValidateBasic(), i)
	}
}

func edPub(seed [32]byte) string {
	return hex.EncodeToString(ed25519.NewKeyFromSeed(seed[:])[ed25519.SeedSize:])
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}
