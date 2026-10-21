// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/signerd"
)

const agentToken = "agent-one-token-0123456789"

// paymentText is a configuration with the Payment-Signature on (the
// defaults): one credential per agent, labelled sources, the relay.
func paymentText(t *testing.T, f files, payer [20]byte, own, second string) string {
	t.Helper()
	cred := writeFile(t, filepath.Dir(f.token), "agent.token", []byte(agentToken+"\n"), 0o600)
	gate := sha256.Sum256([]byte("gate"))
	agent := sha256.Sum256([]byte("agent"))
	return fmt.Sprintf(`
listen = "127.0.0.1:0"
store_path = %q
gate_id = "gate1"
gate_pubkey = %q
agent_pubkeys = [%q]

[[credential]]
agent_pubkey = %q
token_file = %q

[caps]
max_value_per_action = "1000000000000000000"
max_value_per_hour = "10000000000000000000"
max_fee_per_hour = "1000000000000000"

[[chain]]
chain_id = 714
rpc = "own=%s"
own_node = true
settlement_rpc = ["gateway=%s"]
relay_url = "https://pay.example/"
payer_key_file = %q
payer_address = "0x%x"
facilitators = ["0xfac1117a70400000000000000000000000000000"]
max_refund_delay_s = 7200
max_fee_per_gas = "10000"
max_gas = 300000
max_fee_per_action = "3000000000"
`, f.store, edPub(gate), edPub(agent), edPub(agent), cred, own, second, f.payer, payer)
}

func validate(text string) error {
	cfg, err := signerd.ParseConfig([]byte(text))
	if err != nil {
		return err
	}
	cfg.ApplyDefaults()
	return cfg.ValidateBasic()
}

func TestConfigWithThePaymentSignature(t *testing.T) {
	f, payer := newFiles(t)
	base := paymentText(t, f, payer, "http://127.0.0.1:1", "https://rpc.eden.gateway.fm/")
	require.NoError(t, validate(base))

	cfg, err := signerd.ParseConfig([]byte(base))
	require.NoError(t, err)
	cfg.ApplyDefaults()
	assert.True(t, cfg.PaymentSignatureEnabled(), "on by default")
	assert.Equal(t, "L1", cfg.Settlement.AwaitLevel)
	assert.Equal(t, "L1", cfg.SettlementConfig().MinLevel.String())
	assert.Equal(t, "houston-relay", cfg.Chains[0].Broadcaster)

	other := sha256.Sum256([]byte("other agent"))
	refused := map[string]func(string) string{
		"await level L0": func(s string) string {
			return strings.Replace(s, "[caps]", "[settlement]\nawait_level = \"L0\"\n\n[caps]", 1)
		},
		"unlabelled own source": func(s string) string { return strings.Replace(s, `rpc = "own=`, `rpc = "`, 1) },
		"unlabelled second source": func(s string) string {
			return strings.Replace(s, `settlement_rpc = ["gateway=`, `settlement_rpc = ["`, 1)
		},
		"one operator behind two hosts": func(s string) string {
			return strings.Replace(s, `settlement_rpc = ["gateway=`, `settlement_rpc = ["own=`, 1)
		},
		"a shared token": func(s string) string {
			return strings.Replace(s, "store_path", fmt.Sprintf("token_file = %q\nstore_path", f.token), 1)
		},
		"a credential for an agent not served": func(s string) string {
			return strings.Replace(s, "[[credential]]\nagent_pubkey = \""+edPub(sha256.Sum256([]byte("agent")))+"\"",
				"[[credential]]\nagent_pubkey = \""+edPub(other)+"\"", 1)
		},
		"two credentials on one file": func(s string) string {
			i := strings.Index(s, "[[credential]]")
			j := strings.Index(s, "[caps]")
			return s[:j] + s[i:j] + s[j:]
		},
		"field nonce": func(s string) string {
			return strings.Replace(s, "store_path", "payment_signature_field = \"nonce\"\nstore_path", 1)
		},
		"plain http relay":  func(s string) string { return strings.Replace(s, "https://pay.example/", "http://pay.example/", 1) },
		"relay without url": func(s string) string { return strings.Replace(s, `relay_url = "https://pay.example/"`, "", 1) },
		"relay grace above the await grace": func(s string) string {
			return strings.Replace(s, "[caps]", "[settlement]\nawait_grace_s = 20\n\n[broadcast]\nrelay_grace_s = 30\n\n[caps]", 1)
		},
		"server timeout above 60 s": func(s string) string {
			return strings.Replace(s, "[caps]", "[broadcast]\nserver_timeout_s = 61\n\n[caps]", 1)
		},
	}
	for name, mut := range refused {
		t.Run(name, func(t *testing.T) {
			text := mut(base)
			require.NotEqual(t, base, text)
			assert.Error(t, validate(text))
		})
	}

	off := strings.Replace(base, "store_path", "payment_signature_field = \"off\"\nstore_path", 1)
	require.NoError(t, validate(strings.Replace(off, `rpc = "own=`, `rpc = "`, 1)), "labels are needed only for the Payment-Signature")
	oneSource := strings.Replace(off, `settlement_rpc = ["gateway=https://rpc.eden.gateway.fm/"]`, "", 1)
	assert.Error(t, validate(oneSource), "L1 with one operator would never reach an outcome")
	require.NoError(t, validate(strings.Replace(oneSource, "[caps]", "[settlement]\nawait_level = \"L0\"\n\n[caps]", 1)))
	direct := strings.Replace(base, `relay_url = "https://pay.example/"`, `broadcaster = "direct"`, 1)
	require.NoError(t, validate(direct))
	assert.Error(t, validate(strings.Replace(direct, `broadcaster = "direct"`, "broadcaster = \"direct\"\nrelay_url = \"https://pay.example/\"", 1)))
}

func TestBuildWithThePaymentSignature(t *testing.T) {
	f, payer := newFiles(t)
	eden := fakeEden(t, escrowCode(t))
	_, port, err := net.SplitHostPort(strings.TrimPrefix(eden.URL, "http://"))
	require.NoError(t, err)
	text := paymentText(t, f, payer, eden.URL, "http://localhost:"+port)
	cfg, err := signerd.ParseConfig([]byte(text))
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

	for tok, want := range map[string]int{agentToken: http.StatusOK, "0123456789abcdef-token": http.StatusUnauthorized} {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr.String()+"/v1/health", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, want, resp.StatusCode, tok)
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
