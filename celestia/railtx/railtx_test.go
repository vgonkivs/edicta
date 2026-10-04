package railtx_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// Assumed symbols (railtx does not exist yet; this is the contract):
//   railtx.Config{Consensus node.Consensus; Reader node.Reader; Key railtx.KeySource;
//     GasLimit, Fee uint64 (Fee in base units of the bond denom)}
//   railtx.New(ccfg railtx.Config) (*railtx.Rail, error)   // *Rail satisfies transfer.Rail
//   railtx.KeyFromSecret(secret.Secret) railtx.KeySource    // Reveal() = 32-byte secp256k1 scalar
//   railtx.KeyFromKeyring(dir, name string, passphrase secret.Secret) railtx.KeySource // "file" backend
//   (*Rail).Address(ctx) (string, error)
//   sentinels: ErrFeeAboveMax, ErrChainMismatch, ErrSignerMismatch, ErrBadBody,
//     ErrSequenceMismatch (broadcast refused: account sequence differs; NOT a success),
//     ErrIndeterminate (timeout/context/unreachable: outcome unknown, fail closed)
//   Broadcast: node answering "already in mempool/cache" (node.ErrAlreadyInMempool, assumed)
//     is idempotent success (nil); node.ErrSequenceMismatch (assumed) -> railtx.ErrSequenceMismatch.
//   Status: node.TxStatus{Found:false} -> TxUnknown; Found && Height==0 -> TxPending;
//     Found && Height>0 -> TxCommitted{Height, Code}.

var bg = context.Background()

type vec struct {
	ID       string                  `json:"id"`
	BodyRef  string                  `json:"body_ref"`
	ChainID  string                  `json:"chain_id"`
	Account  string                  `json:"account_number"`
	Sequence string                  `json:"sequence"`
	GasLimit string                  `json:"gas_limit"`
	Fee      struct{ Amount string } `json:"fee"`
	Key      struct {
		Priv    string `json:"priv_hex"`
		Address string `json:"address"`
	} `json:"key"`
	AuthInfo string `json:"auth_info_hex"`
	TxRaw    string `json:"tx_raw_hex"`
	TxHash   string `json:"tx_hash_hex"`
}

type vecFile struct {
	Body []struct {
		ID      string `json:"id"`
		BodyHex string `json:"body_hex"`
	} `json:"body"`
	Signed []vec `json:"signed"`
}

func load(t *testing.T) (vecFile, map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "profiles", "bank-send", "tx.json"))
	require.NoError(t, err)
	var f vecFile
	require.NoError(t, json.Unmarshal(raw, &f))
	bodies := map[string][]byte{}
	for _, b := range f.Body {
		bodies[b.ID] = unhex(t, b.BodyHex)
	}
	return f, bodies
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func num(t *testing.T, s string) uint64 {
	t.Helper()
	var n uint64
	_, err := fmt.Sscan(s, &n)
	require.NoError(t, err)
	return n
}

func newRail(t *testing.T, v vec, cons *nodefake.Consensus) *railtx.Rail {
	t.Helper()
	cons.Accounts[v.Key.Address] = node.AccountInfo{Number: num(t, v.Account), Sequence: num(t, v.Sequence)}
	r, err := railtx.New(railtx.Config{
		Consensus: cons, Reader: nodefake.NewChain(nil),
		Key:      railtx.KeyFromSecret(secret.New(unhex(t, v.Key.Priv))),
		GasLimit: num(t, v.GasLimit), Fee: num(t, v.Fee.Amount),
	})
	require.NoError(t, err)
	return r
}

var _ transfer.Rail = (*railtx.Rail)(nil)

func TestSignMatchesVectors(t *testing.T) {
	f, bodies := load(t)
	require.Len(t, f.Signed, 2)
	for _, v := range f.Signed {
		t.Run(v.ID, func(t *testing.T) {
			r := newRail(t, v, nodefake.NewConsensus(v.ChainID))
			body := bodies[v.BodyRef]
			raw, err := r.Sign(bg, body, v.ChainID, num(t, v.Fee.Amount))
			require.NoError(t, err)
			require.Equal(t, v.TxRaw, hex.EncodeToString(raw), "TxRaw byte-for-byte")
			h := sha256.Sum256(raw)
			require.Equal(t, v.TxHash, hex.EncodeToString(h[:]))
			// body_bytes embedded unchanged: TxRaw starts 0x0a len body
			require.True(t, bytes.Contains(raw, body))
			require.True(t, bytes.Contains(raw, unhex(t, v.AuthInfo)), "AuthInfo with fee and gas limit")
			// deterministic: signing twice yields identical bytes
			raw2, err := r.Sign(bg, body, v.ChainID, num(t, v.Fee.Amount))
			require.NoError(t, err)
			require.Equal(t, raw, raw2)
		})
	}
}

func TestSignRefusals(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	body := bodies[v.BodyRef]
	fee := num(t, v.Fee.Amount)

	cases := []struct {
		name    string
		nodeID  string
		body    []byte
		chainID string
		maxFee  uint64
		want    error
	}{
		{"fee above max", v.ChainID, body, v.ChainID, fee - 1, railtx.ErrFeeAboveMax},
		{"zero max fee", v.ChainID, body, v.ChainID, 0, railtx.ErrFeeAboveMax},
		{"action chain differs from node", "other-1", body, v.ChainID, fee, railtx.ErrChainMismatch},
		{"signing chain empty", v.ChainID, body, "", fee, railtx.ErrChainMismatch},
		{"signer is not msg sender", v.ChainID, bodies["body_typical_other_sender"], v.ChainID, fee, railtx.ErrSignerMismatch},
		{"empty body", v.ChainID, nil, v.ChainID, fee, railtx.ErrBadBody},
		{"garbage body", v.ChainID, []byte{0xff, 0x01}, v.ChainID, fee, railtx.ErrBadBody},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cons := nodefake.NewConsensus(c.nodeID)
			r := newRail(t, v, cons)
			b := c.body
			if c.name == "signer is not msg sender" {
				b = otherSenderBody(t, bodies[v.BodyRef])
			}
			raw, err := r.Sign(bg, b, c.chainID, c.maxFee)
			require.ErrorIs(t, err, c.want)
			require.Nil(t, raw)
			require.Empty(t, cons.Sent, "nothing is broadcast by Sign")
		})
	}
}

// otherSenderBody builds a body whose MsgSend has a different valid sender.
func otherSenderBody(t *testing.T, _ []byte) []byte {
	t.Helper()
	from, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{0x42}, 20))
	require.NoError(t, err)
	to, err := bankmsg.EncodeAddress("celestia", bytes.Repeat([]byte{0x43}, 20))
	require.NoError(t, err)
	msg, err := bankmsg.Encode(bankmsg.MsgSend{From: from, To: to, Denom: "utia", Amount: 1}, "celestia")
	require.NoError(t, err)
	body, err := bankaction.Body(msg, commitment.Hash{1}, 100)
	require.NoError(t, err)
	return body
}

func TestSignFailsClosedOnNodeErrors(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	for _, e := range []error{context.DeadlineExceeded, context.Canceled, node.ErrUnavailable} {
		cons := nodefake.NewConsensus(v.ChainID)
		r := newRail(t, v, cons)
		cons.Fail = e
		raw, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, num(t, v.Fee.Amount))
		require.ErrorIs(t, err, e)
		require.Nil(t, raw)
	}
	// unknown account: refuse, never sign with a guessed number/sequence
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	delete(cons.Accounts, v.Key.Address)
	raw, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, num(t, v.Fee.Amount))
	require.ErrorIs(t, err, node.ErrNotFound)
	require.Nil(t, raw)
}

func TestSignUsesLiveAccountState(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	cons.Accounts[v.Key.Address] = node.AccountInfo{Number: 42, Sequence: 8}
	raw, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, num(t, v.Fee.Amount))
	require.NoError(t, err)
	require.NotEqual(t, v.TxRaw, hex.EncodeToString(raw), "sequence is part of the SignDoc")
}

func TestBroadcastResendsSameBytes(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	raw, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, num(t, v.Fee.Amount))
	require.NoError(t, err)
	orig := bytes.Clone(raw)
	for range 3 {
		require.NoError(t, r.Broadcast(bg, raw))
	}
	require.Len(t, cons.Sent, 3)
	for _, s := range cons.Sent {
		require.Equal(t, orig, s, "identical bytes every time, never re-encoded")
	}
	require.Equal(t, orig, raw, "input not mutated")
}

func TestBroadcastClassification(t *testing.T) {
	tx := []byte{1, 2, 3}
	cases := []struct {
		name string
		fail error
		want error // nil = success
	}{
		{"already in mempool is idempotent", node.ErrAlreadyInMempool, nil},
		{"wrapped already in mempool", fmt.Errorf("x: %w", node.ErrAlreadyInMempool), nil},
		{"sequence mismatch", node.ErrSequenceMismatch, railtx.ErrSequenceMismatch},
		{"deadline", context.DeadlineExceeded, context.DeadlineExceeded},
		{"canceled", context.Canceled, context.Canceled},
		{"unavailable", node.ErrUnavailable, node.ErrUnavailable},
		{"other", errors.New("boom"), railtx.ErrIndeterminate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cons := nodefake.NewConsensus("mocha-4")
			r, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
				Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{1}, 32))), GasLimit: 1, Fee: 1})
			require.NoError(t, err)
			cons.Fail = c.fail
			err = r.Broadcast(bg, tx)
			if c.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, c.want)
		})
	}
	// an already-cancelled context is not "sent"
	r, err := railtx.New(railtx.Config{Consensus: nodefake.NewConsensus("mocha-4"), Reader: nodefake.NewChain(nil),
		Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{1}, 32))), GasLimit: 1, Fee: 1})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	require.ErrorIs(t, r.Broadcast(ctx, tx), context.Canceled)
	require.Error(t, r.Broadcast(bg, nil), "empty tx refused")
}

func TestStatus(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	var h, h2, h3 [32]byte
	h[0], h2[0], h3[0] = 1, 2, 3
	cons.SetTx(h, node.TxStatus{Found: true, Height: 0})
	cons.SetTx(h2, node.TxStatus{Found: true, Height: 777, Code: 0})
	cons.SetTx(h3, node.TxStatus{Found: true, Height: 778, Code: 11})

	s, err := r.Status(bg, h)
	require.NoError(t, err)
	require.Equal(t, transfer.TxStatus{State: transfer.TxPending}, s)
	s, err = r.Status(bg, h2)
	require.NoError(t, err)
	require.Equal(t, transfer.TxStatus{State: transfer.TxCommitted, Height: 777}, s)
	s, err = r.Status(bg, h3)
	require.NoError(t, err)
	require.Equal(t, transfer.TxStatus{State: transfer.TxCommitted, Height: 778, Code: 11}, s)
	s, err = r.Status(bg, [32]byte{9})
	require.NoError(t, err)
	require.Equal(t, transfer.TxUnknown, s.State)
}

func TestStatusFailsClosed(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	for _, e := range []error{context.DeadlineExceeded, context.Canceled, node.ErrUnavailable, errors.New("boom")} {
		cons := nodefake.NewConsensus(v.ChainID)
		r := newRail(t, v, cons)
		cons.SetTx([32]byte{1}, node.TxStatus{Found: true, Height: 5})
		cons.Fail = e
		s, err := r.Status(bg, [32]byte{1})
		require.Error(t, err, "%v must not become Unknown or Committed", e)
		require.Equal(t, transfer.TxStatus{}, s)
	}
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, err := r.Status(ctx, [32]byte{1})
	require.ErrorIs(t, err, context.Canceled)
}

func TestDomainAndHeadFailClosed(t *testing.T) {
	f, _ := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus(v.ChainID)
	r := newRail(t, v, cons)
	d, err := r.Domain(bg)
	require.NoError(t, err)
	require.Equal(t, transfer.Domain{ChainID: v.ChainID, Denom: "utia", HRP: "celestia", Sender: v.Key.Address}, d)
	cons.Fail = context.DeadlineExceeded
	_, err = r.Domain(bg)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestConfigValidation(t *testing.T) {
	good := func() railtx.Config {
		return railtx.Config{Consensus: nodefake.NewConsensus("c"), Reader: nodefake.NewChain(nil),
			Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{1}, 32))), GasLimit: 1, Fee: 1}
	}
	_, err := railtx.New(good())
	require.NoError(t, err)
	for name, mut := range map[string]func(*railtx.Config){
		"nil consensus": func(c *railtx.Config) { c.Consensus = nil },
		"nil reader":    func(c *railtx.Config) { c.Reader = nil },
		"zero gas":      func(c *railtx.Config) { c.GasLimit = 0 },
		"no key":        func(c *railtx.Config) { c.Key = railtx.KeySource{} },
		"short key":     func(c *railtx.Config) { c.Key = railtx.KeyFromSecret(secret.New([]byte{1, 2})) },
		"zero key":      func(c *railtx.Config) { c.Key = railtx.KeyFromSecret(secret.New(make([]byte, 32))) },
		"unset secret":  func(c *railtx.Config) { c.Key = railtx.KeyFromSecret(secret.Secret{}) },
	} {
		c := good()
		mut(&c)
		_, err := railtx.New(c)
		require.Error(t, err, name)
	}
}

func TestKeyNeverLeaks(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	cons := nodefake.NewConsensus("other-1") // force an error path
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	r := newRail(t, v, cons)
	_, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, 1)
	require.Error(t, err)
	cfg := railtx.Config{Consensus: cons, Key: railtx.KeyFromSecret(secret.New(unhex(t, v.Key.Priv)))}
	out := fmt.Sprintf("%v|%+v|%#v|%s|%v", cfg, cfg, cfg, err, r) + logs.String()
	j, jerr := json.Marshal(cfg.Key)
	require.NoError(t, jerr)
	out += string(j)
	require.NotContains(t, out, v.Key.Priv)
	require.NotContains(t, out, string(unhex(t, v.Key.Priv)))
	require.NotContains(t, fmt.Sprintf("%v %+v %#v", cfg.Key, cfg.Key, cfg.Key), v.Key.Priv)
	require.Contains(t, strings.ToLower(fmt.Sprint(cfg.Key)), "redacted")
}

func TestKeyFromKeyring(t *testing.T) {
	f, bodies := load(t)
	v := f.Signed[0]
	dir := t.TempDir()
	pass := secret.New([]byte("correct horse battery"))
	// Assumed helper: railtx.ImportKeyring creates a file-backend keyring entry
	// from a raw secp256k1 key (used by tests and edicta-live setup).
	require.NoError(t, railtx.ImportKeyring(dir, "executor", pass, secret.New(unhex(t, v.Key.Priv))))

	cons := nodefake.NewConsensus(v.ChainID)
	cons.Accounts[v.Key.Address] = node.AccountInfo{Number: 42, Sequence: 7}
	r, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
		Key: railtx.KeyFromKeyring(dir, "executor", pass), GasLimit: num(t, v.GasLimit), Fee: num(t, v.Fee.Amount)})
	require.NoError(t, err)
	raw, err := r.Sign(bg, bodies[v.BodyRef], v.ChainID, num(t, v.Fee.Amount))
	require.NoError(t, err)
	require.Equal(t, v.TxRaw, hex.EncodeToString(raw))

	_, err = railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
		Key: railtx.KeyFromKeyring(dir, "executor", secret.New([]byte("wrong passphrase!!"))), GasLimit: 1, Fee: 1})
	require.Error(t, err)
	_, err = railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
		Key: railtx.KeyFromKeyring(dir, "missing", pass), GasLimit: 1, Fee: 1})
	require.Error(t, err)
	_, err = railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
		Key: railtx.KeyFromKeyring(filepath.Join(dir, "nope"), "executor", pass), GasLimit: 1, Fee: 1})
	require.Error(t, err)
}

func FuzzSignBody(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, body []byte) {
		cons := nodefake.NewConsensus("mocha-4")
		r, err := railtx.New(railtx.Config{Consensus: cons, Reader: nodefake.NewChain(nil),
			Key: railtx.KeyFromSecret(secret.New(bytes.Repeat([]byte{1}, 32))), GasLimit: 1, Fee: 1})
		if err != nil {
			t.Skip()
		}
		raw, err := r.Sign(bg, body, "mocha-4", 1)
		if err == nil {
			require.True(t, bytes.Contains(raw, body), "any accepted body is embedded unchanged")
		}
	})
}
