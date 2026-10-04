package edictad_test

// Assumed API of package celestia/edictad (007k), all of it used below:
//
//	var ErrConfig error                       // every config refusal wraps it
//	type Config struct{ Network{ChainID string; MinAppVersion, MaxAppVersion uint64};
//	    Recorder{Enabled bool; Quota{BlobsPerHour, BytesPerDay uint64}};
//	    Gate{GateID string}; Network.DA string ("blob"|"fibre"); HTTP{Listen string} }
//	func ParseConfig(data []byte) (Config, error)   // strict TOML, no file access
//	type Deps struct {
//	    Reader node.Reader; Consensus node.Consensus
//	    Submitter recorder.Submitter   // overrides the keyring; nil + enabled = open keyring
//	    Clock gate.Clock; Logger *slog.Logger
//	    Listen   func(network, addr string) (net.Listener, error)  // nil = net.Listen
//	    WrapGate func(edictaapi.Gate) edictaapi.Gate               // test seam, nil = identity
//	}
//	func Start(ctx context.Context, cfg Config, d Deps) (*Server, error)
//	func (*Server) Addr() string; Shutdown(ctx context.Context) error
//	var ErrDANotSupported error  // da = "fibre" at Start (007l2); health.AllowedDA = [2] for blob
//
// Start order: secret files (mode) -> node.Check -> gate.Preflight -> open
// registry -> recorder -> Listen. Secret files: gate key = 32-byte raw seed;
// agents file = TOML [[agents]] agent_id, pubkey(hex).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
)

var (
	bg      = context.Background()
	t0      = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	recAddr = bytes.Repeat([]byte{9}, 20)
	nsBytes = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{7}, 10)...)
	// Canary secrets: none of these may appear in any log line or error.
	canaryAuthTok  = "canary-authorize-token-7f3a91"
	canaryRecTok   = "canary-record-token-c20d55"
	canaryBNTok    = "canary-bridge-token-5be1aa"
	canaryPass     = "canary-passphrase-91e0d4"
	inlineCanaries = []string{"inline-canary-8c3e", "inline-canary-2f77"}
)

type clock struct{ t time.Time }

func (c clock) Now() time.Time { return c.t }

func blockAt(h uint64, app uint64) node.Header {
	return node.Header{ChainID: "testchain-7", Height: h, Time: t0, AppVersion: app,
		DataRoot: bytes.Repeat([]byte{byte(h)}, 32)}
}

// landing is a recorder.Submitter that really lands the blob in the fake
// chain with the real share commitment.
type landing struct {
	mu     sync.Mutex
	chain  *nodefake.Chain
	chain1 string
	calls  int
	signer int
}

func (l *landing) Signer(context.Context) ([]byte, error) {
	l.mu.Lock()
	l.signer++
	l.mu.Unlock()
	return bytes.Clone(recAddr), nil
}

func (l *landing) Submit(ctx context.Context, ns, data []byte) (recorder.SubmitResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	head, _ := l.chain.Head(ctx)
	h := head.Height + 1
	hd := blockAt(h, 8)
	hd.ChainID = head.ChainID
	l.chain.AddHeader(hd)
	c, err := sharev1.Commitment(ns, recAddr, data)
	if err != nil {
		return recorder.SubmitResult{}, err
	}
	l.chain.AddBlob(h, node.Blob{Namespace: bytes.Clone(ns), Data: bytes.Clone(data), ShareVersion: 1,
		Signer: bytes.Clone(recAddr), Commitment: c}, nil)
	return recorder.SubmitResult{Height: h}, nil
}

func (l *landing) touched() (int, int) { l.mu.Lock(); defer l.mu.Unlock(); return l.calls, l.signer }

// spyGate is the Gate behind the HTTP API when WrapGate is used.
type spyGate struct {
	mu                sync.Mutex
	auth, rec         int
	env, action, ref  string
	pub, sig          []byte
	authFn            func() ([]byte, error)
	authResp, recResp []byte
}

func (g *spyGate) Authorize(_ context.Context, env, action []byte) (gate.Result, error) {
	g.mu.Lock()
	g.auth++
	g.env, g.action = string(env), string(action)
	fn, resp := g.authFn, g.authResp
	g.mu.Unlock()
	if fn != nil {
		b, err := fn()
		return gate.Result{Authorization: b}, err
	}
	return gate.Result{Authorization: resp}, nil
}

func (g *spyGate) Record(_ context.Context, env []byte, ref string, pub, sig []byte) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rec++
	g.env, g.ref, g.pub, g.sig = string(env), ref, bytes.Clone(pub), bytes.Clone(sig)
	return g.recResp, nil
}

func (g *spyGate) calls() (int, int) { g.mu.Lock(); defer g.mu.Unlock(); return g.auth, g.rec }

// lockedBuf is a goroutine-safe log sink.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type env struct {
	t        *testing.T
	dir      string
	seed     []byte
	gatePub  ed25519.PublicKey
	agentPub ed25519.PublicKey
	agentPrv ed25519.PrivateKey
	execPub  ed25519.PublicKey
	chain    *nodefake.Chain
	cons     *nodefake.Consensus
	sub      *landing
	spy      *spyGate
	logs     *lockedBuf
	listens  int
	order    []string
	deps     edictad.Deps
	srv      *edictad.Server
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }

func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, b, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), logs: &lockedBuf{}, spy: &spyGate{authResp: []byte("auth-bytes"), recResp: []byte("receipt-bytes")}}
	var err error
	e.seed = make([]byte, 32)
	_, _ = rand.Read(e.seed)
	e.gatePub = ed25519.NewKeyFromSeed(e.seed).Public().(ed25519.PublicKey)
	e.agentPub, e.agentPrv, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	e.execPub, _, err = ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	e.chain = nodefake.NewChain(recAddr)
	e.chain.AddHeader(blockAt(100, 8))
	e.cons = nodefake.NewConsensus("testchain-7")
	e.sub = &landing{chain: e.chain}

	writeFile(t, e.path("gate.ed25519"), e.seed, 0o600)
	writeFile(t, e.path("agents.toml"), []byte(fmt.Sprintf("[[agents]]\nagent_id = \"agent-1\"\npubkey = %q\n",
		hex.EncodeToString(e.agentPub))), 0o600)
	writeFile(t, e.path("keyring.pass"), []byte(canaryPass+"\n"), 0o600)
	writeFile(t, e.path("bn.token"), []byte(canaryBNTok+"\n"), 0o600)
	writeFile(t, e.path("auth.token"), []byte(canaryAuthTok+"\n"), 0o600)
	writeFile(t, e.path("rec.token"), []byte(canaryRecTok+"\n"), 0o600)

	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.deps = edictad.Deps{
		Reader: e.chain, Consensus: e.cons, Submitter: e.sub, Clock: clock{t0}, Logger: log,
		Listen: func(network, addr string) (net.Listener, error) {
			e.listens++
			return net.Listen(network, addr)
		},
		WrapGate: func(edictaapi.Gate) edictaapi.Gate { return e.spy },
	}
	return e
}

// tomlOf renders a valid config for e; edits are exact-string replacements
// applied in order (each must match).
func (e *env) tomlOf(edits ...[2]string) string {
	s := fmt.Sprintf(`
[network]
chain_id = ""
min_app_version = 3
max_app_version = 10
da = "blob"

[network.bridge]
addr = "bn.invalid:26658"
token_file = %q
tls = false

[network.consensus_grpc]
addr = "grpc.invalid:9090"
token_file = ""
tls = false

[recorder]
enabled = true
namespace = %q
keyring_dir = %q
keyring_backend = "file"
key_name = "recorder"
passphrase_file = %q
max_blob_bytes = 1048576

[recorder.quota]
blobs_per_hour = 60
bytes_per_day = 67108864

[gate]
gate_id = "gate-test-1"
key_file = %q
registry_path = %q
action_types = ["application/vnd.edicta.test.v0+cbor"]
allowlist_file = %q
executor_keys = [%q]
anchor_verifier = "self"

[http]
listen = "127.0.0.1:0"
tls_cert_file = ""
tls_key_file = ""
authorize_token_file = ""
record_token_file = ""
allow_insecure = false
`, e.path("bn.token"), hex.EncodeToString(nsBytes), e.path("keyring"), e.path("keyring.pass"),
		e.path("gate.ed25519"), e.path("registry.db"), e.path("agents.toml"), hex.EncodeToString(e.execPub))
	for _, ed := range edits {
		require.Contains(e.t, s, ed[0], "edit target missing")
		s = strings.Replace(s, ed[0], ed[1], 1)
	}
	return s
}

func (e *env) cfg(edits ...[2]string) edictad.Config {
	e.t.Helper()
	c, err := edictad.ParseConfig([]byte(e.tomlOf(edits...)))
	require.NoError(e.t, err)
	return c
}

// start parses and starts, registering Shutdown on cleanup.
func (e *env) start(edits ...[2]string) *edictad.Server {
	e.t.Helper()
	srv, err := edictad.Start(bg, e.cfg(edits...), e.deps)
	require.NoError(e.t, err)
	e.srv = srv
	e.t.Cleanup(func() { _ = srv.Shutdown(bg) })
	return srv
}

func (e *env) registryExists() bool {
	_, err := os.Stat(e.path("registry.db"))
	return err == nil
}

func (e *env) client(tok string, opts ...edictaapi.ClientOption) *edictaapi.Client {
	e.t.Helper()
	opts = append([]edictaapi.ClientOption{edictaapi.WithGateID("gate-test-1"), edictaapi.WithClock(clock{t0})}, opts...)
	c, err := edictaapi.NewClient("http://"+e.srv.Addr(), edictaapi.NewSecret(tok), agent{e.agentPrv, "agent-1"}, nil, opts...)
	require.NoError(e.t, err)
	return c
}

type agent struct {
	k  ed25519.PrivateKey
	id string
}

func (a agent) AgentID() string { return a.id }
func (a agent) SignPublish(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(a.k, msg), nil
}

func rep(from, to string) [2]string { return [2]string{from, to} }

// ---- minimal CBOR bodies (short items only) ----

func cbHead(major byte, n int) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	return []byte{major<<5 | 24, byte(n)}
}
func cbBytes(b []byte) []byte { return append(cbHead(2, len(b)), b...) }
func cbText(s string) []byte  { return append(cbHead(3, len(s)), s...) }

func authorizeBody(env, action string) []byte {
	b := []byte{0xa2, 0x01}
	b = append(b, cbBytes([]byte(env))...)
	b = append(b, 0x02)
	return append(b, cbBytes([]byte(action))...)
}

func recordBody(env, ref string, pub, sig []byte) []byte {
	b := []byte{0xa4, 0x01}
	b = append(b, cbBytes([]byte(env))...)
	b = append(b, 0x02)
	b = append(b, cbText(ref)...)
	b = append(b, 0x03)
	b = append(b, cbBytes(pub)...)
	b = append(b, 0x04)
	return append(b, cbBytes(sig)...)
}

func post(t *testing.T, srv *edictad.Server, path, authz string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+srv.Addr()+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/cbor")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}
