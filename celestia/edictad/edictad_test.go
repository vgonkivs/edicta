package edictad_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// ---------------- config ----------------

func TestParseConfigValid(t *testing.T) {
	e := newEnv(t)
	c := e.cfg()
	require.Equal(t, "gate-test-1", c.Gate.GateID)
	require.Equal(t, "celestia_blob", c.Network.DA)
	require.True(t, c.Recorder.Enabled)
	require.EqualValues(t, 60, c.Recorder.Quota.BlobsPerHour)
	require.EqualValues(t, 67108864, c.Recorder.Quota.BytesPerDay)
	require.Equal(t, "127.0.0.1:0", c.HTTP.Listen)
	require.EqualValues(t, 3, c.Network.MinAppVersion)
	require.EqualValues(t, 10, c.Network.MaxAppVersion)
}

func TestParseConfigRefusals(t *testing.T) {
	e := newEnv(t)
	good := e.path("gate.ed25519")
	cases := []struct {
		name string
		edit [][2]string
	}{
		{"not toml", [][2]string{rep("[network]", "[network")}},
		{"unknown key", [][2]string{rep("[http]\n", "[http]\nbogus = 1\n")}},
		{"unknown table", [][2]string{rep("[http]\n", "[nope]\nx = 1\n\n[http]\n")}},
		{"compat check cannot be skipped", [][2]string{rep("[network]\n", "[network]\nskip_compat_check = true\n")}},
		{"missing gate_id", [][2]string{rep(`gate_id = "gate-test-1"`, `gate_id = ""`)}},
		{"gate_id outside charset", [][2]string{rep(`gate_id = "gate-test-1"`, `gate_id = "bad id"`)}},
		{"gate_id too long", [][2]string{rep(`gate_id = "gate-test-1"`, `gate_id = "`+strings.Repeat("a", 65)+`"`)}},
		{"no action types", [][2]string{rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`, `action_types = []`)}},
		{"action type not a media type", [][2]string{rep(`"application/vnd.edicta.test.v0+cbor"]`, `"not a media type"]`)}},
		{"duplicate action type", [][2]string{rep(`action_types = ["application/vnd.edicta.test.v0+cbor"]`, `action_types = ["a/b", "a/b"]`)}},
		{"da missing", [][2]string{rep("da = \"celestia_blob\"\n", "")}},
		{"da empty", [][2]string{rep(`da = "celestia_blob"`, `da = ""`)}},
		{"da unknown", [][2]string{rep(`da = "celestia_blob"`, `da = "archive"`)}},
		{"da wrong case", [][2]string{rep(`da = "celestia_blob"`, `da = "Celestia_Blob"`)}},
		{"da list", [][2]string{rep(`da = "celestia_blob"`, `da = ["celestia_blob"]`)}},
		{"da both as list", [][2]string{rep(`da = "celestia_blob"`, `da = ["celestia_blob", "fibre"]`)}},
		{"da number", [][2]string{rep(`da = "celestia_blob"`, `da = 2`)}},
		{"old allowed_da key is unknown", [][2]string{rep("[gate]\n", "[gate]\nallowed_da = [2]\n")}},
		{"da under gate is unknown", [][2]string{rep("[gate]\n", "[gate]\nda = \"blob\"\n")}},
		{"missing key_file", [][2]string{rep(`key_file = "`+good+`"`, `key_file = ""`)}},
		{"missing registry_path", [][2]string{rep(`registry_path = "`+e.path("registry.db")+`"`, `registry_path = ""`)}},
		{"missing allowlist_file", [][2]string{rep(`allowlist_file = "`+e.path("agents.toml")+`"`, `allowlist_file = ""`)}},
		{"executor key not hex", [][2]string{rep(`executor_keys = ["`, `executor_keys = ["zz`)}},
		{"executor key wrong length", [][2]string{rep(`executor_keys = ["`, `executor_keys = ["ab", "`)}},
		{"no executor keys", [][2]string{rep(`executor_keys = ["`, `executor_keys = [] # "`)}},
		{"duplicate executor key", [][2]string{rep(`executor_keys = ["`, `executor_keys = ["`+strings.Repeat("ab", 32)+`", "`+strings.Repeat("ab", 32)+`", "`)}},
		{"anchor_verifier unknown", [][2]string{rep(`anchor_verifier = "self"`, `anchor_verifier = "magic"`)}},
		{"missing listen", [][2]string{rep(`listen = "127.0.0.1:0"`, `listen = ""`)}},
		{"min above max app version", [][2]string{rep("min_app_version = 3", "min_app_version = 11")}},
		{"recorder namespace not hex", [][2]string{rep(`namespace = "`, `namespace = "zz`)}},
		{"recorder namespace wrong length", [][2]string{rep(`namespace = "`, `namespace = "00`)}},
		{"recorder enabled without namespace", [][2]string{rep(`namespace = "`, `#namespace = "`)}},
		{"recorder enabled without key_name", [][2]string{rep(`key_name = "recorder"`, `key_name = ""`)}},
		{"recorder enabled without passphrase_file", [][2]string{rep(`passphrase_file = "`+e.path("keyring.pass")+`"`, `passphrase_file = ""`)}},
		{"recorder enabled without keyring_dir", [][2]string{rep(`keyring_dir = "`+e.path("keyring")+`"`, `keyring_dir = ""`)}},
		{"test keyring needs allow flag", [][2]string{rep(`keyring_backend = "file"`, `keyring_backend = "test"`)}},
		{"unknown keyring backend", [][2]string{rep(`keyring_backend = "file"`, `keyring_backend = "os"`)}},
		{"zero blobs_per_hour", [][2]string{rep("blobs_per_hour = 60", "blobs_per_hour = 0")}},
		{"zero bytes_per_day", [][2]string{rep("bytes_per_day = 67108864", "bytes_per_day = 0")}},
		{"max_blob_bytes above bytes_per_day", [][2]string{rep("bytes_per_day = 67108864", "bytes_per_day = 10")}},
		{"token over plain http to non-loopback", [][2]string{
			rep(`listen = "127.0.0.1:0"`, `listen = "0.0.0.0:8080"`),
			rep(`authorize_token_file = ""`, `authorize_token_file = "`+e.path("auth.token")+`"`)}},
		{"tls cert without key", [][2]string{rep(`tls_cert_file = ""`, `tls_cert_file = "/x.pem"`)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := edictad.ParseConfig([]byte(e.tomlOf(tc.edit...)))
			require.ErrorIs(t, err, edictad.ErrConfig)
		})
	}
}

func TestParseConfigAcceptsFibreAndInsecureOptIn(t *testing.T) {
	e := newEnv(t)
	c := e.cfg(fibreEdits()...)
	require.Equal(t, "fibre", c.Network.DA)
	_, err := edictad.ParseConfig([]byte(e.tomlOf(
		rep(`listen = "127.0.0.1:0"`, `listen = "0.0.0.0:8080"`),
		rep(`authorize_token_file = ""`, `authorize_token_file = "`+e.path("auth.token")+`"`),
		rep(`allow_insecure = false`, `allow_insecure = true`))))
	require.NoError(t, err)
}

// An inline secret is a config error, and the value is never echoed.
func TestInlineSecretsRefused(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ name, table, line string }{
		{"bridge token", "[network.bridge]\n", `token = "` + inlineCanaries[0] + `"`},
		{"grpc token", "[network.consensus_grpc]\n", `auth_token = "` + inlineCanaries[0] + `"`},
		{"passphrase", "[recorder]\n", `passphrase = "` + inlineCanaries[0] + `"`},
		{"gate seed", "[gate]\n", `key = "` + inlineCanaries[1] + `"`},
		{"gate seed alt", "[gate]\n", `seed = "` + inlineCanaries[1] + `"`},
		{"authorize token", "[http]\n", `authorize_token = "` + inlineCanaries[0] + `"`},
		{"record token", "[http]\n", `record_token = "` + inlineCanaries[0] + `"`},
		{"token in token_file slot", "[http]\n", `token_file_inline = "` + inlineCanaries[0] + `"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := edictad.ParseConfig([]byte(e.tomlOf(rep(tc.table, tc.table+tc.line+"\n"))))
			require.ErrorIs(t, err, edictad.ErrConfig)
			for _, c := range inlineCanaries {
				require.NotContains(t, err.Error(), c)
			}
		})
	}
}

func TestRecorderDisabledNeedsNoKeyAndPublishIsDisabled(t *testing.T) {
	e := newEnv(t)
	// No recorder fields at all, and no submitter dependency.
	off := e.tomlOf()
	i := strings.Index(off, "[recorder]")
	j := strings.Index(off, "[archive]")
	off = off[:i] + "[recorder]\nenabled = false\n\n" + off[j:]
	c, err := edictad.ParseConfig([]byte(off))
	require.NoError(t, err)
	require.False(t, c.Recorder.Enabled)

	e.deps.Submitter = nil
	srv, err := edictad.Start(bg, c, e.deps)
	require.NoError(t, err)
	e.srv = srv
	t.Cleanup(func() { _ = srv.Shutdown(bg) })

	_, err = e.client("").Publish(bg, []byte("blob"))
	require.ErrorIs(t, err, edictaapi.ErrPublishDisabled)

	h, err := e.client("").Health(bg)
	require.NoError(t, err)
	require.Empty(t, h.RecorderSigner)
	require.Empty(t, h.Namespace)
}

func TestRecorderDisabledNeverTouchesFeeKey(t *testing.T) {
	e := newEnv(t)
	off := e.tomlOf()
	off = off[:strings.Index(off, "[recorder]")] + "[recorder]\nenabled = false\n\n" + off[strings.Index(off, "[archive]"):]
	c, err := edictad.ParseConfig([]byte(off))
	require.NoError(t, err)
	srv, err := edictad.Start(bg, c, e.deps) // e.deps.Submitter is a tripwire here
	require.NoError(t, err)
	e.srv = srv
	t.Cleanup(func() { _ = srv.Shutdown(bg) })
	calls, signer := e.sub.touched()
	require.Zero(t, calls)
	require.Zero(t, signer)
}

// ---------------- startup order and refusals ----------------

func TestStartServesAnyChainID(t *testing.T) {
	for _, id := range []string{"testchain-7", "some-other-net-9", "celestia"} {
		t.Run(id, func(t *testing.T) {
			e := newEnv(t)
			hd := blockAt(100, 8)
			hd.ChainID = id
			e.chain.AddHeader(hd)
			e.cons.ChainID, e.cons.Providers = id, []string{id}
			e.start()
			h, err := e.client("").Health(bg)
			require.NoError(t, err)
			require.Equal(t, id, h.ChainID)
		})
	}
}

func TestStartConfiguredChainIDIsCrossChecked(t *testing.T) {
	e := newEnv(t)
	e.start(rep(`chain_id = ""`, `chain_id = "testchain-7"`))
}

func TestStartRefusesAndBindsNoListener(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(e *env)
		edits  [][2]string
		is     error
		regOpn bool // registry file may exist only if the failure is after it
	}{
		{"chain id mismatch", nil, [][2]string{rep(`chain_id = ""`, `chain_id = "other-1"`)}, node.ErrUnsupported, false},
		{"app version below min", func(e *env) { e.chain.AddHeader(blockAt(101, 2)) }, nil, node.ErrUnsupported, false},
		{"app version above max", func(e *env) { e.chain.AddHeader(blockAt(101, 11)) }, nil, node.ErrUnsupported, false},
		{"consensus on another network", func(e *env) { e.cons.ChainID = "else-1" }, nil, node.ErrUnsupported, false},
		{"provider disagrees", func(e *env) { e.cons.Providers = []string{"testchain-7", "else-1"} }, nil, node.ErrUnsupported, false},
		{"head stale", func(e *env) { e.deps.Clock = clock{t0.AddDate(0, 0, 1)} }, nil, node.ErrUnsupported, false},
		{"bridge node down", func(e *env) { e.chain.Fail = node.ErrUnavailable }, nil, node.ErrUnsupported, false},
		{"consensus down", func(e *env) { e.cons.Fail = node.ErrUnavailable }, nil, node.ErrUnsupported, false},
		{"gate key file group-readable", func(e *env) { writeFile(t, e.path("gate.ed25519"), e.seed, 0o640) }, nil, secret.ErrPermissions, false},
		{"gate key file wrong size", func(e *env) { writeFile(t, e.path("gate.ed25519"), e.seed[:31], 0o600) }, nil, nil, false},
		{"gate key file missing", func(e *env) { _ = os.Remove(e.path("gate.ed25519")) }, nil, nil, false},
		{"token file world-readable", func(e *env) { writeFile(t, e.path("auth.token"), []byte("tok"), 0o644) },
			[][2]string{rep(`authorize_token_file = ""`, `authorize_token_file = "`+"%AUTH%"+`"`)}, secret.ErrPermissions, false},
		{"agent allowlist missing", func(e *env) { _ = os.Remove(e.path("agents.toml")) }, nil, nil, false},
		{"gate key listed as agent", func(e *env) {
			writeFile(t, e.path("agents.toml"), []byte("[[agents]]\nagent_id = \"agent-1\"\npubkey = \""+hexOf(e.gatePub)+"\"\n"), 0o600)
		}, nil, nil, true},
		{"executor key listed as agent", func(e *env) {
			writeFile(t, e.path("agents.toml"), []byte("[[agents]]\nagent_id = \"agent-1\"\npubkey = \""+hexOf(e.execPub)+"\"\n"), 0o600)
		}, nil, nil, true},
		{"recorder namespace reserved", nil, [][2]string{rep(`namespace = "`, `namespace = "01`)}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			edits := make([][2]string, len(tc.edits))
			for i, ed := range tc.edits {
				edits[i] = [2]string{ed[0], strings.ReplaceAll(ed[1], "%AUTH%", e.path("auth.token"))}
			}
			var cfg edictad.Config
			var perr error
			cfg, perr = edictad.ParseConfig([]byte(e.tomlOf(edits...)))
			if perr != nil { // refused at parse: still no listener, trivially
				require.ErrorIs(t, perr, edictad.ErrConfig)
				return
			}
			srv, err := edictad.Start(bg, cfg, e.deps)
			require.Error(t, err)
			require.Nil(t, srv)
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
			require.Zero(t, e.listens, "no listener may be bound after a failed check")
			if !tc.regOpn {
				require.False(t, e.registryExists(), "registry must not be opened before Check and Preflight pass")
			}
		})
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestStartOrder(t *testing.T) {
	e := newEnv(t)
	var order []string
	e.deps.Reader = &orderReader{Reader: e.chain, log: &order, regExists: e.registryExists}
	e.deps.Listen = func(n, a string) (net.Listener, error) {
		order = append(order, "listen")
		if e.registryExists() {
			order = append(order, "registry-open-before-listen")
		}
		return net.Listen(n, a)
	}
	srv, err := edictad.Start(bg, e.cfg(), e.deps)
	require.NoError(t, err)
	e.srv = srv
	t.Cleanup(func() { _ = srv.Shutdown(bg) })
	require.Equal(t, []string{"check(registry absent)", "listen", "registry-open-before-listen"}, firstOf(order))
}

// firstOf collapses repeated entries.
func firstOf(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

type orderReader struct {
	node.Reader
	log       *[]string
	regExists func() bool
}

func (r *orderReader) Head(ctx context.Context) (node.Header, error) {
	if !r.regExists() {
		*r.log = append(*r.log, "check(registry absent)")
	} else {
		*r.log = append(*r.log, "check(registry PRESENT)")
	}
	return r.Reader.Head(ctx)
}

func TestStartRefusesBusyListenAddress(t *testing.T) {
	e := newEnv(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	_, err = edictad.Start(bg, e.cfg(rep(`listen = "127.0.0.1:0"`, `listen = "`+l.Addr().String()+`"`)), e.deps)
	require.Error(t, err)
}

// ---------------- wiring ----------------

func TestWiringAuthorizeAndRecord(t *testing.T) {
	e := newEnv(t)
	e.start()
	c := e.client("")
	out, err := c.Authorize(bg, []byte("env-1"), []byte("act-1"))
	require.NoError(t, err)
	require.Equal(t, []byte("auth-bytes"), out)
	require.Equal(t, "env-1", e.spy.env)
	require.Equal(t, "act-1", e.spy.action)

	sig := make([]byte, 64)
	rc, err := c.Record(bg, []byte("env-2"), "rail-ref-9", e.execPub, sig)
	require.NoError(t, err)
	require.Equal(t, []byte("receipt-bytes"), rc)
	require.Equal(t, "env-2", e.spy.env)
	require.Equal(t, "rail-ref-9", e.spy.ref)
	require.Equal(t, []byte(e.execPub), e.spy.pub)
	require.Equal(t, sig, e.spy.sig)
	a, r := e.spy.calls()
	require.Equal(t, 1, a)
	require.Equal(t, 1, r)
}

// Without the test seam the REAL gate answers: a garbage envelope is a 400,
// not a 404/500 (the endpoint is wired to a gate).
func TestRealGateIsBehindAuthorizeAndRecord(t *testing.T) {
	e := newEnv(t)
	e.deps.WrapGate = nil
	e.start()
	for _, tc := range []struct {
		path string
		body []byte
	}{
		{"/v0/authorize", authorizeBody("garbage", "act")},
		{"/v0/record", recordBody("garbage", "ref", e.execPub, make([]byte, 64))},
	} {
		resp := post(t, e.srv, tc.path, "", tc.body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, tc.path)
	}
}

func TestWiringPublishReachesRecorderAndQuota(t *testing.T) {
	e := newEnv(t)
	e.start(rep("blobs_per_hour = 60", "blobs_per_hour = 1"))
	c := e.client("")
	pub, err := c.Publish(bg, []byte("decision payload one"))
	require.NoError(t, err)
	require.Equal(t, nsBytes, pub.Ref.Namespace)
	require.Equal(t, recAddr, pub.Ref.Signer)
	calls, _ := e.sub.touched()
	require.Equal(t, 1, calls)

	// Per-agent quota from the config: the second distinct blob is refused.
	_, err = c.Publish(bg, []byte("decision payload two"))
	require.ErrorIs(t, err, edictaapi.ErrQuotaExceeded)
	calls, _ = e.sub.touched()
	require.Equal(t, 1, calls)
}

func TestPublishRequiresAllowlistedAgent(t *testing.T) {
	e := newEnv(t)
	e.start()
	c := e.client("")
	bad, err := edictaapi.NewClient("http://"+e.srv.Addr(), edictaapi.NewSecret(""), agent{e.agentPrv, "agent-unknown"}, nil,
		edictaapi.WithGateID("gate-test-1"), edictaapi.WithClock(clock{t0}))
	require.NoError(t, err)
	_, err = bad.Publish(bg, []byte("x"))
	require.ErrorIs(t, err, edictaapi.ErrPublishSignature)
	calls, _ := e.sub.touched()
	require.Zero(t, calls)
	_ = c
}

func TestHealthReportsEverything(t *testing.T) {
	e := newEnv(t)
	e.start()
	h, err := e.client("").Health(bg)
	require.NoError(t, err)
	require.Equal(t, "testchain-7", h.ChainID)
	require.EqualValues(t, 100, h.HeadHeight)
	require.Equal(t, "gate-test-1", h.GateID)
	require.Equal(t, []byte(e.gatePub), h.GatePubKey)
	require.Equal(t, recAddr, h.RecorderSigner)
	require.Equal(t, nsBytes, h.Namespace)
	require.Equal(t, []uint64{2}, h.AllowedDA, "da = blob is the single allowed DA")
}

func TestDABlobRejectsDA1OverHTTP(t *testing.T) {
	e := newEnv(t)
	e.deps.WrapGate = nil
	e.start()
	c := gatefix.Clone(gatefix.FibreTemplate(t))
	action := []byte("act")
	sum := sha256.Sum256(action)
	c.AgentID, c.AgentPubKey = "agent-1", bytes.Clone(e.agentPub)
	c.Scope.GateID = "gate-test-1"
	c.Action.Type, c.Action.Hash = "application/vnd.edicta.test.v0+cbor", sum[:]
	c.IssuedAt, c.ValidUntil = uint64(t0.Unix())-5, uint64(t0.Unix())+600
	require.EqualValues(t, 1, c.PayloadRef.DA)
	env, _ := gatefix.SignWith(t, e.agentPrv, c)
	_, err := e.client("").Authorize(bg, env, action)
	require.ErrorIs(t, err, gate.ErrDANotAllowed)
}

// Restart: the registry file survives and is reused by the next instance.
func TestRegistryFileReusedAcrossRestarts(t *testing.T) {
	e := newEnv(t)
	e.start()
	require.NoError(t, e.srv.Shutdown(bg))
	before, err := os.Stat(e.path("registry.db"))
	require.NoError(t, err)
	require.NotZero(t, before.Size())

	srv, err := edictad.Start(bg, e.cfg(), e.deps)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(bg) })
	after, err := os.Stat(e.path("registry.db"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, after.Size(), before.Size(), "registry must not be recreated")
}

// ---------------- bearer tokens ----------------

func TestBearerTokens(t *testing.T) {
	e := newEnv(t)
	e.start(
		rep(`authorize_token_file = ""`, `authorize_token_file = "`+e.path("auth.token")+`"`),
		rep(`record_token_file = ""`, `record_token_file = "`+e.path("rec.token")+`"`))
	sig := make([]byte, 64)

	for _, tok := range []string{"", "wrong", canaryAuthTok[:len(canaryAuthTok)-1], canaryAuthTok + "x", canaryRecTok} {
		_, err := e.client(tok).Authorize(bg, []byte("e"), []byte("a"))
		require.ErrorIs(t, err, edictaapi.ErrTokenInvalid, "authorize token %q", tok)
	}
	for _, tok := range []string{"", "wrong", canaryAuthTok} {
		_, err := e.client(tok).Record(bg, []byte("e"), "r", e.execPub, sig)
		require.ErrorIs(t, err, edictaapi.ErrTokenInvalid, "record token %q", tok)
	}
	a, r := e.spy.calls()
	require.Zero(t, a+r, "the gate must not be reached without a valid token")

	_, err := e.client(canaryAuthTok).Authorize(bg, []byte("e"), []byte("a"))
	require.NoError(t, err)
	_, err = e.client(canaryRecTok).Record(bg, []byte("e"), "r", e.execPub, sig)
	require.NoError(t, err)

	// Wrong scheme or malformed header: 401.
	for _, h := range []string{"", "Basic " + canaryAuthTok, canaryAuthTok, "Bearer", "Bearer  " + canaryAuthTok, "bearer-" + canaryAuthTok} {
		resp := post(t, e.srv, "/v0/authorize", h, authorizeBody("e", "a"))
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "header %q", h)
	}
	resp := post(t, e.srv, "/v0/authorize", "Bearer "+canaryAuthTok, authorizeBody("e", "a"))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Health is open.
	_, err = e.client("").Health(bg)
	require.NoError(t, err)
}

func TestNoTokenConfiguredMeansOpen(t *testing.T) {
	e := newEnv(t)
	e.start()
	_, err := e.client("").Authorize(bg, []byte("e"), []byte("a"))
	require.NoError(t, err)
}

// The comparison must be constant time: the package has to use
// crypto/subtle and must not compare token bytes with == / bytes.Equal.
func TestTokenComparisonIsConstantTime(t *testing.T) {
	files := nonTestSources(t)
	var uses bool
	for name, src := range files {
		if strings.Contains(src, `"crypto/subtle"`) && strings.Contains(src, "ConstantTimeCompare") {
			uses = true
		}
		require.NotRegexp(t, regexp.MustCompile(`(?i)token[A-Za-z]*\)?\s*==\s|bytes\.Equal\([^)]*[Tt]oken|string\(.*[Tt]oken.*\)\s*==`), src, name)
	}
	require.True(t, uses, "token check must use subtle.ConstantTimeCompare")
}

// ---------------- secrets in logs ----------------

func TestNoSecretInLogs(t *testing.T) {
	e := newEnv(t)
	e.start(
		rep(`authorize_token_file = ""`, `authorize_token_file = "`+e.path("auth.token")+`"`),
		rep(`record_token_file = ""`, `record_token_file = "`+e.path("rec.token")+`"`))
	sig := make([]byte, 64)
	_, _ = e.client(canaryAuthTok).Authorize(bg, []byte("e"), []byte("a"))
	_, _ = e.client("wrong-"+canaryAuthTok).Authorize(bg, []byte("e"), []byte("a"))
	_, _ = e.client(canaryRecTok).Record(bg, []byte("e"), "r", e.execPub, sig)
	_, _ = e.client("").Record(bg, []byte("e"), "r", e.execPub, sig)
	_, _ = e.client("").Publish(bg, []byte("blob"))
	_, _ = e.client("").Health(bg)
	post(t, e.srv, "/v0/authorize", "Bearer "+canaryAuthTok+"junk", []byte{0xff})
	require.NoError(t, e.srv.Shutdown(bg))

	logs := e.logs.String()
	secrets := [][]byte{[]byte(canaryAuthTok), []byte(canaryRecTok), []byte(canaryBNTok), []byte(canaryPass),
		e.seed, []byte(hexOf(e.seed)), []byte(b64(e.seed)), []byte(hexOf(e.agentPrv)), []byte(hexOf(e.agentPrv.Seed()))}
	for _, s := range secrets {
		require.NotContains(t, logs, string(s))
	}
	require.NotContains(t, logs, "Authorization")
	require.NotContains(t, logs, "Bearer")
}

func b64(b []byte) string {
	const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3; j++ {
			v <<= 8
			if i+j < len(b) {
				v |= uint32(b[i+j])
				n++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= n {
				out = append(out, a[(v>>(18-6*uint(j)))&63])
			}
		}
	}
	return string(out)
}

func TestStartupErrorsDoNotLeakSecrets(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.path("gate.ed25519"), e.seed, 0o644)
	_, err := edictad.Start(bg, e.cfg(), e.deps)
	require.Error(t, err)
	for _, s := range []string{hexOf(e.seed), string(e.seed), canaryBNTok, canaryPass} {
		require.NotContains(t, err.Error(), s)
	}
}

// ---------------- repo hygiene ----------------

func TestNothingNetworkSpecificInSource(t *testing.T) {
	banned := regexp.MustCompile(`(?i)mocha|mainnet|arabica|"celestia"|"testnet`)
	fset := token.NewFileSet()
	for name := range nonTestSources(t) {
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				require.NotRegexp(t, banned, bl.Value, "%s: network-specific literal %s", name, bl.Value)
			}
			return true
		})
	}
}

func TestNoSecretAssignmentsWithValuesInSource(t *testing.T) {
	re := regexp.MustCompile(`(?i)(token|passphrase|password|secret|seed)[A-Za-z_]*\s*(:=|=)\s*"[^"]{4,}"`)
	for name, src := range nonTestSources(t) {
		require.NotRegexp(t, re, src, name)
	}
}

func nonTestSources(t *testing.T) map[string]string {
	t.Helper()
	m, err := filepath.Glob("*.go")
	require.NoError(t, err)
	out := map[string]string{}
	for _, f := range m {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		out[f] = string(b)
	}
	require.NotEmpty(t, out, "package edictad has no source yet")
	return out
}

// ---------------- graceful shutdown ----------------

func TestGracefulShutdownFinishesInFlightAndClosesRegistry(t *testing.T) {
	e := newEnv(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	e.spy.authFn = func() ([]byte, error) {
		close(entered)
		<-release
		return []byte("auth-bytes"), nil
	}
	srv := e.start()

	type res struct {
		out []byte
		err error
	}
	got := make(chan res, 1)
	go func() {
		out, err := e.client("").Authorize(bg, []byte("e"), []byte("a"))
		got <- res{out, err}
	}()
	<-entered

	down := make(chan error, 1)
	go func() { down <- srv.Shutdown(bg) }()
	close(release)

	r := <-got
	require.NoError(t, r.err, "in-flight request must complete")
	require.Equal(t, []byte("auth-bytes"), r.out)
	require.NoError(t, <-down)

	// The listener is gone.
	_, err := net.Dial("tcp", srv.Addr())
	require.Error(t, err)

	// The registry file lock was released: it can be reopened.
	reg, err := boltreg.Open(e.path("registry.db"), 1)
	require.NoError(t, err)
	require.NoError(t, reg.Close())

	// Shutdown is idempotent.
	require.NoError(t, srv.Shutdown(bg))
}

func TestShutdownHonoursContextDeadline(t *testing.T) {
	e := newEnv(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	e.spy.authFn = func() ([]byte, error) { close(entered); <-release; return []byte("a"), nil }
	srv := e.start()
	go func() { _, _ = e.client("").Authorize(bg, []byte("e"), []byte("a")) }()
	<-entered
	ctx, cancel := context.WithCancel(bg)
	cancel()
	err := srv.Shutdown(ctx)
	require.ErrorIs(t, err, context.Canceled)
	close(release)
	require.NoError(t, srv.Shutdown(bg))
}

// A real gate: an Authorization issued before shutdown is durable (the
// registry is closed only after in-flight work). Reopening the file must work
// and the file must be a valid registry.
func TestRegistryReopensAfterRealGateRun(t *testing.T) {
	e := newEnv(t)
	e.deps.WrapGate = nil
	srv := e.start()
	_ = post(t, srv, "/v0/authorize", "", authorizeBody("garbage", "act"))
	require.NoError(t, srv.Shutdown(bg))
	reg, err := boltreg.Open(e.path("registry.db"), 1)
	require.NoError(t, err)
	require.NoError(t, reg.Close())
}
