package doctor_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/config"
)

func status(t *testing.T, got map[string]doctor.Item, name string) doctor.Item {
	t.Helper()
	it, ok := got[name]
	require.True(t, ok, "check %s did not run", name)
	return it
}

func TestHealthyStackIsAllOK(t *testing.T) {
	s := newStack(t)
	got := s.run()
	require.Len(t, got, 14, "every check of the design runs")
	for name, it := range got {
		assert.Equal(t, doctor.OK, it.Status, "%s: %s | fix: %s", name, it.Cause, it.Fix)
		assert.Empty(t, it.Fix, name)
	}
	for _, name := range []string{"config", "endpoints", "chain", "fibre", "fees", "keyring", "keydirs", "clock", "archive", "gate", "signer", "settlement", "facilitator", "balances"} {
		assert.Contains(t, got, name)
	}
}

func TestChecksRunInTheDesignOrder(t *testing.T) {
	s := newStack(t)
	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{}))
	var names []string
	for _, it := range rep.Items {
		names = append(names, it.Name)
	}
	assert.Equal(t, []string{"config", "endpoints", "chain", "fibre", "fees", "keyring", "keydirs", "clock", "archive", "gate", "signer", "settlement", "facilitator", "balances"}, names)
}

func TestConfigCheck(t *testing.T) {
	ctx := context.Background()
	var c config.Config
	r := doctor.ConfigCheck{Err: errors.New("config: invalid configuration: unknown keys [x]")}.Run(ctx, c)
	assert.Equal(t, doctor.Fail, r.Status)
	assert.Contains(t, r.Cause, "unknown keys")
	assert.NotEmpty(t, r.Fix)

	r = doctor.ConfigCheck{Drift: []string{"preset mocha: file written against version 1, this binary has version 2"}}.Run(ctx, c)
	assert.Equal(t, doctor.Warn, r.Status)
	assert.Contains(t, r.Cause, "version 2")

	r = doctor.ConfigCheck{Presets: "mocha v1"}.Run(ctx, c)
	assert.Equal(t, doctor.OK, r.Status)
	assert.Contains(t, r.Cause, "mocha v1", "ok prints the preset version")
}

func TestEndpoints(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"dns", func(s *stack) { s.net.lookup["rpc-mocha.pops.one"] = errors.New("no such host") }, doctor.Fail, "DNS: cannot resolve rpc-mocha.pops.one"},
		{"tcp refused", func(s *stack) { s.net.tcp["grpc-mocha.pops.one:9090"] = errors.New("connection refused") }, doctor.Fail, "network.consensus_grpc"},
		{"tls expired", func(s *stack) {
			s.net.tls["public-endpoint.celestia-mocha.quiknode.pro:443"] = errors.New("x509: certificate has expired or is not yet valid")
		}, doctor.Fail, "TLS: x509: certificate has expired"},
		{"tls to a plain server", func(s *stack) {
			s.net.tls["public-endpoint.celestia-mocha.quiknode.pro:443"] = tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}
		}, doctor.Fail, "scheme"},
		{"http to a tls server", func(s *stack) {
			s.net.http["https://rpc-mocha.pops.one/status"] = doctor.Response{Status: 400, Body: []byte("Client sent an HTTP request to an HTTPS server.")}
		}, doctor.Fail, "scheme"},
		{"not comet", func(s *stack) {
			s.net.http["https://rpc-mocha.pops.one/status"] = doctor.Response{Status: 200, Body: []byte(`<html>`)}
		}, doctor.Fail, "CometBFT"},
		{"comet 404", func(s *stack) {
			s.net.http["https://rpc-mocha.pops.one/status"] = doctor.Response{Status: 404}
		}, doctor.Fail, "HTTP 404"},
		{"second comet down is only a warning", func(s *stack) {
			s.net.tcp["rpc-1.testnet.celestia.nodes.guru:443"] = nil
			s.net.tls["rpc-1.testnet.celestia.nodes.guru:443"] = errors.New("connection refused")
		}, doctor.Warn, "comet_rpc[1]"},
		{"bridge token refused", func(s *stack) { s.chain.headErr = errors.New("401 Unauthorized") }, doctor.Fail, "auth token"},
		{"grpc unanswered", func(s *stack) { s.chain.consensusEr = errors.New("transport: connection reset") }, doctor.Fail, "gRPC"},
		{"token file too open", func(s *stack) {
			f := filepath.Join(s.dir, "bridge.token")
			mustWrite(s.t, f, []byte("tok\n"), 0o644)
			s.cfg.Network.Bridge.TokenFile = f
		}, doctor.Fail, "token_file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "endpoints")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
			assert.NotEmpty(t, it.Fix)
		})
	}
}

func TestEndpointsUseSNIAndLocalHostsNeedNoDNS(t *testing.T) {
	s := newStack(t)
	s.cfg.Network.CometRPC = append(s.cfg.Network.CometRPC, "http://127.0.0.1:26657")
	s.net.lookup["127.0.0.1"] = errors.New("must not be looked up")
	it := status(t, s.run(), "endpoints")
	assert.Equal(t, doctor.OK, it.Status, it.Cause)
	assert.Contains(t, s.net.dialled, "tls:rpc-mocha.pops.one:443:rpc-mocha.pops.one")
	assert.Contains(t, s.net.dialled, "tcp:127.0.0.1:26657")
}

func TestChain(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"wrong consensus chain", func(s *stack) { s.chain.consensusID = "celestia" }, doctor.Fail, "node at grpc-mocha.pops.one:9090 is chain celestia, config expects mocha-5"},
		{"wrong bridge chain", func(s *stack) { s.chain.head.ChainID = "arabica-11" }, doctor.Fail, "is chain arabica-11, config expects mocha-5"},
		{"wrong comet chain", func(s *stack) {
			s.net.http["https://rpc-mocha.pops.one/status"] = doctor.Response{Status: 200, Body: []byte(cometStatus("celestia", 1, false))}
		}, doctor.Fail, "is chain celestia"},
		{"comet catching up", func(s *stack) {
			s.net.http["https://rpc-mocha.pops.one/status"] = doctor.Response{Status: 200, Body: []byte(cometStatus("mocha-5", 1, true))}
		}, doctor.Fail, "catching up"},
		{"head stalled", func(s *stack) { s.chain.head.Time = testNow.Add(-10 * time.Minute) }, doctor.Fail, "off the local clock"},
		{"app version too old", func(s *stack) { s.chain.head.AppVersion = 2 }, doctor.Fail, "app version 2 is outside the pinned 3..10"},
		{"app version too new", func(s *stack) { s.chain.head.AppVersion = 11 }, doctor.Fail, "app version 11"},
		{"fibre pins one version", func(s *stack) {
			s.cfg.Recorder.DA, s.cfg.Recorder.OwnNode = config.DAFibre, true
			s.chain.head.AppVersion = 9
		}, doctor.Fail, "pinned 10..10"},
		{"consensus lags", func(s *stack) { s.chain.height = 100 }, doctor.Warn, "behind"},
		{"cannot open", func(s *stack) {
			s.env.OpenChain = func(context.Context, config.Network) (doctor.Chain, error) { return nil, errBoom }
		}, doctor.Fail, "cannot open the node connections"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "chain")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestChainIsOpenedOncePerRun(t *testing.T) {
	s := newStack(t)
	calls := 0
	s.env.OpenChain = func(context.Context, config.Network) (doctor.Chain, error) { calls++; return s.chain, nil }
	s.run()
	assert.Equal(t, 1, calls)
	require.NoError(t, s.env.Close())
	assert.True(t, s.chain.closed)
}

func fibreStack(t *testing.T) *stack {
	s := newStack(t)
	s.cfg.Recorder.DA, s.cfg.Recorder.OwnNode = config.DAFibre, true
	s.cfg.Recorder.MaxBlobBytes = 1 << 20
	return s
}

func TestFibre(t *testing.T) {
	t.Run("not used", func(t *testing.T) {
		it := status(t, newStack(t).run(), "fibre")
		assert.Equal(t, doctor.OK, it.Status)
		assert.Contains(t, it.Cause, "not used")
	})
	t.Run("ok", func(t *testing.T) {
		it := status(t, fibreStack(t).run(), "fibre")
		assert.Equal(t, doctor.OK, it.Status, it.Cause)
	})
	t.Run("no module", func(t *testing.T) {
		s := fibreStack(t)
		s.chain.paramsErr = node.ErrNotFound
		it := status(t, s.run(), "fibre")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "no x/fibre module")
	})
	t.Run("params unreadable", func(t *testing.T) {
		s := fibreStack(t)
		s.chain.paramsErr = errBoom
		it := status(t, s.run(), "fibre")
		assert.Equal(t, doctor.Fail, it.Status)
	})
	t.Run("escrow below headroom", func(t *testing.T) {
		s := fibreStack(t)
		s.cfg.Recorder.EscrowHeadroomUtia = 1_000
		need, err := doctor.EscrowNeed(1<<20, 1_000)
		require.NoError(t, err)
		s.chain.escrow.AvailableUtia = need - 1
		it := status(t, s.run(), "fibre")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "utia below headroom")
		assert.Contains(t, it.Cause, "(one upload of max_blob_bytes)")
		assert.Contains(t, it.Fix, "celestia1recorder")
	})
	t.Run("escrow exactly the need", func(t *testing.T) {
		s := fibreStack(t)
		need, err := doctor.EscrowNeed(1<<20, 0)
		require.NoError(t, err)
		s.chain.escrow.AvailableUtia = need
		assert.Equal(t, doctor.OK, status(t, s.run(), "fibre").Status)
	})
	t.Run("keyring broken", func(t *testing.T) {
		s := fibreStack(t)
		s.kr.err["recorder"] = node.ErrBadPassphrase
		it := status(t, s.run(), "fibre")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "does not open recorder")
	})
}

func TestEscrowNeedRefusesAnImpossibleBlob(t *testing.T) {
	_, err := doctor.EscrowNeed(0, 0)
	require.Error(t, err)
	_, err = doctor.EscrowNeed(1<<40, 0)
	require.Error(t, err)
	_, err = doctor.EscrowNeed(1<<20, ^uint64(0))
	require.Error(t, err)
}

func TestFees(t *testing.T) {
	t.Run("price unreadable", func(t *testing.T) {
		s := newStack(t)
		s.chain.priceErr = errBoom
		it := status(t, s.run(), "fees")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Fix, "read from the node")
	})
	t.Run("recorder balance below one day", func(t *testing.T) {
		s := newStack(t)
		// 100 blobs x ceil(0.002 x 250000) = 50000 utia
		s.chain.balances["celestia1recorder"] = 49_999
		it := status(t, s.run(), "fees")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "recorder celestia1recorder holds 49999 utia")
		assert.Contains(t, it.Cause, "needs about 50000")
	})
	t.Run("exactly one day", func(t *testing.T) {
		s := newStack(t)
		s.chain.balances["celestia1recorder"] = 50_000
		s.chain.balances["celestia1publisher"] = 50_000
		assert.Equal(t, doctor.OK, status(t, s.run(), "fees").Status)
	})
	t.Run("publisher balance", func(t *testing.T) {
		s := newStack(t)
		s.chain.balances["celestia1publisher"] = 0
		it := status(t, s.run(), "fees")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "publisher")
	})
	t.Run("keyring broken is a warning here", func(t *testing.T) {
		s := newStack(t)
		s.kr.err["recorder"] = errBoom
		it := status(t, s.run(), "fees")
		assert.Equal(t, doctor.Warn, it.Status)
	})
}

func TestKeyring(t *testing.T) {
	t.Run("wrong passphrase", func(t *testing.T) {
		s := newStack(t)
		s.kr.err["recorder"] = node.ErrBadPassphrase
		it := status(t, s.run(), "keyring")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "keyring passphrase file "+s.cfg.Recorder.PassphraseFile+" does not open recorder")
	})
	t.Run("passphrase file open to others", func(t *testing.T) {
		s := newStack(t)
		require.NoError(t, os.Chmod(s.cfg.Publisher.PassphraseFile, 0o644))
		it := status(t, s.run(), "keyring")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, "publisher passphrase file")
		assert.Contains(t, it.Fix, "0600")
	})
	t.Run("passphrase file missing", func(t *testing.T) {
		s := newStack(t)
		require.NoError(t, os.Remove(s.cfg.Recorder.PassphraseFile))
		assert.Equal(t, doctor.Fail, status(t, s.run(), "keyring").Status)
	})
	t.Run("no keyring", func(t *testing.T) {
		s := newStack(t)
		s.cfg.Recorder, s.cfg.Publisher = nil, nil
		assert.Equal(t, doctor.OK, status(t, s.run(), "keyring").Status)
	})
}

func TestKeyDirs(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		s := newStack(t)
		it := status(t, s.run(), "keydirs")
		assert.Equal(t, doctor.OK, it.Status, it.Cause)
	})
	t.Run("keys directory writable by the group", func(t *testing.T) {
		s := newStack(t)
		keys := filepath.Dir(s.cfg.Gate.KeyFile)
		require.NoError(t, os.Chmod(keys, 0o770))
		t.Cleanup(func() { _ = os.Chmod(keys, 0o700) })
		it := status(t, s.run(), "keydirs")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, keys)
		assert.Contains(t, it.Cause, "chmod 700")
		assert.Contains(t, it.Fix, "chmod 700")
	})
	t.Run("keyring parent writable by others", func(t *testing.T) {
		s := newStack(t)
		require.NoError(t, os.MkdirAll(s.cfg.Recorder.KeyringDir, 0o700))
		parent := filepath.Dir(s.cfg.Recorder.KeyringDir)
		require.NoError(t, os.Chmod(parent, 0o707))
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		it := status(t, s.run(), "keydirs")
		assert.Equal(t, doctor.Fail, it.Status)
		assert.Contains(t, it.Cause, parent)
	})
	t.Run("missing directories are left to the key checks", func(t *testing.T) {
		s := newStack(t)
		s.cfg.Agent.KeyFile = filepath.Join(s.dir, "nowhere", "agent.ed25519")
		assert.Equal(t, doctor.OK, status(t, s.run(), "keydirs").Status)
	})
	t.Run("no keys", func(t *testing.T) {
		var c config.Config
		r := doctor.Run(context.Background(), c, doctor.Checks(&doctor.Env{}, doctor.ConfigCheck{}))
		for _, it := range r.Items {
			if it.Name == "keydirs" {
				assert.Equal(t, doctor.OK, it.Status)
			}
		}
	})
}

func TestClock(t *testing.T) {
	tests := []struct {
		name   string
		clocks []doctor.TimeSource
		status doctor.Status
		cause  string
	}{
		{"both fine", []doctor.TimeSource{fakeClock{name: "a", off: 900 * time.Millisecond}, fakeClock{name: "b", off: -900 * time.Millisecond}}, doctor.OK, "below 1s"},
		{"one source over 1 s", []doctor.TimeSource{fakeClock{name: "a"}, fakeClock{name: "b", off: 1100 * time.Millisecond}}, doctor.Fail, "b says the clock is off by"},
		{"negative over 1 s", []doctor.TimeSource{fakeClock{name: "a", off: -2 * time.Second}, fakeClock{name: "b"}}, doctor.Fail, "a says"},
		{"one source down", []doctor.TimeSource{fakeClock{name: "a"}, fakeClock{name: "b", err: errBoom}}, doctor.Warn, "only one time source"},
		{"none answers", []doctor.TimeSource{fakeClock{name: "a", err: errBoom}, fakeClock{name: "b", err: errBoom}}, doctor.Fail, "no time source answered"},
		{"no sources", nil, doctor.Fail, "no time source answered"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			s.env.Clocks = tc.clocks
			it := status(t, s.run(), "clock")
			assert.Equal(t, tc.status, it.Status, it.Cause)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestArchive(t *testing.T) {
	t.Run("writable and absent dir is fine", func(t *testing.T) {
		s := newStack(t)
		it := status(t, s.run(), "archive")
		assert.Equal(t, doctor.OK, it.Status, it.Cause)
		_, err := os.Stat(s.cfg.Archive.Dir)
		assert.True(t, os.IsNotExist(err), "doctor creates no directory")
		ents, _ := os.ReadDir(s.dir)
		for _, e := range ents {
			assert.NotContains(t, e.Name(), ".doctor-", "no probe file is left behind")
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		s := newStack(t)
		f := filepath.Join(s.dir, "afile")
		mustWrite(t, f, []byte("x"), 0o600)
		s.cfg.Archive.Dir = f
		assert.Equal(t, doctor.Fail, status(t, s.run(), "archive").Status)
	})
	t.Run("read-only parent", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes anywhere")
		}
		s := newStack(t)
		ro := filepath.Join(s.dir, "ro")
		require.NoError(t, os.Mkdir(ro, 0o500))
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
		s.cfg.Archive.Dir = filepath.Join(ro, "archive")
		assert.Equal(t, doctor.Fail, status(t, s.run(), "archive").Status)
	})
	overlap := func(t *testing.T, archive, capture func(root string) string, wantFail bool) {
		s := newStack(t)
		root := t.TempDir()
		s.cfg.Archive.Dir = archive(root)
		s.cfg.Capture = &config.Capture{Dir: capture(root), CometRPC: "https://rpc-mocha.pops.one"}
		it := status(t, s.run(), "archive")
		if wantFail {
			assert.Equal(t, doctor.Fail, it.Status)
			assert.Contains(t, it.Cause, "one lies inside the other")
		} else {
			assert.Equal(t, doctor.OK, it.Status, it.Cause)
		}
	}
	t.Run("capture inside archive", func(t *testing.T) {
		overlap(t, func(r string) string { return filepath.Join(r, "a") }, func(r string) string { return filepath.Join(r, "a", "c") }, true)
	})
	t.Run("archive inside capture", func(t *testing.T) {
		overlap(t, func(r string) string { return filepath.Join(r, "c", "a") }, func(r string) string { return filepath.Join(r, "c") }, true)
	})
	t.Run("same directory spelled two ways", func(t *testing.T) {
		overlap(t, func(r string) string { return filepath.Join(r, "a") }, func(r string) string { return filepath.Join(r, "x", "..", "a") }, true)
	})
	t.Run("through a symlink", func(t *testing.T) {
		s := newStack(t)
		root := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(root, "real"), 0o700))
		require.NoError(t, os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")))
		s.cfg.Archive.Dir = filepath.Join(root, "real")
		s.cfg.Capture = &config.Capture{Dir: filepath.Join(root, "link", "cap"), CometRPC: "https://rpc-mocha.pops.one"}
		assert.Equal(t, doctor.Fail, status(t, s.run(), "archive").Status)
	})
	t.Run("siblings", func(t *testing.T) {
		overlap(t, func(r string) string { return filepath.Join(r, "a") }, func(r string) string { return filepath.Join(r, "ab") }, false)
	})
	t.Run("mirror down is a warning", func(t *testing.T) {
		s := newStack(t)
		s.cfg.Archive.MirrorURLs = []string{"https://mirror.example.org"}
		s.net.httpErr["https://mirror.example.org"] = errBoom
		assert.Equal(t, doctor.Warn, status(t, s.run(), "archive").Status)
	})
}

func TestGate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"gate key too open", func(s *stack) { require.NoError(s.t, os.Chmod(s.cfg.Gate.KeyFile, 0o644)) }, doctor.Fail, "gate key file"},
		{"gate key wrong length", func(s *stack) { mustWrite(s.t, s.cfg.Gate.KeyFile, []byte("short"), 0o600) }, doctor.Fail, "exactly 32 bytes"},
		{"agent key missing", func(s *stack) { require.NoError(s.t, os.Remove(s.cfg.Agent.KeyFile)) }, doctor.Fail, "agent key file"},
		{"executor is the gate", func(s *stack) { s.cfg.Gate.ExecutorKeys = []string{hex.EncodeToString(s.gatePub)} }, doctor.Fail, "gate's own key"},
		{"executor is the agent", func(s *stack) { s.cfg.Gate.ExecutorKeys = []string{hex.EncodeToString(s.agentPub)} }, doctor.Fail, "agent's key"},
		{"gate and agent share a key", func(s *stack) {
			b, err := os.ReadFile(s.cfg.Agent.KeyFile)
			require.NoError(s.t, err)
			mustWrite(s.t, s.cfg.Gate.KeyFile, b, 0o600)
		}, doctor.Fail, "one key"},
		{"allowlist missing", func(s *stack) { require.NoError(s.t, os.Remove(s.cfg.Gate.AllowlistFile)) }, doctor.Fail, "allowlist_file"},
		{"allowlist unknown key", func(s *stack) {
			mustWrite(s.t, s.cfg.Gate.AllowlistFile, []byte("[[agents]]\nagent_id = \"a\"\nx = 1\n"), 0o600)
		}, doctor.Fail, "allowlist_file is not"},
		{"agent not listed", func(s *stack) { s.cfg.Agent.ID = "someone-else" }, doctor.Fail, "not in the allowlist"},
		{"agent listed with another key", func(s *stack) {
			mustWrite(s.t, s.cfg.Gate.AllowlistFile, []byte("[[agents]]\nagent_id = \"agent-1\"\npubkey = \""+hex.EncodeToString(s.gatePub)+"\"\n"), 0o600)
		}, doctor.Fail, "another public key"},
		{"mandate missing", func(s *stack) { require.NoError(s.t, os.Remove(s.cfg.Gate.MandateFile)) }, doctor.Fail, "mandate_file"},
		{"mandate does not decode", func(s *stack) { mustWrite(s.t, s.cfg.Gate.MandateFile, []byte("not cbor"), 0o600) }, doctor.Fail, "does not decode"},
		{"mandate for another gate", func(s *stack) { s.cfg.Gate.GateID = "gate-2" }, doctor.Fail, "bound to gate"},
		{"mandate not covering the agent", func(s *stack) {
			s.env.Now = func() time.Time { return testNow }
			require.NoError(s.t, os.WriteFile(s.cfg.Agent.KeyFile+".bak", nil, 0o600))
			seed := make([]byte, 32)
			seed[0] = 9
			mustWrite(s.t, s.cfg.Agent.KeyFile, seed, 0o600)
			mustWrite(s.t, s.cfg.Gate.AllowlistFile, []byte("[[agents]]\nagent_id = \"agent-1\"\npubkey = \"\"\n"), 0o600)
		}, doctor.Fail, "does not cover the agent"},
		{"mandate not yet in force", func(s *stack) { s.env.Now = func() time.Time { return testNow.Add(-24 * time.Hour) } }, doctor.Fail, "starts at"},
		{"mandate expired", func(s *stack) { s.env.Now = func() time.Time { return testNow.Add(60 * 24 * time.Hour) } }, doctor.Fail, "expired"},
		{"mandate expires soon", func(s *stack) { s.env.Now = func() time.Time { return testNow.Add(30*24*time.Hour - time.Hour) } }, doctor.Warn, "expires in"},
		{"fast mode without consent", func(s *stack) { s.cfg.Gate.FastMode = true }, doctor.Fail, "fast_mode_max_delay"},
		{"fast mode without a mandate", func(s *stack) { s.cfg.Gate.FastMode, s.cfg.Gate.MandateFile = true, "" }, doctor.Fail, "mandate that allows it"},
		{"sessions in a build without them", func(s *stack) { s.cfg.Gate.Sessions = true }, doctor.Fail, "no sessions"},
		{"sessions without a mandate limit", func(s *stack) {
			s.cfg.Gate.Sessions = true
			s.env.Sessions = fakeSessions{supported: true, slack: 3}
		}, doctor.Fail, "no session_max_delay"},
		{"session delay at slack", func(s *stack) {
			s.cfg.Gate.Sessions = true
			s.env.Sessions = fakeSessions{supported: true, slack: 3, delay: 3, has: true}
		}, doctor.Fail, "below MinPublishSlackBlocks + 1 = 4"},
		{"session delay at slack plus one", func(s *stack) {
			s.cfg.Gate.Sessions = true
			s.env.Sessions = fakeSessions{supported: true, slack: 3, delay: 4, has: true}
		}, doctor.OK, "known-answer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "gate")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestSigner(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"payer key missing", func(s *stack) { require.NoError(s.t, os.Remove(s.cfg.Signer.PayerKeyFile)) }, doctor.Fail, "payer_key_file"},
		{"payer key open to others", func(s *stack) { require.NoError(s.t, os.Chmod(s.cfg.Signer.PayerKeyFile, 0o644)) }, doctor.Fail, "payer_key_file"},
		{"payer address differs", func(s *stack) { s.cfg.Signer.PayerAddress = "0x0000000000000000000000000000000000000001" }, doctor.Fail, "is not the address of the payer key"},
		{"pinned chain differs from the preset", func(s *stack) { s.cfg.Signer.PinnedChainID = 8453 }, doctor.Fail, "pinned_chain_id 8453 is not the preset's 84532"},
		{"pinned usdc differs from the preset", func(s *stack) {
			s.cfg.Signer.PinnedUSDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
		}, doctor.Fail, "pinned_usdc"},
		{"gate key not pinned", func(s *stack) { s.cfg.Signer.PinnedGateKeys = []string{hex.EncodeToString(s.execPub)} }, doctor.Fail, "does not contain this gate's public key"},
		{"extra pin", func(s *stack) {
			s.cfg.Signer.PinnedGateKeys = append(s.cfg.Signer.PinnedGateKeys, hex.EncodeToString(s.execPub))
			s.env.Signer = fakeSigner{info: doctor.SignerInfo{PinnedGateKeys: s.cfg.Signer.PinnedGateKeys, ChainID: 84532, USDC: s.cfg.Network.EVM.USDC.Address, PayerAddress: s.payer}}
		}, doctor.Warn, "more than the local gate"},
		{"not running", func(s *stack) { s.env.Signer = fakeSigner{err: doctor.ErrNotAvailable} }, doctor.Warn, "not running"},
		{"unreachable", func(s *stack) { s.env.Signer = fakeSigner{err: errBoom} }, doctor.Fail, "not reachable"},
		{"running signer pins another gate", func(s *stack) {
			s.env.Signer = fakeSigner{info: doctor.SignerInfo{PinnedGateKeys: []string{hex.EncodeToString(s.execPub)}, ChainID: 84532, USDC: s.cfg.Network.EVM.USDC.Address, PayerAddress: s.payer}}
		}, doctor.Fail, "pins other gate keys"},
		{"running signer on another chain", func(s *stack) {
			s.env.Signer = fakeSigner{info: doctor.SignerInfo{PinnedGateKeys: s.cfg.Signer.PinnedGateKeys, ChainID: 1, USDC: s.cfg.Network.EVM.USDC.Address, PayerAddress: s.payer}}
		}, doctor.Fail, "another chain or token"},
		{"running signer pays from another address", func(s *stack) {
			s.env.Signer = fakeSigner{info: doctor.SignerInfo{PinnedGateKeys: s.cfg.Signer.PinnedGateKeys, ChainID: 84532, USDC: s.cfg.Network.EVM.USDC.Address, PayerAddress: "0x0000000000000000000000000000000000000002"}}
		}, doctor.Fail, "is not the address of the payer key"},
		{"no signer configured", func(s *stack) { s.cfg.Signer = nil }, doctor.OK, "no signer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "signer")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestPayerAddressIsTheEthereumAddress(t *testing.T) {
	// The key 1 has a well-known address.
	p := filepath.Join(t.TempDir(), "k")
	scalar := make([]byte, 32)
	scalar[31] = 1
	mustWrite(t, p, scalar, 0o600)
	a, err := doctor.PayerAddress(p)
	require.NoError(t, err)
	assert.Equal(t, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", a)

	mustWrite(t, p, []byte(hex.EncodeToString(scalar)+"\n"), 0o600)
	a2, err := doctor.PayerAddress(p)
	require.NoError(t, err)
	assert.Equal(t, a, a2, "hex text works as well")

	mustWrite(t, p, make([]byte, 32), 0o600)
	_, err = doctor.PayerAddress(p)
	require.Error(t, err, "the zero scalar is no key")
}

func TestSettlement(t *testing.T) {
	rpcs := func(s *stack) (string, string) { return s.cfg.Network.EVM.RPC[0], s.cfg.Network.EVM.RPC[1] }
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"wrong chain", func(s *stack) { a, _ := rpcs(s); s.evm.ids[a] = 8453 }, doctor.Fail, "answers chain 8453, config expects 84532"},
		{"one provider down", func(s *stack) { a, _ := rpcs(s); s.evm.errs[a] = errBoom }, doctor.Warn, "only one settlement provider"},
		{"both down", func(s *stack) {
			a, b := rpcs(s)
			s.evm.errs[a], s.evm.errs[b] = errBoom, errBoom
		}, doctor.Fail, "no settlement RPC answered"},
		{"two urls one provider", func(s *stack) {
			s.cfg.Network.EVM.RPC = []string{"https://rpc.example.org/a", "https://rpc.example.org/b"}
			s.evm.ids = map[string]uint64{"https://rpc.example.org/a": 84532, "https://rpc.example.org/b": 84532}
		}, doctor.Warn, "single-source"},
		{"no settlement", func(s *stack) { s.cfg.Network.Settlement = config.SettlementNone }, doctor.OK, "no settlement"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "settlement")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestFacilitator(t *testing.T) {
	const url = "https://x402.org/facilitator/supported"
	tests := []struct {
		name   string
		mutate func(s *stack)
		status doctor.Status
		cause  string
	}{
		{"other network only", func(s *stack) {
			s.net.http[url] = doctor.Response{Status: 200, Body: []byte(`{"kinds":[{"scheme":"exact","network":"base"}]}`)}
		}, doctor.Fail, "does not list scheme exact on base-sepolia"},
		{"other scheme only", func(s *stack) {
			s.net.http[url] = doctor.Response{Status: 200, Body: []byte(`{"kinds":[{"scheme":"upto","network":"base-sepolia"}]}`)}
		}, doctor.Fail, "does not list scheme exact"},
		{"not json", func(s *stack) { s.net.http[url] = doctor.Response{Status: 200, Body: []byte("<html>")} }, doctor.Fail, "not the expected JSON"},
		{"http 503", func(s *stack) { s.net.http[url] = doctor.Response{Status: 503} }, doctor.Fail, "HTTP 503"},
		{"unreachable", func(s *stack) { s.net.httpErr[url] = errBoom }, doctor.Fail, "/supported"},
		{"none configured", func(s *stack) { s.cfg.Network.EVM.FacilitatorURL = "" }, doctor.OK, "no facilitator"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			tc.mutate(s)
			it := status(t, s.run(), "facilitator")
			assert.Equal(t, tc.status, it.Status, "%s | %s", it.Cause, it.Fix)
			assert.Contains(t, it.Cause, tc.cause)
		})
	}
}

func TestBalances(t *testing.T) {
	t.Run("zero warns", func(t *testing.T) {
		s := newStack(t)
		s.evm.balances[s.payer] = big.NewInt(0)
		it := status(t, s.run(), "balances")
		assert.Equal(t, doctor.Warn, it.Status)
		assert.Contains(t, it.Cause, "holds 0 USDC")
		assert.Contains(t, it.Fix, "no ETH is needed")
		assert.Contains(t, it.Fix, "faucet")
	})
	t.Run("unreadable", func(t *testing.T) {
		s := newStack(t)
		s.evm.balErr = errBoom
		assert.Equal(t, doctor.Warn, status(t, s.run(), "balances").Status)
	})
	t.Run("no payer", func(t *testing.T) {
		s := newStack(t)
		s.cfg.Signer = nil
		assert.Equal(t, doctor.OK, status(t, s.run(), "balances").Status)
	})
	t.Run("funded", func(t *testing.T) {
		it := status(t, newStack(t).run(), "balances")
		assert.Equal(t, doctor.OK, it.Status)
		assert.Contains(t, it.Cause, "25000000")
	})
}

type panicCheck struct{}

func (panicCheck) Name() string                                     { return "boom" }
func (panicCheck) Run(context.Context, config.Config) doctor.Result { panic("kaboom") }

type blankCheck struct{}

func (blankCheck) Name() string                                     { return "blank" }
func (blankCheck) Run(context.Context, config.Config) doctor.Result { return doctor.Result{} }

func TestRunnerContainsAFaultyCheck(t *testing.T) {
	rep := doctor.Run(context.Background(), config.Config{}, []doctor.Check{panicCheck{}, blankCheck{}, doctor.ConfigCheck{Presets: "x"}})
	require.Len(t, rep.Items, 3)
	assert.Equal(t, doctor.Fail, rep.Items[0].Status)
	assert.Contains(t, rep.Items[0].Cause, "kaboom")
	assert.Equal(t, doctor.Fail, rep.Items[1].Status)
	assert.Equal(t, doctor.OK, rep.Items[2].Status)
	assert.True(t, rep.Failed())
}

func TestReportOutput(t *testing.T) {
	s := newStack(t)
	s.chain.consensusID = "celestia"
	s.chain.balances["celestia1publisher"] = 0
	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{Presets: "mocha v1"}))
	require.True(t, rep.Failed())

	var txt bytes.Buffer
	require.NoError(t, rep.WriteText(&txt))
	assert.Contains(t, txt.String(), "fail  chain")
	assert.Contains(t, txt.String(), "      ")
	assert.Contains(t, txt.String(), "fix: ")
	assert.Contains(t, txt.String(), "ok    config")
	assert.Contains(t, txt.String(), " fail\n")

	var js bytes.Buffer
	require.NoError(t, rep.WriteJSON(&js))
	var doc struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Cause  string `json:"cause"`
			Fix    string `json:"fix"`
		} `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(js.Bytes(), &doc))
	assert.False(t, doc.OK)
	require.Len(t, doc.Checks, 14)
	assert.Equal(t, "config", doc.Checks[0].Name)
	assert.Equal(t, "ok", doc.Checks[0].Status)
	var sawFail bool
	for _, c := range doc.Checks {
		if c.Status == "fail" {
			sawFail = true
			assert.NotEmpty(t, c.Cause)
			assert.NotEmpty(t, c.Fix)
		}
	}
	assert.True(t, sawFail)

	var empty bytes.Buffer
	require.NoError(t, doctor.Report{}.WriteJSON(&empty))
	assert.Contains(t, empty.String(), `"checks": []`)
	assert.Contains(t, empty.String(), `"ok": true`)
}

func TestWarningsDoNotFailTheRun(t *testing.T) {
	s := newStack(t)
	s.evm.balances[s.payer] = big.NewInt(0)
	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{Presets: "x"}))
	assert.False(t, rep.Failed())
	assert.Equal(t, 1, rep.Count(doctor.Warn))
}

func TestNoSecretInAnyOutput(t *testing.T) {
	s := newStack(t)
	s.kr.err["recorder"] = node.ErrBadPassphrase
	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{Presets: "x"}))
	var js bytes.Buffer
	require.NoError(t, rep.WriteJSON(&js))
	pass, err := os.ReadFile(s.cfg.Recorder.PassphraseFile)
	require.NoError(t, err)
	assert.NotContains(t, js.String(), string(bytes.TrimSpace(pass)))
	seed, err := os.ReadFile(s.cfg.Gate.KeyFile)
	require.NoError(t, err)
	assert.NotContains(t, js.String(), hex.EncodeToString(seed))
}

// echo is the error net/http returns: it carries the whole URL.
func echo(u string) error { return &url.Error{Op: "Get", URL: u, Err: errBoom} }

func TestNoURLKeyInAnyOutput(t *testing.T) {
	s := newStack(t)
	const (
		rpcA     = "https://rpc-a.example/v2/SECRET?key=SECRET"
		rpcB     = "https://user:SECRET@rpc-b.example/SECRET"
		fac      = "https://fac.example/SECRET?key=SECRET"
		archive  = "https://archive.example/SECRET?key=SECRET"
		mirror   = "https://u:SECRET@mirror.example/SECRET"
		comet    = "https://comet.example/v2/SECRET"
		capture  = "https://capture.example/SECRET?key=SECRET"
		headers  = "https://headers.example/SECRET"
		bridge   = "bridge.example/SECRET"
		checkRPC = "https://checkpoint.example?apikey=SECRET"
	)
	c := &s.cfg
	c.Network.EVM.RPC = []string{rpcA, rpcB}
	c.Network.EVM.FacilitatorURL = fac
	c.Network.CometRPC = []string{comet}
	c.Network.Bridge.Addr = bridge
	c.Archive.URL = archive
	c.Archive.MirrorURLs = []string{mirror}
	c.Capture = &config.Capture{Dir: filepath.Join(s.dir, "capture"), CometRPC: capture}
	c.Verify = &config.Verify{HeadersRPC: headers, CheckpointRPC: []string{checkRPC}, Quorum: 1}

	s.evm.errs[rpcA] = &url.Error{Op: "Post", URL: rpcA, Err: errBoom}
	s.evm.ids[rpcB] = 84532
	s.evm.balErr = &url.Error{Op: "Post", URL: rpcB, Err: errBoom}
	s.net.httpErr[fac+"/supported"] = echo(fac + "/supported")
	s.net.httpErr[archive] = echo(archive)
	s.net.httpErr[mirror] = echo(mirror)
	s.net.httpErr[comet+"/status"] = echo(comet + "/status")
	s.net.httpErr[capture+"/status"] = echo(capture + "/status")
	s.net.http[headers+"/status"] = doctor.Response{Status: 200, Body: []byte(cometStatus("other-chain", 1, true))}
	s.net.httpErr[checkRPC+"/status"] = echo(checkRPC + "/status")
	s.chain.headErr = fmt.Errorf("dial %s: refused", bridge)

	rep := doctor.Run(context.Background(), s.cfg, doctor.Checks(s.env, doctor.ConfigCheck{Err: errors.New("bad value " + rpcA)}))
	require.True(t, rep.Failed())
	var text, js bytes.Buffer
	require.NoError(t, rep.WriteText(&text))
	require.NoError(t, rep.WriteJSON(&js))
	for name, out := range map[string]string{"text": text.String(), "json": js.String()} {
		assert.NotContains(t, out, "SECRET", name)
		assert.NotContains(t, out, "user", name)
		for _, h := range []string{"rpc-a.example", "rpc-b.example", "fac.example", "archive.example", "comet.example", "bridge.example"} {
			assert.Contains(t, out, h, "%s names the endpoint by its host", name)
		}
	}
}

func TestPayerAddressReadsARawKeyWhole(t *testing.T) {
	// About 1 in 128 random keys ends in a newline or carriage return byte; a
	// trimming reader would refuse them as 31 bytes.
	for _, last := range []byte{0x0a, 0x0d} {
		p := filepath.Join(t.TempDir(), "k")
		scalar := make([]byte, 32)
		scalar[0] = 1
		scalar[31] = last
		mustWrite(t, p, scalar, 0o600)
		a, err := doctor.PayerAddress(p)
		require.NoError(t, err)
		want, err := doctor.PayerAddressOf(scalar)
		require.NoError(t, err)
		assert.Equal(t, want, a)
	}
	p := filepath.Join(t.TempDir(), "k")
	mustWrite(t, p, make([]byte, 32), 0o644)
	_, err := doctor.PayerAddress(p)
	require.Error(t, err, "a key readable by others is refused")
}
