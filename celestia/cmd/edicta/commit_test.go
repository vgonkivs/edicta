// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/sdktest"
)

const testGateID = "gate-cli-1"

type cliGate struct {
	priv ed25519.PrivateKey
	err  error
	got  commonOpts
}

func (g *cliGate) AuthorizeWithVerdict(_ context.Context, envelope, _, _ []byte) ([]byte, []byte, error) {
	if g.err != nil {
		return nil, nil, g.err
	}
	sc, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return nil, nil, err
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return nil, nil, err
	}
	a := commitment.Authorization{
		Version: commitment.Version, CommitmentHash: h[:], ActionHash: sc.Commitment.Action.Hash,
		GateID: testGateID, Expires: sc.Commitment.ValidUntil, Path: commitment.PathDA, Mode: commitment.ModeStrict,
	}
	canon, err := commitment.EncodeAuthorization(&a)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(g.priv, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	return b, nil, err
}

// fakeService replaces the production wiring for one test.
func fakeService(t *testing.T, g *cliGate, pub *sdktest.Publisher) {
	t.Helper()
	fakeServiceAt(t, g, pub, 1_800_000_000, nil)
}

// fakeServiceAt is fakeService with its own clock and a signer.
func fakeServiceAt(t *testing.T, g *cliGate, pub *sdktest.Publisher, at int64, sg commitcmd.Signer) {
	t.Helper()
	old := newCommitService
	t.Cleanup(func() { newCommitService = old })
	_, agent, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := sdk.NewEd25519Signer(agent)
	require.NoError(t, err)
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub.SetBlockTime(uint64(at) - 20)
	clock := sdktest.NewClock(at)
	newCommitService = func(_ context.Context, o commonOpts) (*commitcmd.Service, func(), error) {
		g.got = o
		var state commitcmd.StateStore
		if o.stateDir != "" {
			st, err := commitcmd.NewFileStateStore(o.stateDir)
			require.NoError(t, err)
			state = st
		}
		return &commitcmd.Service{
			State: state,
			Gate:  g, GateKeys: [][]byte{g.priv.Public().(ed25519.PublicKey)}, GateID: testGateID, Clock: clock.Now,
			Signer: sg, PollInterval: time.Second, Sleep: func(context.Context, time.Duration) error { return nil },
			Builders: func(mode string, validFor time.Duration) (*sdk.Builder, error) {
				cfg := sdk.DefaultConfig()
				cfg.AgentID = "agent-1"
				cfg.Scope = commitment.Scope{GateID: testGateID}
				cfg.Recipients = []blob.Recipient{{KID: []byte("a"), PublicKey: rk.PublicKey()}}
				cfg.SubmitterTrust = sdk.SubmitterSameOperator
				return sdk.New(cfg, sdk.Deps{Publisher: pub, Signer: signer, Clock: clock})
			},
		}, func() {}, nil
	}
}

func commit(t *testing.T, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runCommit(context.Background(), args, &out, strings.NewReader(stdin))
	return code, out.String()
}

const goodRequest = `{"action_type":"application/vnd.test.order+json","action":"eyJidXkiOiIxIn0=","context":{"p":1},"model":{"id":"m"},"policy":{"id":"p"}}`

func newCLIGate(t *testing.T) *cliGate {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &cliGate{priv: priv}
}

func TestCommitPrintsTheSignedAuthorization(t *testing.T) {
	g := newCLIGate(t)
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	fakeService(t, g, pub)
	code, out := commit(t, goodRequest, "--request", "-", "--recipient", "00", "--mode", "strict")
	require.Equal(t, commitcmd.ExitOK, code, out)

	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	for _, k := range []string{"commitment_hash", "authorization", "envelope", "action", "salt", "payload_ref", "mode", "expires"} {
		assert.Contains(t, resp, k)
	}
	assert.Equal(t, "strict", resp["mode"])
	assert.Equal(t, []string{"00"}, []string(g.got.recipients))
}

func TestCommitFlagsOverrideTheRequestAndTakeActionFromAFile(t *testing.T) {
	g := newCLIGate(t)
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	fakeService(t, g, pub)
	dir := t.TempDir()
	act, ctxf := filepath.Join(dir, "a.bin"), filepath.Join(dir, "c.json")
	require.NoError(t, os.WriteFile(act, []byte{0, 1, 2, 255}, 0o600))
	require.NoError(t, os.WriteFile(ctxf, []byte(`{"from":"file"}`), 0o600))
	code, out := commit(t, "", "--action-file", act, "--context", ctxf, "--action-type", "application/vnd.test.bin",
		"--model", "m", "--policy", "p")
	require.Equal(t, commitcmd.ExitOK, code, out)
	var resp commitcmd.Response
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, []byte{0, 1, 2, 255}, resp.Action, "the file's bytes are committed unchanged")
}

func TestCommitExitCodes(t *testing.T) {
	t.Run("gate refusal is 3 and prints the code", func(t *testing.T) {
		g := newCLIGate(t)
		g.err = &edictaapi.Error{Status: 409, Code: "ErrNonceUsed", Message: "used"}
		fakeService(t, g, sdktest.NewPublisher(commitment.DACelestiaBlob))
		code, out := commit(t, goodRequest, "--request", "-")
		assert.Equal(t, commitcmd.ExitRefused, code)
		assert.Contains(t, out, `"code":"ErrNonceUsed"`)
	})
	t.Run("a source outage is 6 and retryable", func(t *testing.T) {
		g := newCLIGate(t)
		pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
		fakeService(t, g, pub)
		pub.Fail(errors.New("refused"))
		code, out := commit(t, goodRequest, "--request", "-")
		assert.Equal(t, commitcmd.ExitUnavailable, code)
		assert.Contains(t, out, `"retryable":true`)
	})
	t.Run("a bad request is 64", func(t *testing.T) {
		fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
		code, _ := commit(t, `{"unknown":1}`, "--request", "-")
		assert.Equal(t, commitcmd.ExitUsage, code)
	})
	t.Run("an unknown flag is 64", func(t *testing.T) {
		code, out := commit(t, "", "--nope")
		assert.Equal(t, commitcmd.ExitUsage, code)
		assert.Contains(t, out, "usage: edicta commit")
	})
	t.Run("a missing request file is 64", func(t *testing.T) {
		code, _ := commit(t, "", "--request", filepath.Join(t.TempDir(), "none.json"))
		assert.Equal(t, commitcmd.ExitUsage, code)
	})
}

func TestCommitWithoutAConfigIsAUsageError(t *testing.T) {
	code, out := commit(t, goodRequest, "--request", "-", "--config", filepath.Join(t.TempDir(), "edicta.toml"), "--recipient", "00")
	assert.Equal(t, commitcmd.ExitUsage, code)
	assert.Contains(t, out, `"code":"usage"`)
}

func TestParseRecipients(t *testing.T) {
	_, err := parseRecipients([]string{"zz"})
	require.Error(t, err)
	_, err = parseRecipients([]string{"00"})
	require.Error(t, err, "not a 32-byte key")
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	r, err := parseRecipients([]string{hex.EncodeToString(k.PublicKey().Bytes())})
	require.NoError(t, err)
	require.Len(t, r, 1)
	assert.Len(t, r[0].KID, 16)
}

func TestAgentServeRefusesANonLoopbackBind(t *testing.T) {
	fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
	var out bytes.Buffer
	code := runAgent(context.Background(), []string{"serve", "--listen", "0.0.0.0:0"}, &out)
	assert.Equal(t, commitcmd.ExitUsage, code)
	assert.Contains(t, out.String(), "loopback")
}

func TestAgentNeedsTheServeSubcommand(t *testing.T) {
	var out bytes.Buffer
	assert.Equal(t, commitcmd.ExitUsage, runAgent(context.Background(), nil, &out))
	assert.Equal(t, commitcmd.ExitUsage, runAgent(context.Background(), []string{"run"}, &out))
}

func TestAgentServeRunsUntilCancelled(t *testing.T) {
	fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan int, 1)
	go func() { done <- runAgent(ctx, []string{"serve", "--listen", "127.0.0.1:0"}, &out) }()
	require.Eventually(t, func() bool { return strings.Contains(out.String(), "listening on 127.0.0.1:") }, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case code := <-done:
		assert.Equal(t, commitcmd.ExitOK, code)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestTopLevelRoutesCommitAndAgent(t *testing.T) {
	code, out := edicta(t, "agent")
	assert.Equal(t, commitcmd.ExitUsage, code)
	assert.Contains(t, out, "serve")
	code, out = edicta(t, "commit", "--nope")
	assert.Equal(t, commitcmd.ExitUsage, code)
	assert.Contains(t, out, "commit")
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestSubmitterTrustIsRequiredAndUntrustedIsRefused(t *testing.T) {
	_, err := submitterTrust("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
	_, err = submitterTrust("untrusted")
	require.Error(t, err)
	_, err = submitterTrust("bogus")
	require.Error(t, err)
	v, err := submitterTrust("same_operator")
	require.NoError(t, err)
	assert.Equal(t, sdk.SubmitterSameOperator, v)
}

func TestGateKeySourcesInOrder(t *testing.T) {
	k1, k2 := strings.Repeat("11", 32), strings.Repeat("22", 32)
	var cfg config.Config
	cfg.Agent = &config.Agent{GateKeys: []string{k1}}
	cfg.Signer = &config.Signer{PinnedGateKeys: []string{k2}}

	got, err := gateKeysOf(commonOpts{gateKeys: stringList{k2}}, cfg)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(got[0]), k2, "the flag wins")
	got, err = gateKeysOf(commonOpts{}, cfg)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(got[0]), k1, "then agent.gate_keys")
	cfg.Agent.GateKeys = nil
	got, err = gateKeysOf(commonOpts{}, cfg)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(got[0]), k2, "then signer.pinned_gate_keys")
	cfg.Signer = nil
	_, err = gateKeysOf(commonOpts{}, cfg)
	require.Error(t, err, "no key, no run")
	_, err = gateKeysOf(commonOpts{gateKeys: stringList{"zz"}}, cfg)
	require.Error(t, err)
}

func TestMandateOfNeedsARecipientAndAGoodRef(t *testing.T) {
	_, _, err := mandateOf(commonOpts{}, "")
	require.Error(t, err)
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := hex.EncodeToString(k.PublicKey().Bytes())
	_, _, err = mandateOf(commonOpts{recipients: stringList{pub}, mandateRef: "abc"}, "")
	require.Error(t, err)
	ref, rec, err := mandateOf(commonOpts{recipients: stringList{pub}, mandateRef: strings.Repeat("ab", 32)}, "")
	require.NoError(t, err)
	assert.Equal(t, byte(0xab), ref[0])
	assert.Len(t, rec, 1)
	_, _, err = mandateOf(commonOpts{recipients: stringList{pub}}, filepath.Join(t.TempDir(), "none"))
	require.Error(t, err, "a missing mandate file is an error, not a silent skip")
}

func TestAgentServeRemoteNeedsTokenAndHost(t *testing.T) {
	fakeService(t, newCLIGate(t), sdktest.NewPublisher(commitment.DACelestiaBlob))
	var out bytes.Buffer
	code := runAgent(context.Background(), []string{"serve", "--listen", "0.0.0.0:0", "--allow-remote"}, &out)
	assert.Equal(t, commitcmd.ExitUsage, code)
	assert.Contains(t, out.String(), "bearer token")
}
