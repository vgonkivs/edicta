package edictad_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// secpSigner is the real anchor signer on a secp256k1 key given as its scalar.
func secpSigner(t *testing.T, sk [32]byte) node.AnchorSigner {
	t.Helper()
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	require.NoError(t, kr.ImportPrivKeyHex("recorder", hex.EncodeToString(sk[:]), "secp256k1"))
	s, err := node.NewAnchorSigner(kr, "recorder", "testchain-7")
	require.NoError(t, err)
	return s
}

// signSecp writes the mandate signed by a secp256k1 principal under scheme
// and makes later decisions name it.
func (p *policyEnv) signSecp(scheme principalsig.Scheme, sk [32]byte) {
	p.t.Helper()
	hrp := ""
	if scheme == principalsig.CosmosADR036 {
		hrp = "celestia"
	}
	s, err := principalsig.NewSecp256k1Signer(scheme, sk[:], hrp)
	require.NoError(p.t, err)
	m := *p.mandate
	m.SigType, m.PrincipalHRP, m.Principal = uint64(scheme), hrp, s.Principal()
	b, mh, err := policy.SignMandateWith(s, &m)
	require.NoError(p.t, err)
	base := *p.base
	base.MandateRef = bytes.Clone(mh[:])
	p.base = &base
	p.file = p.path("mandate.cbor")
	writeFile(p.t, p.file, b, 0o600)
}

// Keys never overlap across roles, compared as (sig_type, bytes): a principal
// may be a secp256k1 key, so the Recorder's account key being secp256k1 is no
// guarantee. A principal that is the Recorder's own key is refused at start.
func TestRecorderFastKeyEqualToThePrincipalIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("recorder and principal"))
	other := sha256.Sum256([]byte("another principal"))
	for name, tc := range map[string]struct {
		principal [32]byte
		refused   bool
	}{
		"ADR-036 principal is the Recorder key": {recKey, true},
		"ADR-036 principal is another key":      {other, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			p.mandate.FastModeMaxDelay = fastDelay
			p.signSecp(principalsig.CosmosADR036, tc.principal)
			p.deps.Archive = p.real
			p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: secpSigner(t, recKey)}

			signer := p.deps.RecorderFast.Signer
			addr, err := signer.Address(bg)
			require.NoError(t, err)
			s, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, tc.principal[:], "celestia")
			require.NoError(t, err)
			same := bytes.Equal(addr, (&secp256k1.PubKey{Key: s.Principal()}).Address().Bytes())
			require.Equal(t, tc.refused, same, "the principal is the Recorder's account key")

			srv, err := edictad.Start(bg, p.cfg(p.edits(gateFastFor(), recFast())...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, edictad.ErrConfig, "the Recorder key is the mandate's principal")
			assert.Zero(t, p.listens)
		})
	}
}

// The same key named as an EIP-712 principal is a 20-byte Ethereum address,
// not the Cosmos account: it is still the Recorder's key and is refused.
func TestRecorderFastKeyEqualToAnEIP712PrincipalIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("recorder and principal"))
	other := sha256.Sum256([]byte("another principal"))
	for name, tc := range map[string]struct {
		principal [32]byte
		refused   bool
	}{
		"EIP-712 principal is the Recorder key": {recKey, true},
		"EIP-712 principal is another key":      {other, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicyEnv(t)
			p.mandate.FastModeMaxDelay = fastDelay
			p.signSecp(principalsig.EIP712, tc.principal)
			p.deps.Archive = p.real
			p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: secpSigner(t, recKey)}

			srv, err := edictad.Start(bg, p.cfg(p.edits(gateFastFor(), recFast())...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, edictad.ErrConfig, "the Recorder key is the mandate's principal")
			assert.Contains(t, err.Error(), "eip712 principal")
			assert.Zero(t, p.listens)
		})
	}
}

// A signer that cannot show its public key cannot be cleared against an
// EIP-712 principal, so the start is refused.
func TestRecorderFastSignerWithoutPublicKeyAndEIP712PrincipalIsRefused(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.signSecp(principalsig.EIP712, sha256.Sum256([]byte("another principal")))
	p.deps.Archive = p.real
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: fixedSigner{bytes.Repeat([]byte{1}, 20)}}

	_, err := edictad.Start(bg, p.cfg(p.edits(gateFastFor(), recFast())...), p.deps)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "does not show its public key")
	assert.Zero(t, p.listens)
}

// A successor version adopted at a restart is checked like the first one: a
// new version whose principal is the Recorder's key is refused before any
// listener, and nothing more is archived.
func TestRecorderFastSuccessorMandateWithTheRecorderKeyIsRefused(t *testing.T) {
	recKey := sha256.Sum256([]byte("recorder and principal"))
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.signSecp(principalsig.CosmosADR036, sha256.Sum256([]byte("another principal")))
	p.deps.Archive = p.real
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: secpSigner(t, recKey)}
	edits := func() [][2]string { return p.edits(gateFastFor(), recFast()) }
	require.NoError(t, p.start(edits()...).Shutdown(bg))
	listens := p.listens

	for _, scheme := range []principalsig.Scheme{principalsig.CosmosADR036, principalsig.EIP712} {
		t.Run(scheme.String(), func(t *testing.T) {
			p.mandate.Version = 2
			p.signSecp(scheme, recKey)
			srv, err := edictad.Start(bg, p.cfg(edits()...), p.deps)
			if srv != nil {
				t.Cleanup(func() { _ = srv.Shutdown(bg) })
			}
			require.ErrorIs(t, err, edictad.ErrConfig, "the successor's principal is the Recorder key")
			assert.Equal(t, listens, p.listens, "no listener")
		})
	}
}

// The fast keys are refused without recorder.fast for da = fibre as well.
func TestRecorderFastFibreKeysWithoutFast(t *testing.T) {
	for name, line := range map[string]string{
		"upload address": `fast_upload_addr = "grpc.invalid:9090"`,
		"headroom":       fmt.Sprintf("fast_escrow_headroom_utia = %d", maxUploadCost(t)),
		"dedicated":      "fast_dedicated_account = true",
	} {
		t.Run(name, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			_, err := p.parseFibreFast(gateFastFor(), recFast(line))
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), "need recorder.fast")
		})
	}
}

// The fast gate off, or the Recorder's namespace outside its pending
// namespaces, refuses a fibre fast Recorder too.
func TestRecorderFastFibreNeedsTheFastGateForItsNamespace(t *testing.T) {
	keys := recFast(fibreFastKeys(maxUploadCost(t))...)
	other := hex.EncodeToString(append(bytes.Clone(nsBytes[:28]), 8))
	for name, tc := range map[string]struct {
		edits   [][2]string
		message string
	}{
		"gate not fast": {[][2]string{keys}, "recorder.fast needs gate.fast.enabled"},
		"namespace not pending": {[][2]string{keys, rep(`pending_namespaces = ["`+hex.EncodeToString(nsBytes)+`"]`,
			`pending_namespaces = ["`+other+`"]`)}, "recorder.namespace in gate.fast.pending_namespaces"},
	} {
		t.Run(name, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			edits := tc.edits
			if name != "gate not fast" {
				edits = append([][2]string{gateFastFor()}, edits...)
			}
			_, err := p.parseFibreFast(edits...)
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

// The upload address must be the consensus address; a different port or host
// with the same scheme is not.
func TestRecorderFastUploadAddressMustBeTheConsensusAddress(t *testing.T) {
	for _, addr := range []string{"grpc.invalid:9091", "grpc.invalid", "grpc.invalid.evil:9090", "https://grpc.invalid:9090/x"} {
		t.Run(addr, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			var keys []string
			for _, k := range fibreFastKeys(maxUploadCost(t)) {
				if strings.HasPrefix(k, "fast_upload_addr") {
					k = fmt.Sprintf("fast_upload_addr = %q", addr)
				}
				keys = append(keys, k)
			}
			_, err := p.parseFibreFast(gateFastFor(), recFast(keys...))
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), "must be network.consensus_grpc.addr")
		})
	}
}

// The headroom adds to the configured margin; it is never folded into it or
// lost when the margin is zero.
func TestRecorderFastEscrowHeadroomAddsToTheMargin(t *testing.T) {
	need := maxUploadCost(t)
	for _, margin := range []uint64{0, 5, 1_000_000} {
		t.Run(fmt.Sprint(margin), func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			keys := append(fibreFastKeys(need+7), fmt.Sprintf("escrow_margin_utia = %d", margin))
			c, err := p.parseFibreFast(gateFastFor(), rep("escrow_margin_utia = 5\n", ""), recFast(keys...))
			require.NoError(t, err)
			assert.Equal(t, margin+need+7, c.FibreRecorderConfig(nsBytes, nil).EscrowMarginUtia)
		})
	}
}

// readOnlyIntents serves anchor intents to the gate but cannot list them.
type readOnlyIntents struct {
	archive.Store
	r archive.IntentReader
}

func (s readOnlyIntents) Intent(ctx context.Context, da commitment.DA, c []byte, h uint64) (*archive.AnchorIntentRecord, error) {
	return s.r.Intent(ctx, da, c, h)
}

// A restart finds the intents it has to follow by listing them, so an archive
// that cannot list them refuses the start before any listener.
func TestRecorderFastStartNeedsAnIntentLister(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	signer, _ := keyringSigner(t, "testchain-7")
	p.deps.Archive = readOnlyIntents{Store: p.real, r: p.real}
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: signer}

	_, err := edictad.Start(bg, p.cfg(p.edits(gateFastFor(), recFast())...), p.deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lists anchor intents")
	assert.Zero(t, p.listens)
	p.registryReopens()
}

// blockingLister lists intents only once ctx ends, and says it was asked.
type blockingLister struct {
	*fsarchive.Store
	once   sync.Once
	called chan struct{}
}

func (b *blockingLister) Intents(ctx context.Context, _ commitment.DA, _ uint64) ([]*archive.AnchorIntentRecord, error) {
	b.once.Do(func() { close(b.called) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// The recovery of an earlier process's intents starts with the daemon, with no
// Publish to trigger it, and a recovery stuck on the archive does not hold up
// the shutdown past its budget.
func TestRecorderFastRecoveryRunsAtBootAndStopsAtShutdown(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	signer, _ := keyringSigner(t, "testchain-7")
	bl := &blockingLister{Store: p.real, called: make(chan struct{})}
	p.deps.Archive = bl
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: signer}
	cfg := p.cfg(p.edits(gateFastFor(), recFast())...)

	srv, err := edictad.Start(bg, cfg, p.deps)
	require.NoError(t, err)
	select {
	case <-bl.called:
	case <-time.After(20 * time.Second):
		require.Fail(t, "the recovery did not list the archived intents after start")
	}

	budget := cfg.ShutdownBudget()
	ctx, cancel := context.WithTimeout(bg, budget)
	defer cancel()
	begin := time.Now()
	require.NoError(t, srv.Shutdown(ctx))
	assert.Less(t, time.Since(begin), budget)
	p.registryReopens()
}

// countingCons counts what is broadcast through the operator's node.
type countingCons struct {
	*nodefake.Consensus
	mu   sync.Mutex
	sent [][]byte
}

func (c *countingCons) Broadcast(ctx context.Context, tx []byte) ([32]byte, error) {
	c.mu.Lock()
	c.sent = append(c.sent, bytes.Clone(tx))
	c.mu.Unlock()
	return c.Consensus.Broadcast(ctx, tx)
}

func (c *countingCons) distinct() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[[32]byte]bool{}
	for _, tx := range c.sent {
		seen[sha256.Sum256(tx)] = true
	}
	return len(seen)
}

// An intent archived by a daemon that stopped before its anchor landed is
// followed by the next daemon on the same archive without any Publish: the
// evidence is written at the anchor height and the tx is never signed again.
func TestRecorderFastRestartFollowsAnEarlierIntentWithoutPublish(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	signer, addr := keyringSigner(t, "testchain-7")
	bech, err := bech32.ConvertAndEncode("celestia", addr)
	require.NoError(t, err)
	p.cons.Accounts[bech] = node.AccountInfo{Number: 7, Sequence: 3}
	cc := &countingCons{Consensus: p.cons}
	p.deps.Consensus = cc

	head, err := p.chain.Head(bg)
	require.NoError(t, err)
	h0 := head.Height + 1
	hd0 := blockAt(h0, 8)
	hd0.Time = t0.Add(-60 * time.Second)
	p.chain.AddHeader(hd0)
	p.cons.SetHeight(h0)

	p.deps.Archive = p.real
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: signer}
	edits := p.edits(gateFastFor(), recFast())
	first := p.start(edits...)

	blob := gatefix.Blob(t)
	pub, err := p.client("").Publish(bg, blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())
	intent, err := p.real.Intent(bg, commitment.DACelestiaBlob, pub.Ref.Commitment, h0)
	require.NoError(t, err)
	require.NoError(t, first.Shutdown(bg))

	p.start(edits...)
	h := h0 + 1
	hdH := blockAt(h, 8)
	hdH.Time = t0
	p.chain.AddHeader(hdH)
	p.chain.AddBlob(h, node.Blob{Namespace: bytes.Clone(nsBytes), Data: bytes.Clone(blob), ShareVersion: 1,
		Signer: bytes.Clone(addr), Commitment: bytes.Clone(pub.Ref.Commitment)}, rootProof{root: hdH.DataRoot})
	p.cons.SetTx(sha256.Sum256(intent.Tx), node.TxStatus{Found: true, Height: h})
	p.cons.SetHeight(h)

	var ev *archive.EvidenceRecord
	require.Eventually(t, func() bool {
		ev, err = p.real.Evidence(bg, commitment.DACelestiaBlob, pub.Ref.Commitment)
		return err == nil
	}, 20*time.Second, 50*time.Millisecond, "the restarted daemon follows the archived intent")
	assert.Equal(t, h, ev.Height)
	assert.Equal(t, 1, cc.distinct(), "only the archived anchor tx is ever sent")
}
