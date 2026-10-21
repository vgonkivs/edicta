// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/commitcmd"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/signer"
)

const (
	quoteExpiresAt = int64(1792466814)
	edenNow        = quoteExpiresAt - 200
)

// cliSigner signs with a local key and releases the proof after a number of
// refusals, as the signer does while the deposit is not yet executed.
type cliSigner struct {
	mu          sync.Mutex
	priv        *secp256k1.PrivateKey
	signErr     error
	notExecuted int
	proofCalls  int
	signCalls   int
}

func (s *cliSigner) Sign(_ context.Context, req signer.Request) (signer.Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signCalls++
	if s.signErr != nil {
		return signer.Output{}, s.signErr
	}
	tx, err := edenescrow.DecodeTxAction(req.Action)
	if err != nil {
		return signer.Output{}, err
	}
	signed, _, err := tx.SignTx(s.priv)
	if err != nil {
		return signer.Output{}, err
	}
	sc, err := commitment.DecodeSigned(req.Envelope)
	if err != nil {
		return signer.Output{}, err
	}
	h, err := commitment.HashOf(&sc.Commitment)
	if err != nil {
		return signer.Output{}, err
	}
	return signer.Output{CommitmentHash: h, Signed: signed, RailRef: edenescrow.RailRef(signed)}, nil
}

// Status answers like a signer without the status route, so the CLI falls
// back to the payment-signature poll.
func (s *cliSigner) Status(context.Context, commitment.Hash) (signer.Status, error) {
	return signer.Status{}, &commitcmd.SignerError{Status: 404, Code: "edictaapi.ErrRouteNotFound", Message: "no route"}
}

func (s *cliSigner) PaymentSignature(_ context.Context, req signer.PaymentProofRequest) (signer.PaymentProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofCalls++
	if s.proofCalls <= s.notExecuted {
		return signer.PaymentProof{}, &commitcmd.SignerError{Status: 409, Code: "signer.ErrNotExecuted", Message: "not yet", Retryable: true}
	}
	tx, err := edenescrow.DecodeTxAction(req.Action)
	if err != nil {
		return signer.PaymentProof{}, err
	}
	m, err := edenescrow.PaymentProofMessage(tx, req.Requirements)
	if err != nil {
		return signer.PaymentProof{}, err
	}
	sig, err := edenescrow.Sign(s.priv, edenescrow.PersonalDigest(m))
	if err != nil {
		return signer.PaymentProof{}, err
	}
	raw := append(append(append([]byte{}, sig.R[:]...), sig.S[:]...), 27+sig.YParity)
	return signer.PaymentProof{CommitmentHash: req.CommitmentHash, Message: m, Signature: []byte("0x" + hex.EncodeToString(raw))}, nil
}

type edenFiles struct {
	build, header string
}

func writeEdenFiles(t *testing.T) edenFiles {
	t.Helper()
	live := filepath.Join("..", "..", "..", "spec", "vectors", "profiles", "eden-escrow", "live")
	rr, err := os.ReadFile(filepath.Join(live, "houston-payment-required.json"))
	require.NoError(t, err)
	dir := t.TempDir()
	f := edenFiles{build: filepath.Join(live, "houston-deposit-build.json"), header: filepath.Join(dir, "header.txt")}
	require.NoError(t, os.WriteFile(f.header, []byte(base64.StdEncoding.EncodeToString(rr)+"\n"), 0o600))
	return f
}

func edenArgs(f edenFiles, extra ...string) []string {
	return append([]string{
		"--eden-build", f.build, "--payment-required", "@" + f.header,
		"--resource", "https://inference.bot.fun/v1/chat/completions",
		"--model", "m", "--policy", "p", "--recipient", "00",
	}, extra...)
}

// privateDir is a state directory only its owner can use, as the store requires.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}

func newCLISigner(t *testing.T) *cliSigner {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	return &cliSigner{priv: priv}
}

func TestEdenCommitFlagsDriveTheWholeFlow(t *testing.T) {
	g := newCLIGate(t)
	sg := newCLISigner(t)
	sg.notExecuted = 2
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	fakeServiceAt(t, g, pub, edenNow, sg)
	f := writeEdenFiles(t)

	code, out := commit(t, "", edenArgs(f, "--sign", "--broadcast", "--record", "--payment-signature", "--wait", "1m", "--state-dir", privateDir(t))...)
	require.Equal(t, commitcmd.ExitOK, code, out)
	var resp map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, true, resp["settled"])
	assert.Regexp(t, `^0x[0-9a-f]{130}$`, resp["payment_signature"])
	for _, k := range []string{"commitment_hash", "signed_tx", "rail_ref", "payer", "deposit", "authorization", "action"} {
		assert.Contains(t, resp, k)
	}
	assert.Equal(t, 3, sg.proofCalls)
}

func TestEdenCommitReadsTheBuildFromStdin(t *testing.T) {
	g := newCLIGate(t)
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	fakeServiceAt(t, g, pub, edenNow, nil)
	f := writeEdenFiles(t)
	build, err := os.ReadFile(f.build)
	require.NoError(t, err)
	args := edenArgs(f)
	args[1] = "-"
	code, out := commit(t, string(build), args...)
	require.Equal(t, commitcmd.ExitOK, code, out)
	assert.Contains(t, out, `"deposit"`)
}

func TestEdenCommitUsageErrors(t *testing.T) {
	f := writeEdenFiles(t)
	build, err := os.ReadFile(f.build)
	require.NoError(t, err)
	cases := map[string]struct {
		stdin string
		args  []string
	}{
		"sign without broadcast": {args: edenArgs(f, "--sign")},
		"broadcast without sign": {args: edenArgs(f, "--broadcast")},
		"sign without a signer":  {args: edenArgs(f, "--sign", "--broadcast")},
		"both read stdin":        {stdin: string(build), args: []string{"--request", "-", "--eden-build", "-", "--payment-required", "@" + f.header}},
		"build file missing":     {args: edenArgs(f, "--eden-build", "/nonexistent")},
		"header file missing":    {args: edenArgs(f, "--payment-required", "@/nonexistent")},
		"resume without a state": {args: []string{"--resume-hash", "aa"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := newCLIGate(t)
			fakeServiceAt(t, g, sdktest.NewPublisher(commitment.DACelestiaBlob), edenNow, nil)
			code, out := commit(t, tc.stdin, tc.args...)
			assert.Equal(t, commitcmd.ExitUsage, code, out)
		})
	}
}

func TestEdenCommitAnExpiredQuoteIsExit3(t *testing.T) {
	g := newCLIGate(t)
	fakeServiceAt(t, g, sdktest.NewPublisher(commitment.DACelestiaBlob), quoteExpiresAt+10, nil)
	code, out := commit(t, "", edenArgs(writeEdenFiles(t))...)
	require.Equal(t, commitcmd.ExitRefused, code, out)
	assert.Contains(t, out, "quote_expired")
}

func TestEdenCommitResumesByHashAfterASignerOutage(t *testing.T) {
	g := newCLIGate(t)
	sg := newCLISigner(t)
	sg.signErr = &commitcmd.SignerError{Status: 503, Code: "signer.ErrUnavailable", Message: "down", Retryable: true}
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	fakeServiceAt(t, g, pub, edenNow, sg)
	f := writeEdenFiles(t)
	state := privateDir(t)

	code, out := commit(t, "", edenArgs(f, "--sign", "--broadcast", "--state-dir", state)...)
	require.Equal(t, commitcmd.ExitUnavailable, code, out)
	var failed struct {
		Error struct {
			Code           string `json:"code"`
			CommitmentHash string `json:"commitment_hash"`
			Retryable      bool   `json:"retryable"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &failed))
	assert.True(t, failed.Error.Retryable)
	require.Len(t, failed.Error.CommitmentHash, 64)
	blobs := len(pub.Blobs())

	sg.signErr = nil
	code, out = commit(t, "", "--resume-hash", failed.Error.CommitmentHash, "--state-dir", state,
		"--payment-required", "@"+f.header, "--sign", "--broadcast", "--record")
	require.Equal(t, commitcmd.ExitOK, code, out)
	assert.Len(t, pub.Blobs(), blobs, "no second publication")
	assert.Contains(t, out, failed.Error.CommitmentHash)
	assert.Contains(t, out, `"settled":true`)
}
