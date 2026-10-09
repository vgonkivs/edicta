package demo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk"
)

func TestPrincipalKeyIsPrivateDistinctAndTheMandateIsMode0600(t *testing.T) {
	e := newTestEnv(t)
	r := e.runner(t)
	_, err := r.Run(context.Background())
	require.Error(t, err, "the fake gate refuses to start")

	seeds := map[string][]byte{}
	for _, n := range []string{"agent.ed25519", "gate.ed25519", "executor.ed25519", principalFile} {
		b, err := os.ReadFile(filepath.Join(r.runDir, n))
		require.NoError(t, err)
		require.Len(t, b, ed25519.SeedSize)
		seeds[n] = b
		fi, err := os.Stat(filepath.Join(r.runDir, n))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), n)
	}
	pubs := map[string]bool{}
	for n, s := range seeds {
		k := hex.EncodeToString(ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey))
		assert.False(t, pubs[k], "%s repeats another key", n)
		pubs[k] = true
	}

	priv := ed25519.NewKeyFromSeed(seeds[principalFile])
	for _, secret := range [][]byte{seeds[principalFile], priv} {
		assert.NotContains(t, e.screen.String(), hex.EncodeToString(secret))
	}

	fi, err := os.Stat(r.edCfg.Policy.MandateFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	raw, err := os.ReadFile(r.edCfg.Policy.MandateFile)
	require.NoError(t, err)
	sm, _, err := policy.VerifyMandate(raw)
	require.NoError(t, err)
	assert.Equal(t, []byte(priv.Public().(ed25519.PublicKey)), sm.Mandate.Principal)
	assert.Equal(t, r.edCfg.Gate.GateID, sm.Mandate.GateID)
	require.Len(t, sm.Mandate.Assets, 1)
	assert.Equal(t, policy.AmountFromUint64(2*e.cfg.AmountUTIA), sm.Mandate.Assets[0].PerActionMax,
		"the rogue amount + 1 stays inside the per-action maximum")
}

type fakeAuthorizer struct {
	auth, verdict []byte
	err           error
}

func (f fakeAuthorizer) AuthorizeWithVerdict(context.Context, []byte, []byte, []byte) ([]byte, []byte, error) {
	return f.auth, f.verdict, f.err
}

func TestOverLimitIsDeniedAndBroadcastsNothing(t *testing.T) {
	e := newTestEnv(t)
	r := e.runner(t)
	gatePub, gatePriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	r.gatePub = gatePub
	rail := &countingRail{}
	r.rail = GuardRail(rail, r.consent)
	r.rail.Lock()
	d := &decision{amount: 2*r.cfg.AmountUTIA + 1, res: &sdk.Result{CommitmentHash: commitment.Hash{1}}}

	v := policy.Verdict{
		Format: 1, GateID: "g", MandateHash: make([]byte, 32), CommitmentHash: d.res.CommitmentHash[:],
		ActionHash: make([]byte, 32), AgentPubKey: make([]byte, 32), Outcome: policy.OutcomeDeny,
		Reason: "ErrAmountAboveMax", Extractor: "celestia/tia-transfer/v1", DecidedAt: 1,
		Facts: &policy.Facts{Kind: "transfer", Asset: "a", Amount: policy.AmountFromUint64(d.amount), Scale: 6, Recipient: "r"},
	}
	canon, err := policy.EncodeVerdict(&v)
	require.NoError(t, err)
	sig := ed25519.Sign(gatePriv, policy.VerdictSigningMessage(policy.HashVerdict(canon)))
	verdict, err := policy.EncodeSignedVerdict(&policy.SignedVerdict{Verdict: v, Signature: sig})
	require.NoError(t, err)

	deny := &edictaapi.Error{Code: "policy.ErrAmountAboveMax", Status: 403, PolicyVerdict: verdict}
	a := r.judgeOverLimit(context.Background(), fakeAuthorizer{err: deny}, d)
	assert.True(t, a.AsExpected, a.Got)
	assert.Zero(t, rail.broadcasts)

	// A gate that authorized anyway, or a deny without a signed verdict, is not
	// the expected outcome.
	a = r.judgeOverLimit(context.Background(), fakeAuthorizer{auth: []byte{1}, err: deny}, d)
	assert.False(t, a.AsExpected)
	a = r.judgeOverLimit(context.Background(), fakeAuthorizer{err: &edictaapi.Error{Code: "policy.ErrAmountAboveMax", Status: 403}}, d)
	assert.False(t, a.AsExpected)
}
