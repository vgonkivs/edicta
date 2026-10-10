package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func TestMandateHashFlag(t *testing.T) {
	c, err := parse(t)
	require.NoError(t, err)
	assert.Empty(t, c.MandateHash, "unset by default")

	c, err = parse(t, "--mandate-hash", testMandateHash)
	require.NoError(t, err, "optional in strict mode")
	assert.Equal(t, testMandateHash, c.MandateHash)

	c, err = parse(t, "--fast", "--archive-url", "https://archive.example.invalid", "--mandate-hash", testMandateHash)
	require.NoError(t, err)
	assert.Equal(t, testMandateHash, c.MandateHash)

	for name, v := range map[string]string{
		"short":     testMandateHash[:62],
		"long":      testMandateHash + "00",
		"odd":       testMandateHash[:63],
		"not hex":   "zz" + testMandateHash[2:],
		"uppercase": strings.ToUpper(testMandateHash),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, "--mandate-hash", v)
			require.ErrorIs(t, err, ErrConfig)
			_, err = parse(t, "--fast", "--archive-url", "https://archive.example.invalid", "--mandate-hash", v)
			require.ErrorIs(t, err, ErrConfig)
		})
	}
}

// A gate with a mandate refuses a fast commitment without mandate_ref, so a
// fast run without the hash is refused before any network step.
func TestFastWithoutMandateHashIsAUsageError(t *testing.T) {
	_, err := parse(t, "--fast", "--archive-url", "https://archive.example.invalid")
	require.ErrorIs(t, err, ErrConfig)
	assert.Contains(t, err.Error(), "--mandate-hash")
}

func TestCommitmentCarriesMandateRef(t *testing.T) {
	want, err := hex.DecodeString(testMandateHash)
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		hash string
		ref  []byte
	}{
		"set":   {testMandateHash, want},
		"unset": {"", nil},
	} {
		t.Run(name, func(t *testing.T) {
			l := loadLiveFibre(t)
			v, trust, _, err := buildFibreVerifier(Config{DA: "fibre"}, fibreChainID, l.chain(t))
			require.NoError(t, err)
			vec := sdkfix.Load(t)

			scfg, err := sdkConfig(Config{AgentID: "dca-agent-1", MandateHash: tc.hash},
				edictaapi.HealthInfo{GateID: "gate-paper-1"}, vec.Recipients(t, "gate-paper-1", "auditor-1"), trust)
			require.NoError(t, err)
			scfg.SkewS = sdk.DefaultConfig().SkewS
			scfg.ExpectNamespace, scfg.ExpectSigners = nil, nil
			scfg.MaxReissues = 0

			signer, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
			require.NoError(t, err)
			b, err := sdk.New(scfg, sdk.Deps{
				Publisher: &fibrePublisher{ref: l.ref}, Signer: signer, Clock: fixedClock{liveHeaderTime.Add(30 * time.Second)},
				Chain: gatetest.NewChainParams(14400), Inclusion: v,
				Committers: map[commitment.DA]sdk.Committer{commitment.DAFibre: acceptCommit{}},
			})
			require.NoError(t, err)
			res, err := b.Commit(context.Background(), sdkfix.ClonePayload(vec.Case0(t).Payload))
			require.NoError(t, err)
			assert.Equal(t, tc.ref, res.Commitment.MandateRef)
		})
	}
}
