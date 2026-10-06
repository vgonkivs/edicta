package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibreworld"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// liveBlobPublisher stands in for edictad: it hands the Recorder the one blob
// whose PayForFibre has a certificate that verifies, whatever the SDK built.
type liveBlobPublisher struct {
	rec   *recorder.FibreRecorder
	blob  []byte
	calls int
}

func (p *liveBlobPublisher) Publish(ctx context.Context, _ []byte) (sdk.Published, error) {
	p.calls++
	return p.rec.Publish(ctx, p.blob)
}

func fibreBuilderAt(t *testing.T, pub sdk.Publisher, v sdk.InclusionVerifier, trust sdk.SubmitterTrust, now time.Time) (*sdk.Builder, *sdkfix.Vectors) {
	t.Helper()
	vec := sdkfix.Load(t)
	signer, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
	require.NoError(t, err)
	cfg := sdk.DefaultConfig()
	cfg.AgentID = "dca-agent-1"
	cfg.Scope = commitment.Scope{GateID: "gate-paper-1"}
	cfg.Recipients = vec.Recipients(t, "gate-paper-1", "auditor-1")
	cfg.SubmitterTrust = trust
	cfg.MaxReissues = 0
	b, err := sdk.New(cfg, sdk.Deps{
		Publisher: pub, Signer: signer, Clock: fixedClock{now},
		Chain: gatetest.NewChainParams(14400), Inclusion: v,
		Committers: map[commitment.DA]sdk.Committer{commitment.DAFibre: acceptCommit{}},
	})
	require.NoError(t, err)
	return b, vec
}

// The SDK builder publishes through the real da = 1 Recorder over fakes, and
// the same-operator Fibre check reads the same chain.
func TestFibreFlowThroughTheRecorder(t *testing.T) {
	w := fibreworld.New(t)
	v, trust, level, err := buildFibreVerifier(Config{DA: "fibre"}, fibreChainID, w.Node)
	require.NoError(t, err)
	pub := &liveBlobPublisher{rec: w.Rec, blob: w.Live.Payload}
	b, vec := fibreBuilderAt(t, pub, v, trust, w.Live.Header.Time.Add(30*time.Second))

	res, err := b.Commit(context.Background(), sdkfix.ClonePayload(vec.Case0(t).Payload))
	require.NoError(t, err)
	assert.Equal(t, 1, pub.calls)
	assert.Equal(t, 1, w.Sub.Calls())
	assert.Equal(t, commitment.DAFibre, res.Published.Ref.DA)
	assert.Equal(t, w.Live.Height, res.Published.Ref.Height)
	assert.EqualValues(t, w.Live.Header.Time.Unix(), res.Published.BlockTime)
	assert.EqualValues(t, w.Live.Created.Unix(), res.Published.RetentionStart)

	_, err = w.St.Evidence(context.Background(), commitment.DAFibre, w.Live.Ref.Commitment)
	require.NoError(t, err, "the Recorder archived the evidence before the SDK signed")

	a := &actor{level: level, dom: transfer.Domain{ChainID: fibreChainID, HRP: hrp}}
	ev := a.baseEvidence(res)
	assert.Equal(t, w.Live.Height, ev.BlobHeight)
	txt := ev.Text()
	assert.Contains(t, txt, "PFF at height H")
	assert.NotContains(t, txt, "blob height H")
}

func TestFibreFlowSignsNothingWhenTheRecorderCannotPublish(t *testing.T) {
	cases := map[string]func(w *fibreworld.World){
		"escrow short": func(w *fibreworld.World) { w.Sub.SetEscrow(node.Escrow{AvailableUtia: 1}) },
		"submit fails": func(w *fibreworld.World) {
			w.Sub.Plan = func(int, []byte, []byte) nodefake.SubmitPlan {
				return nodefake.SubmitPlan{Err: node.ErrUnavailable}
			}
		},
	}
	for name, bend := range cases {
		t.Run(name, func(t *testing.T) {
			w := fibreworld.New(t)
			bend(w)
			v, trust, _, err := buildFibreVerifier(Config{DA: "fibre"}, fibreChainID, w.Node)
			require.NoError(t, err)
			b, vec := fibreBuilderAt(t, &liveBlobPublisher{rec: w.Rec, blob: w.Live.Payload}, v, trust, w.Live.Header.Time.Add(30*time.Second))
			res, err := b.Commit(context.Background(), sdkfix.ClonePayload(vec.Case0(t).Payload))
			require.Error(t, err)
			assert.Nil(t, res, "no commitment is signed without a published and verified payload")
		})
	}
}

func fibreStartupRig(t *testing.T, app uint64, fibreParams bool) (*nodefake.Chain, *nodefake.Consensus) {
	t.Helper()
	ch := nodefake.NewChain(make([]byte, 20))
	for _, h := range []uint64{90, 100} {
		ch.AddHeader(node.Header{ChainID: fibreChainID, Height: h, Time: time.Now(), AppVersion: app, DataRoot: []byte{1}})
	}
	co := nodefake.NewConsensus(fibreChainID)
	if fibreParams {
		co.Fibre = &node.FibreParams{RetentionS: 4 * 3600, PromiseHeightWindow: 1000}
	}
	return ch, co
}

// da=fibre starts from the Fibre check, da=blob from the blob check.
func TestStartupCheckPicksTheCheckerOfTheDA(t *testing.T) {
	ctx := context.Background()
	t.Run("fibre passes on a Fibre chain", func(t *testing.T) {
		ch, co := fibreStartupRig(t, 10, true)
		head, err := startupCheck(ctx, Config{DA: "fibre"}, ch, co)
		require.NoError(t, err)
		assert.Equal(t, fibreChainID, head.ChainID)
		assert.EqualValues(t, 100, head.Height)
	})
	t.Run("fibre needs the x/fibre module, which the blob check never reads", func(t *testing.T) {
		ch, co := fibreStartupRig(t, 10, false)
		_, err := startupCheck(ctx, Config{DA: "fibre"}, ch, co)
		require.ErrorIs(t, err, node.ErrUnsupported)
		_, err = startupCheck(ctx, Config{DA: "blob"}, ch, co)
		require.NoError(t, err)
	})
	t.Run("fibre pins the app version, blob takes the wider range", func(t *testing.T) {
		ch, co := fibreStartupRig(t, 8, true)
		_, err := startupCheck(ctx, Config{DA: "fibre"}, ch, co)
		require.ErrorIs(t, err, node.ErrUnsupported)
		_, err = startupCheck(ctx, Config{DA: "blob"}, ch, co)
		require.NoError(t, err)
	})
	t.Run("the chain id pin still applies", func(t *testing.T) {
		ch, co := fibreStartupRig(t, 10, true)
		_, err := startupCheck(ctx, Config{DA: "fibre", ChainID: "mocha-4"}, ch, co)
		require.ErrorIs(t, err, node.ErrUnsupported)
	})
	t.Run("an empty da is the blob check", func(t *testing.T) {
		ch, co := fibreStartupRig(t, 8, false)
		_, err := startupCheck(ctx, Config{}, ch, co)
		require.NoError(t, err)
	})
}

func TestFibreRefusesBlobOnlyFlagsSetExplicitly(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	tests := []struct {
		flag string
		val  string
	}{
		{"--inclusion", "self"},
		{"--rpc-primary", "https://rpc.example.invalid:26657"},
		{"--rpc-witness", "https://witness.example.invalid:26657"},
		{"--trust-height", "5"},
		{"--trust-hash", hash},
		{"--crosscheck-bridge", "other.example.invalid:26658"},
	}
	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			_, err := parse(t, "--da", "fibre", tc.flag, tc.val)
			require.ErrorIs(t, err, ErrConfig)
			assert.ErrorContains(t, err, tc.flag)
			assert.ErrorContains(t, err, "da=fibre", "the refusal says why: nobody should believe they got a light-client check")

			_, err = parse(t, "--da", "blob", tc.flag, tc.val)
			if tc.flag == "--inclusion" {
				require.NoError(t, err, "the same flag is fine for da=blob")
			}
		})
	}
}

func TestFibreAcceptsTheDefaultsAndDoesNotValidateBlobOnlyFields(t *testing.T) {
	c, err := parse(t, "--da", "fibre")
	require.NoError(t, err, "no blob-only flag was given, so none is checked")
	assert.Equal(t, "fibre", c.DA)

	c.Inclusion = ""
	require.NoError(t, c.Validate(), "the inclusion mode is not read for da=fibre")
	c.Inclusion = "light"
	require.NoError(t, c.Validate(), "a light check with nothing configured is not validated for da=fibre")

	c.DA = "blob"
	require.Error(t, c.Validate(), "for da=blob the same fields are still validated")
}
