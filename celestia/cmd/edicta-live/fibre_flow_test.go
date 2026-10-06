package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/share/shwap"

	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

const (
	liveCertVector   = "../../../spec/vectors/da/fibre_cert.json"
	liveAnchorVector = "../../../spec/vectors/da/fibre_anchor.json"
	fibreChainID     = "mocha-5"
)

var liveHeaderTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

type liveFibre struct {
	ref      commitment.PayloadRef
	pffH     uint64
	promiseH uint64
	hist     []byte
	promHdr  []byte
	dataHash []byte
	rows     [][]byte
	cols     [][]byte
	nsData   []byte
}

func loadLiveFibre(t *testing.T) liveFibre {
	t.Helper()
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	u := func(s string) uint64 {
		n, err := strconv.ParseUint(s, 10, 64)
		require.NoError(t, err)
		return n
	}
	raw, err := os.ReadFile(liveCertVector)
	require.NoError(t, err)
	var cv struct {
		Live struct {
			Raw struct {
				PFFHeight  string `json:"pff_height"`
				Historical struct {
					Hex string `json:"hex"`
				} `json:"historical_info"`
				Headers []struct {
					Height string `json:"height"`
					Hex    string `json:"header_hex"`
				} `json:"headers"`
			} `json:"raw"`
			Derived struct {
				Binding struct {
					NamespaceHex  string `json:"namespace_hex"`
					CommitmentHex string `json:"commitment_hex"`
				} `json:"binding"`
				Promise struct {
					Height string `json:"height"`
				} `json:"promise"`
			} `json:"derived"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &cv))
	l := liveFibre{
		pffH: u(cv.Live.Raw.PFFHeight), promiseH: u(cv.Live.Derived.Promise.Height), hist: unhex(cv.Live.Raw.Historical.Hex),
	}
	l.ref = commitment.PayloadRef{DA: commitment.DAFibre, Namespace: unhex(cv.Live.Derived.Binding.NamespaceHex),
		Commitment: unhex(cv.Live.Derived.Binding.CommitmentHex), Height: l.pffH}
	for _, h := range cv.Live.Raw.Headers {
		if u(h.Height) == l.promiseH {
			l.promHdr = unhex(h.Hex)
		}
	}
	require.NotEmpty(t, l.promHdr)

	raw, err = os.ReadFile(liveAnchorVector)
	require.NoError(t, err)
	var av struct {
		Live struct {
			Cases []struct {
				ID  string `json:"id"`
				Raw struct {
					DataHash   string   `json:"data_hash"`
					RowRoots   []string `json:"row_roots"`
					ColRoots   []string `json:"column_roots"`
					NamespaceD string   `json:"namespace_data_hex"`
				} `json:"raw"`
			} `json:"cases"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &av))
	for _, c := range av.Live.Cases {
		if c.ID != "h1402819" {
			continue
		}
		l.dataHash, l.nsData = unhex(c.Raw.DataHash), unhex(c.Raw.NamespaceD)
		for _, r := range c.Raw.RowRoots {
			l.rows = append(l.rows, unhex(r))
		}
		for _, r := range c.Raw.ColRoots {
			l.cols = append(l.cols, unhex(r))
		}
	}
	require.NotEmpty(t, l.dataHash)
	return l
}

func (l liveFibre) chain(t *testing.T) *nodefake.FibreChain {
	t.Helper()
	c := nodefake.NewFibreChain()
	c.AddHeader(l.pffH, l.dataHash, liveHeaderTime)
	c.SetDAH(l.pffH, l.rows, l.cols)
	var nd = decodeNamespaceData(t, l.nsData)
	c.SetNamespaceData(l.pffH, nd)
	c.SetHistoricalInfo(l.promiseH, l.hist)
	c.SetSignedHeader(l.promiseH, l.promHdr)
	return c
}

// fibrePublisher is the Recorder side: it returns the live anchor.
type fibrePublisher struct {
	ref   commitment.PayloadRef
	calls int
}

func (p *fibrePublisher) Publish(_ context.Context, _ []byte) (sdk.Published, error) {
	p.calls++
	r := p.ref
	r.Namespace, r.Commitment = bytes.Clone(r.Namespace), bytes.Clone(r.Commitment)
	return sdk.Published{Ref: r, BlockTime: uint64(liveHeaderTime.Unix()), RetentionStart: uint64(liveHeaderTime.Unix()) - 20}, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// acceptCommit stands in for the Fibre commitment recompute: the live vector's
// commitment belongs to a payload this test does not build.
type acceptCommit struct{}

func (acceptCommit) Check(commitment.PayloadRef, []byte) error { return nil }

func fibreBuilder(t *testing.T, pub sdk.Publisher, v sdk.InclusionVerifier, trust sdk.SubmitterTrust) (*sdk.Builder, *sdkfix.Vectors) {
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
		Publisher: pub, Signer: signer, Clock: fixedClock{liveHeaderTime.Add(30 * time.Second)},
		Chain: gatetest.NewChainParams(14400), Inclusion: v,
		Committers: map[commitment.DA]sdk.Committer{commitment.DAFibre: acceptCommit{}},
	})
	require.NoError(t, err)
	return b, vec
}

func TestFibreFlowCommitsAfterTheIndependentInclusionCheck(t *testing.T) {
	l := loadLiveFibre(t)
	v, trust, level, err := buildFibreVerifier(Config{DA: "fibre"}, fibreChainID, l.chain(t))
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.NotEmpty(t, level)

	pub := &fibrePublisher{ref: l.ref}
	b, vec := fibreBuilder(t, pub, v, trust)
	res, err := b.Commit(context.Background(), sdkfix.ClonePayload(vec.Case0(t).Payload))
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, res.Published.Ref.DA)
	assert.Equal(t, l.pffH, res.Published.Ref.Height)
	assert.EqualValues(t, liveHeaderTime.Unix(), res.Published.BlockTime)

	a := &actor{level: level, dom: transfer.Domain{ChainID: fibreChainID, HRP: hrp}}
	ev := a.baseEvidence(res)
	assert.Equal(t, l.pffH, ev.BlobHeight)
	assert.Equal(t, hex.EncodeToString(l.ref.Commitment), ev.ShareCommitment)
	assert.Equal(t, level, ev.InclusionLevel)
}

func TestFibreFlowSignsNothingWhenTheAnchorIsNotThere(t *testing.T) {
	l := loadLiveFibre(t)
	cases := map[string]struct {
		chain   func(t *testing.T) *nodefake.FibreChain
		chainID string
	}{
		"no block data": {chainID: fibreChainID, chain: func(*testing.T) *nodefake.FibreChain { return nodefake.NewFibreChain() }},
		"other chain":   {chainID: "mocha-4", chain: l.chain},
		"endpoint ignores the height": {chainID: fibreChainID, chain: func(t *testing.T) *nodefake.FibreChain {
			c := l.chain(t)
			c.AddHeader(l.pffH+1, l.dataHash, liveHeaderTime)
			c.IgnoreHeights(l.pffH + 1)
			return c
		}},
		"bridge down": {chainID: fibreChainID, chain: func(t *testing.T) *nodefake.FibreChain {
			c := l.chain(t)
			c.FailBridge = nodefake.ErrInjected
			return c
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, trust, _, err := buildFibreVerifier(Config{DA: "fibre"}, tc.chainID, tc.chain(t))
			require.NoError(t, err)
			pub := &fibrePublisher{ref: l.ref}
			b, vec := fibreBuilder(t, pub, v, trust)
			res, err := b.Commit(context.Background(), sdkfix.ClonePayload(vec.Case0(t).Payload))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
			assert.Nil(t, res, "no commitment is signed without the check")
		})
	}
}

func TestFibreVerifierNeedsAReaderAndAChain(t *testing.T) {
	_, _, _, err := buildFibreVerifier(Config{DA: "fibre"}, fibreChainID, nil)
	require.Error(t, err)
	_, _, _, err = buildFibreVerifier(Config{DA: "fibre"}, "", nodefake.NewFibreChain())
	require.Error(t, err)
}

func decodeNamespaceData(t *testing.T, stream []byte) shwap.NamespaceData {
	t.Helper()
	var nd shwap.NamespaceData
	_, err := nd.ReadFrom(bytes.NewReader(stream))
	require.NoError(t, err)
	return nd
}
