package gate_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type vParams struct {
	FibreRetentionS string `json:"fibre_retention_s"`
	BlobRetentionS  string `json:"blob_retention_s"`
	SkewS           string `json:"skew_s"`
}

type vScope struct {
	GateID      string   `json:"gate_id"`
	ActionTypes []string `json:"action_types"`
}

func (p vParams) params(t *testing.T) commitment.Params {
	return commitment.Params{
		FibreRetentionS: gatefix.U64(t, p.FibreRetentionS),
		BlobRetentionS:  gatefix.U64(t, p.BlobRetentionS),
		SkewS:           gatefix.U64(t, p.SkewS),
	}
}

func (s vScope) scope(t *testing.T) commitment.GateScope {
	return commitment.GateScope{GateID: s.GateID, ActionTypes: s.ActionTypes}
}

// TestRejectVectorsThroughAuthorize feeds every spec reject vector to Authorize.
// Every stage, including the action stage with the vector's own action
// bytes, must give the vector's sentinel. The other stages get the template action: their defect is
// earlier in the order.
func TestRejectVectorsThroughAuthorize(t *testing.T) {
	var rf struct {
		Params vParams `json:"params"`
		Gate   vScope  `json:"gate"`
		Cases  []struct {
			ID          string   `json:"id"`
			Stage       string   `json:"stage"`
			EnvelopeHex string   `json:"envelope_hex"`
			Now         string   `json:"now"`
			Params      *vParams `json:"params"`
			Gate        *vScope  `json:"gate"`
			ExpectError string   `json:"expect_error"`
			Signer      string   `json:"signer"`
			ActionHex   string   `json:"action_hex"`
			Pattern     string   `json:"action_pattern"`
			ActionSize  string   `json:"action_size"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "reject.json", &rf)
	require.GreaterOrEqualf(t, len(rf.Cases), 100, "only %d reject vectors loaded", len(rf.Cases))
	for _, rc := range rf.Cases {
		t.Run(rc.ID, func(t *testing.T) {
			p, g := rf.Params, rf.Gate
			if rc.Params != nil {
				p = *rc.Params
			}
			if rc.Gate != nil {
				g = *rc.Gate
			}
			e := gatefix.New(t,
				gatefix.WithScope(g.scope(t)),
				gatefix.WithParams(p.params(t)),
				gatefix.WithNow(gatefix.U64(t, rc.Now)),
				gatefix.WithAllowlist(map[string][]byte{"dca-agent-1": gatefix.Pub(t, "agent1")}))
			want, ok := gatefix.Sentinel(rc.ExpectError)
			require.Truef(t, ok, "unknown sentinel %s", rc.ExpectError)
			action := gatefix.Action(t)
			if rc.Stage == "A" {
				action = gatefix.ActionOf(t, rc.ActionHex, rc.Pattern, rc.ActionSize)
			}
			_, err := e.AuthorizeWith(gatefix.MustHex(t, rc.EnvelopeHex), action)
			require.ErrorIs(t, err, want)
		})
	}
}

// TestValidVectorsReachChainStage: every valid vector passes all stateless
// stages, including the action check on its own bytes, the registry epoch, the key roles and the allowlist, and stops at
// the anchor lookup because no anchor exists in the fake.
func TestValidVectorsReachChainStage(t *testing.T) {
	var vf struct {
		Params vParams `json:"params"`
		Gate   vScope  `json:"gate"`
		Cases  []struct {
			ID          string   `json:"id"`
			EnvelopeHex string   `json:"envelope_hex"`
			Now         string   `json:"now"`
			Params      *vParams `json:"params"`
			Input       struct {
				AgentID string `json:"agent_id"`
			} `json:"input"`
			ActionHex  string `json:"action_hex"`
			Pattern    string `json:"action_pattern"`
			ActionSize string `json:"action_size"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "valid.json", &vf)
	for _, vc := range vf.Cases {
		t.Run(vc.ID, func(t *testing.T) {
			p := vf.Params
			if vc.Params != nil {
				p = *vc.Params
			}
			e := gatefix.New(t,
				gatefix.WithScope(vf.Gate.scope(t)),
				gatefix.WithParams(p.params(t)),
				gatefix.WithNow(gatefix.U64(t, vc.Now)),
				gatefix.WithAllowlist(map[string][]byte{vc.Input.AgentID: gatefix.Pub(t, "agent1")}))
			_, err := e.AuthorizeWith(gatefix.MustHex(t, vc.EnvelopeHex), gatefix.ActionOf(t, vc.ActionHex, vc.Pattern, vc.ActionSize))
			require.ErrorIs(t, err, gate.ErrAnchorNotFound)
		})
	}
}

const bigTime = uint64(1) << 62

// TestAnchorK1Vectors: signed-before-anchor rule at the boundary.
func TestAnchorK1Vectors(t *testing.T) {
	var af struct {
		K1 []struct {
			ID          string `json:"id"`
			IssuedAt    string `json:"issued_at"`
			BlockTime   string `json:"block_time"`
			SkewS       string `json:"skew_s"`
			ExpectError string `json:"expect_error"`
		} `json:"k1"`
	}
	gatefix.ReadVector(t, "anchor.json", &af)
	ran := 0
	for _, v := range af.K1 {
		skew, issued, th := gatefix.U64(t, v.SkewS), gatefix.U64(t, v.IssuedAt), gatefix.U64(t, v.BlockTime)
		if th >= bigTime {
			continue // covered by the pure function tests
		}
		ran++
		t.Run(v.ID, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithNow(issued+1), gatefix.WithConfig(func(c *gate.Config) { c.SkewS = skew }))
			c := gatefix.Times(gatefix.Template(t), issued, issued+900)
			e.StageChain(c, th, th)
			e.DA.Put(c.PayloadRef, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			_, err := e.Authorize(b)
			if v.ExpectError == "" {
				require.NoError(t, err)
				return
			}
			e.RequireRejected(c, err, commitment.ErrIssuedBeforeAnchor)
		})
	}
	require.GreaterOrEqualf(t, ran, 3, "only %d K1 vectors ran", ran)
}

// TestAnchorK2Vectors: retention window routing and the fail-closed read of
// the retention at the anchor height.
func TestAnchorK2Vectors(t *testing.T) {
	var af struct {
		K2 []struct {
			ID                string  `json:"id"`
			DA                string  `json:"da"`
			ValidUntil        string  `json:"valid_until"`
			BlockTime         string  `json:"block_time"`
			BlobRetentionS    string  `json:"blob_retention_s"`
			FibreLatest       string  `json:"fibre_retention_latest_s"`
			FibreAtHeight     *string `json:"fibre_retention_at_height_s"`
			CreationTimestamp string  `json:"creation_timestamp"`
			Expect            struct {
				Within      *bool  `json:"within"`
				Route       string `json:"route"`
				ExpectError string `json:"expect_error"`
			} `json:"expect"`
		} `json:"k2"`
	}
	gatefix.ReadVector(t, "anchor.json", &af)
	ran := 0
	for _, v := range af.K2 {
		vu, th := gatefix.U64(t, v.ValidUntil), gatefix.U64(t, v.BlockTime)
		if th >= bigTime {
			continue
		}
		ran++
		t.Run(v.ID, func(t *testing.T) {
			da := commitment.DA(gatefix.U64(t, v.DA))
			p := commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
			var base *commitment.Commitment
			var blob []byte
			if da == commitment.DACelestiaBlob {
				p.BlobRetentionS = gatefix.U64(t, v.BlobRetentionS)
				base, blob = gatefix.Template(t), gatefix.Blob(t)
			} else {
				p.FibreRetentionS = gatefix.U64(t, v.FibreLatest)
				base, blob = gatefix.FibreTemplate(t), gatefix.FibreBlob()
			}
			var maxTTL uint64
			if da == commitment.DACelestiaBlob {
				maxTTL = min(3600, p.BlobRetentionS/4)
			} else {
				maxTTL = min(3600, p.FibreRetentionS/4)
			}
			issued := max(th, vu-maxTTL)
			c := gatefix.Times(base, issued, vu)
			e := gatefix.New(t, gatefix.WithParams(p), gatefix.WithNow(issued+1))
			if da == commitment.DAFibre {
				if v.FibreAtHeight != nil {
					e.Chain.SetAt(c.PayloadRef.Height, gatefix.U64(t, *v.FibreAtHeight))
				} else {
					e.Chain.FailHistorical(errors.New("state pruned"))
				}
			}
			e.StageChain(c, th, optU64(t, v.CreationTimestamp))
			b, _ := gatefix.Sign(t, "agent1", c)

			switch v.Expect.Route {
			case "da":
				e.DA.Put(c.PayloadRef, blob)
			case "archive":
				e.Archive.Put(c.PayloadRef, blob)
			default:
				e.DA.Put(c.PayloadRef, blob)
				e.Archive.Put(c.PayloadRef, blob)
			}
			res, err := e.Authorize(b)
			switch {
			case v.Expect.ExpectError != "":
				want, _ := gatefix.Sentinel(v.Expect.ExpectError)
				if want == nil {
					want = gate.ErrRetentionUnavailable
				}
				e.RequireRejected(c, err, want)
				require.EqualValues(t, 0, e.DA.Fetches()+e.Archive.Fetches())
			case v.Expect.Route == "da":
				require.NoErrorf(t, err, "route da: err %v path %v archive fetches %d", err, res.Path, e.Archive.Fetches())
				require.Equalf(t, registry.PathDA, res.Path, "route da: err %v path %v archive fetches %d", err, res.Path, e.Archive.Fetches())
				require.EqualValuesf(t, 0, e.Archive.Fetches(), "route da: err %v path %v archive fetches %d", err, res.Path, e.Archive.Fetches())
			case v.Expect.Route == "archive":
				require.NoErrorf(t, err, "route archive: err %v path %v da fetches %d", err, res.Path, e.DA.Fetches())
				require.Equalf(t, registry.PathArchive, res.Path, "route archive: err %v path %v da fetches %d", err, res.Path, e.DA.Fetches())
				require.EqualValuesf(t, 0, e.DA.Fetches(), "route archive: err %v path %v da fetches %d", err, res.Path, e.DA.Fetches())
			default:
				require.FailNow(t, fmt.Sprintf("vector has no route or error: %+v", v.Expect))
			}
		})
	}
	require.GreaterOrEqualf(t, ran, 14, "only %d K2 vectors ran", ran)
}

// TestAnchorK2UnreadableRetentionIsNeverSubstituted: reading the retention at
// the anchor height fails; the current value must not be used, and neither
// source may be touched.
func TestAnchorK2UnreadableRetentionIsNeverSubstituted(t *testing.T) {
	e := gatefix.New(t)
	e.Chain.FailHistorical(errors.New("state pruned"))
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	e.RequireRejected(c, err, gate.ErrRetentionUnavailable)
	require.EqualValues(t, 0, e.DA.Fetches()+e.Archive.Fetches(), "source touched")
	// The envelope can be retried once the node serves the parameter.
	e.Chain.FailHistorical(nil)
	_, err = e.Authorize(b)
	require.NoError(t, err, "retry")
}

// TestRegistryEpochVectors runs the epoch rule through Authorize for the vectors
// that fit the time ranges Authorize accepts.
func TestRegistryEpochVectors(t *testing.T) {
	var af struct {
		Epoch []struct {
			ID          string `json:"id"`
			IssuedAt    string `json:"issued_at"`
			Epoch       string `json:"epoch"`
			SkewS       string `json:"skew_s"`
			ExpectError string `json:"expect_error"`
		} `json:"epoch"`
	}
	gatefix.ReadVector(t, "anchor.json", &af)
	ran := 0
	for _, v := range af.Epoch {
		skew, issued, epoch := gatefix.U64(t, v.SkewS), gatefix.U64(t, v.IssuedAt), gatefix.U64(t, v.Epoch)
		if issued >= bigTime || epoch >= bigTime {
			continue
		}
		ran++
		t.Run(v.ID, func(t *testing.T) {
			e := gatefix.New(t,
				gatefix.WithRegistry(gatefix.MemReg(t, epoch)),
				gatefix.WithNow(issued),
				gatefix.WithConfig(func(c *gate.Config) { c.SkewS = skew }))
			c := gatefix.Times(gatefix.Template(t), issued, issued+900)
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			_, err := e.Authorize(b)
			if v.ExpectError == "" {
				require.NoError(t, err)
				return
			}
			e.RequireRejected(c, err, gate.ErrBeforeRegistryEpoch)
		})
	}
	require.GreaterOrEqualf(t, ran, 3, "only %d epoch vectors ran", ran)
}

// optU64 reads a decimal string that vectors omit when it does not apply.
func optU64(t *testing.T, s string) uint64 {
	if s == "" {
		return 0
	}
	return gatefix.U64(t, s)
}
