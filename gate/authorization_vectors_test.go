package gate_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// TestAuthorizationVectorsThroughTheGate runs every authorization vector whose
// payload can be served from the data in the vector files: the gate must
// produce exactly the vector's SignedAuthorization bytes. Vectors whose
// payload cannot be reproduced are checked as an executor would check them.
func TestAuthorizationVectorsThroughTheGate(t *testing.T) {
	var af struct {
		MaxTTL string `json:"max_authorization_ttl_s"`
		Gate   vScope `json:"gate"`
		Cases  []struct {
			ID            string `json:"id"`
			CommitmentRef string `json:"commitment_ref"`
			AuthorizedAt  string `json:"authorized_at"`
			Input         struct {
				Path    string `json:"path"`
				Expires string `json:"expires"`
				Mode    string `json:"mode"`
			} `json:"input"`
			SignedHex string `json:"signed_authorization_hex"`
			Check     struct {
				GatePubKeyHex string `json:"gate_pubkey_hex"`
				GateID        string `json:"gate_id"`
				ActionType    string `json:"action_type"`
				ActionHex     string `json:"action_hex"`
				Pattern       string `json:"action_pattern"`
				ActionSize    string `json:"action_size"`
				SaltHex       string `json:"action_salt_hex"`
				Now           string `json:"now"`
				SkewS         string `json:"skew_s"`
			} `json:"check"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "authorization.json", &af)
	require.NotEmpty(t, af.Cases)

	var vf struct {
		Params vParams `json:"params"`
		Cases  []struct {
			ID          string   `json:"id"`
			EnvelopeHex string   `json:"envelope_hex"`
			Params      *vParams `json:"params"`
			Input       struct {
				AgentID    string `json:"agent_id"`
				MandateRef string `json:"mandate_ref"`
			} `json:"input"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "valid.json", &vf)
	var pf struct {
		Cases []struct {
			ID      string `json:"id"`
			BlobHex string `json:"blob_hex"`
		} `json:"cases"`
	}
	gatefix.ReadVector(t, "payload.json", &pf)
	candidates := [][]byte{gatefix.FibreBlob()}
	for _, c := range pf.Cases {
		if c.BlobHex != "" {
			candidates = append(candidates, gatefix.MustHex(t, c.BlobHex))
		}
	}

	served := 0
	for _, ac := range af.Cases {
		t.Run(ac.ID, func(t *testing.T) {
			if ac.CommitmentRef == "" {
				t.Skip("encoding-only vector with stand-in hashes")
			}
			envHex, agent, mandated := "", "", false
			p := vf.Params
			for _, vc := range vf.Cases {
				if vc.ID == ac.CommitmentRef {
					envHex, agent, mandated = vc.EnvelopeHex, vc.Input.AgentID, vc.Input.MandateRef != ""
					if vc.Params != nil {
						p = *vc.Params
					}
				}
			}
			require.NotEmptyf(t, envHex, "no valid vector %q", ac.CommitmentRef)
			envelope := gatefix.MustHex(t, envHex)
			s, err := commitment.DecodeSigned(envelope)
			require.NoError(t, err)
			c := &s.Commitment
			action := gatefix.ActionOf(t, ac.Check.ActionHex, ac.Check.Pattern, ac.Check.ActionSize)
			want := gatefix.MustHex(t, ac.SignedHex)
			now := gatefix.U64(t, ac.AuthorizedAt)

			chk := commitment.AuthorizationCheck{
				GatePubKey: gatefix.MustHex(t, ac.Check.GatePubKeyHex),
				GateID:     ac.Check.GateID,
				ActionType: ac.Check.ActionType,
				Action:     action,
				ActionSalt: gatefix.MustHex(t, ac.Check.SaltHex),
				Now:        gatefix.U64(t, ac.Check.Now),
				SkewS:      gatefix.U64(t, ac.Check.SkewS),
			}
			_, _, err = commitment.VerifyAuthorization(want, chk)
			require.NoError(t, err, "the vector itself must verify")

			var blob []byte
			for _, b := range candidates {
				sum := sha256.Sum256(b)
				if string(sum[:]) == string(c.CiphertextHash) && uint64(len(b)) == c.PayloadSize {
					blob = b
				}
			}
			if blob == nil {
				t.Logf("payload of %s is not in the vector files: executor-side check only", ac.CommitmentRef)
				return
			}
			if mandated {
				t.Logf("%s names a mandate the vector does not carry: executor-side check only", ac.CommitmentRef)
				return
			}
			if ac.Input.Mode == "2" {
				t.Logf("%s is a fast-mode Authorization; this gate has no stage K-fast: executor-side check only", ac.ID)
				return
			}
			served++

			e := gatefix.New(t,
				gatefix.WithScope(af.Gate.scope(t)),
				gatefix.WithParams(p.params(t)),
				gatefix.WithNow(now),
				gatefix.WithAllowlist(map[string][]byte{agent: gatefix.Pub(t, "agent1")}),
				gatefix.WithConfig(func(cfg *gate.Config) { cfg.MaxAuthorizationTTL = gatefix.U64(t, af.MaxTTL) }),
				gatefix.WithDeps(func(d *gate.Deps) {
					ok := gatetest.NewDACommitter()
					ok.Bind(c.PayloadRef.Commitment, blob)
					d.Committers = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: ok}
				}))
			if ac.Input.Path == "2" {
				th := c.ValidUntil + 600 - 14400 - 1
				e.StageChain(c, th, th)
				e.Archive.Put(c.PayloadRef, blob)
			} else {
				e.StageDA(c, blob)
			}
			res, err := e.AuthorizeWithSalt(envelope, action, chk.ActionSalt)
			require.NoError(t, err)
			require.Equal(t, want, res.Authorization, "the gate's bytes differ from the vector")
			require.EqualValues(t, gatefix.U64(t, ac.Input.Path), res.Path)
		})
	}
	require.GreaterOrEqual(t, served, 4, "too few vectors ran through the gate")
}
