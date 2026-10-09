package gate_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

type stage4mCase struct {
	ID          string `json:"id"`
	GateMandate *struct {
		Mandate  string `json:"mandate"`
		Auditors bool   `json:"auditors"`
	} `json:"gate_mandate"`
	CommitmentRef string `json:"commitment_ref"`
	StoredEntry   bool   `json:"stored_entry_same_commitment"`
	Expect        struct {
		Rule          string   `json:"rule"`
		Result        string   `json:"result"`
		StoredAuth    bool     `json:"stored_authorization"`
		VerdictSigned bool     `json:"verdict_signed"`
		Writes        []string `json:"writes"`
	} `json:"expect"`
}

// stage4mMandate is the scenario's mandate: m_full is the one the agent
// names, other is a different mandate of the same principal.
func stage4mMandate(t *testing.T, name string, auditors bool) *policy.Mandate {
	m := baseMandate(t)
	switch name {
	case "m_full":
	case "other":
		m.MandateID = bytes.Repeat([]byte{0x0e}, 16)
	default:
		require.FailNow(t, "unknown mandate "+name)
	}
	if auditors {
		pub, err := curve25519.X25519(bytes.Repeat([]byte{0x11}, 32), curve25519.Basepoint)
		require.NoError(t, err)
		m.Auditors = []policy.Auditor{{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "Bob"}}
		m.StateSalt = bytes.Repeat([]byte{0x22}, 32)
	}
	return m
}

// TestStage4mVectors drives the gate through spec/vectors/v1/stage4m.json.
// A library gate writes only the decision record (the markers are the
// daemon's), so the writes are compared on the decision records.
func TestStage4mVectors(t *testing.T) {
	var f struct {
		Cases []stage4mCase `json:"cases"`
	}
	gatefix.ReadVector(t, "stage4m.json", &f)
	require.Len(t, f.Cases, 10)
	_, named, err := policy.VerifyMandate(signedMandate(t, stage4mMandate(t, "m_full", false)))
	require.NoError(t, err)

	for _, tc := range f.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			arch := &recordingArchiver{}
			withArch := gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = arch })
			x, err := policy.NewExtractors(lastByteExtractor{typ: gatefix.ActionType})
			require.NoError(t, err)
			e := gatefix.New(t, withArch, gatefix.WithDeps(func(d *gate.Deps) { d.Extractors = x }))

			c := gatefix.WithAction(t, gatefix.Fresh(gatefix.Template(t), 1), gatefix.ActionType, gatefix.OtherAction(t, 10))
			switch tc.CommitmentRef {
			case "v1_mandate_ref":
				c.MandateRef = named[:]
				// The agent names m_full in the form the gate runs it: with
				// auditors it is another mandate with another hash.
				if gm := tc.GateMandate; gm != nil && gm.Auditors && gm.Mandate == "m_full" {
					_, priv, err := policy.VerifyMandate(signedMandate(t, stage4mMandate(t, "m_full", true)))
					require.NoError(t, err)
					c.MandateRef = priv[:]
				}
			case "v1_minimal_included_blob":
				c.MandateRef = nil
			default:
				require.FailNow(t, "unknown commitment_ref "+tc.CommitmentRef)
			}
			e.StageDA(c, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			action := gatefix.OtherAction(t, 10)

			var first gate.Result
			if tc.StoredEntry {
				// Authorized while the named mandate was in force.
				e.Cfg.Mandate = signedMandate(t, stage4mMandate(t, "m_full", false))
				require.NoError(t, e.Restart())
				first, err = e.AuthorizeWith(b, action)
				require.NoError(t, err)
			}
			e.Cfg.Mandate = nil
			if gm := tc.GateMandate; gm != nil {
				e.Cfg.Mandate = signedMandate(t, stage4mMandate(t, gm.Mandate, gm.Auditors))
			}
			require.NoError(t, e.Restart(), "gate starts with the scenario's mandate")
			before := arch.n

			res, err := e.AuthorizeWith(b, action)
			decisions := 0
			for _, w := range tc.Expect.Writes {
				if strings.HasPrefix(w, "decision_form_") {
					decisions++
				}
			}
			switch tc.Expect.Result {
			case "continue":
				require.NotErrorIs(t, err, gate.ErrMandateMismatch)
				require.NotErrorIs(t, err, gate.ErrMandateRefMissing)
				return
			case "ErrNonceUsed":
				require.ErrorIs(t, err, gate.ErrNonceUsed)
				require.True(t, tc.Expect.StoredAuth)
				assert.Equal(t, first.Authorization, res.Authorization, "the stored Authorization")
			default:
				want, ok := map[string]error{
					"ErrMandateMismatch":   gate.ErrMandateMismatch,
					"ErrMandateRefMissing": gate.ErrMandateRefMissing,
				}[tc.Expect.Result]
				require.True(t, ok, tc.Expect.Result)
				require.ErrorIs(t, err, want)
				assert.Empty(t, res.Authorization)
				e.RequireUntouched(c)
			}
			if !tc.Expect.VerdictSigned && tc.Expect.Result != "ErrNonceUsed" {
				assert.Empty(t, res.PolicyVerdict, "stage 4m signs no verdict")
			}
			assert.Equal(t, decisions, arch.n-before, "decision records written")
		})
	}
}
