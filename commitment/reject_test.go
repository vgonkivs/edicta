package commitment_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func loadReject(t testing.TB) rejectFile {
	var rf rejectFile
	loadJSON(t, "reject.json", &rf)
	return rf
}

// TestRejectVectors drives every must-reject vector through the stage that
// owns it and through the full pipeline. Earlier stages must pass.
func TestRejectVectors(t *testing.T) {
	rf := loadReject(t)
	require.NotEmpty(t, rf.Cases, "no reject vectors loaded")
	for _, rc := range rf.Cases {
		t.Run(rc.ID, func(t *testing.T) {
			env := mustHex(t, rc.EnvelopeHex)
			now := u64(t, rc.Now)
			params := toParams(t, rf.Params)
			if rc.Params != nil {
				params = toParams(t, *rc.Params)
			}
			gate := toGate(t, rf.Gate)
			if rc.Gate != nil {
				gate = toGate(t, *rc.Gate)
			}

			_, _, pipeErr := commitment.VerifyForGate(env, now, gate, params)

			if rc.Stage == "D" {
				_, err := commitment.DecodeSigned(env)
				assertSentinel(t, err, rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
				return
			}

			s, err := commitment.DecodeSigned(env)
			require.NoErrorf(t, err, "stage D must pass for a stage %s vector", rc.Stage)
			staticErr := commitment.ValidateStatic(&s.Commitment, params)

			if rc.Stage == "S" {
				assertSentinel(t, staticErr, rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
				return
			}
			require.NoErrorf(t, staticErr, "stage S must pass for a stage %s vector", rc.Stage)
			_, verr := commitment.Verify(s)

			if rc.Stage == "G" {
				assertSentinel(t, verr, rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
				return
			}
			require.NoErrorf(t, verr, "stage G must pass for a stage %s vector", rc.Stage)

			switch rc.Stage {
			case "T":
				assertSentinel(t, commitment.CheckTime(&s.Commitment, now, params), rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
			case "C":
				assertSentinel(t, commitment.CheckScope(&s.Commitment, gate), rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
			case "A":
				require.NoError(t, pipeErr, "pipeline must pass for a stage A vector")
				err := commitment.CheckAction(&s.Commitment, actionBytes(t, rc.actionSpec))
				assertSentinel(t, err, rc.ExpectError)
			default:
				require.FailNow(t, fmt.Sprintf("unknown stage %q", rc.Stage))
			}
		})
	}
}

// Every sentinel except the two without vectors must be exercised by at
// least one vector, and every vector must name a known sentinel.
func TestRejectVectorsCoverSentinels(t *testing.T) {
	rf := loadReject(t)
	var pf payloadFile
	loadJSON(t, "payload.json", &pf)
	var af authorizationFile
	loadJSON(t, "authorization.json", &af)
	var rcf receiptFile
	loadJSON(t, "receipt.json", &rcf)

	seen := map[string]bool{}
	for _, c := range rf.Cases {
		seen[c.ExpectError] = true
	}
	for _, c := range pf.Reject {
		seen[c.ExpectError] = true
	}
	for _, c := range af.Reject {
		seen[c.ExpectError] = true
	}
	for _, c := range rcf.Reject {
		seen[c.ExpectError] = true
	}
	// The signed-before-anchor sentinel is covered by anchor.json, which
	// TestSignedBeforeAnchorVectors asserts.
	seen["ErrIssuedBeforeAnchor"] = true
	for name := range seen {
		_, ok := sentinels[name]
		assert.Truef(t, ok, "vector expects %q, which is not a known sentinel", name)
	}
	for name := range sentinels {
		if name == "ErrNonCanonical" || name == "ErrInvalidParams" {
			continue
		}
		assert.Truef(t, seen[name], "sentinel %s has no must-reject vector", name)
	}
}

// The stage order decode, static, signature, time, scope is normative. Each case runs a vector with a defect in
// its own stage at a clock that would also fail a later stage.
func TestVerifyForGateStageOrder(t *testing.T) {
	rf := loadReject(t)
	byID := map[string]rejectCase{}
	for _, c := range rf.Cases {
		byID[c.ID] = c
	}
	params := toParams(t, rf.Params)
	gate := toGate(t, rf.Gate)

	tests := []struct {
		name string
		id   string
		now  uint64
		want string
	}{
		{"public key before time", "pubkey_identity", 1791009999, "ErrInvalidPublicKey"},
		{"public key before signature", "pubkey_noncanonical_y", 1791000060, "ErrInvalidPublicKey"},
		{"signature before time", "sig_wrong_key", 1791009999, "ErrSignatureInvalid"},
		{"time before scope", "foreign_gate_id", 1791009999, "ErrExpired"},
		{"scope when time is fine", "foreign_gate_id", 1791000060, "ErrScopeMismatch"},
		{"time before action type", "action_type_not_allowed", 1791009999, "ErrExpired"},
		{"action type when time is fine", "action_type_not_allowed", 1791000060, "ErrActionTypeNotAllowed"},
		{"gate id before action type", "action_type_not_allowed", 1791000060, "ErrScopeMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := byID[tt.id]
			g := gate
			if rc.Gate != nil {
				g = toGate(t, *rc.Gate)
			}
			if tt.want == "ErrScopeMismatch" && tt.id == "action_type_not_allowed" {
				g.GateID = "gate-paper-2"
			}
			_, _, err := commitment.VerifyForGate(mustHex(t, rc.EnvelopeHex), tt.now, g, params)
			assertSentinel(t, err, tt.want)
		})
	}
}
