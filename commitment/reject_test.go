package commitment_test

import (
	"testing"

	"github.com/vgonkivs/prior/commitment"
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
	if len(rf.Cases) == 0 {
		t.Fatal("no reject vectors loaded")
	}
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
			if err != nil {
				t.Fatalf("stage D must pass for a stage %s vector: %v", rc.Stage, err)
			}
			staticErr := commitment.ValidateStatic(&s.Commitment, params)

			if rc.Stage == "S" {
				assertSentinel(t, staticErr, rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
				return
			}
			if staticErr != nil {
				t.Fatalf("stage S must pass for a stage %s vector: %v", rc.Stage, staticErr)
			}
			_, verr := commitment.Verify(s)

			if rc.Stage == "G" {
				assertSentinel(t, verr, rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
				return
			}
			if verr != nil {
				t.Fatalf("stage G must pass for a stage %s vector: %v", rc.Stage, verr)
			}

			switch rc.Stage {
			case "T":
				assertSentinel(t, commitment.CheckTime(&s.Commitment, now, params), rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
			case "C":
				assertSentinel(t, commitment.CheckScope(&s.Commitment, gate), rc.ExpectError)
				assertSentinel(t, pipeErr, rc.ExpectError)
			case "A":
				if pipeErr != nil {
					t.Fatalf("pipeline must pass for a stage A vector: %v", pipeErr)
				}
				if rc.Request == nil {
					t.Fatal("stage A vector without request")
				}
				err := commitment.CheckAction(&s.Commitment, toOrder(t, *rc.Request))
				assertSentinel(t, err, rc.ExpectError)
			default:
				t.Fatalf("unknown stage %q", rc.Stage)
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

	seen := map[string]bool{}
	for _, c := range rf.Cases {
		seen[c.ExpectError] = true
	}
	for _, c := range pf.Reject {
		seen[c.ExpectError] = true
	}
	for name := range seen {
		if _, ok := sentinels[name]; !ok {
			t.Errorf("vector expects %q, which is not a known sentinel", name)
		}
	}
	for name := range sentinels {
		if name == "ErrNonCanonical" || name == "ErrInvalidParams" {
			continue
		}
		if !seen[name] {
			t.Errorf("sentinel %s has no must-reject vector", name)
		}
	}
}

// Stage order D, S, G (G0, G2, G1), T, C is normative. Each case runs a vector with a defect in
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
		{"time before scope", "foreign_account", 1791009999, "ErrExpired"},
		{"scope when time is fine", "foreign_account", 1791000060, "ErrScopeMismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := byID[tt.id]
			_, _, err := commitment.VerifyForGate(mustHex(t, rc.EnvelopeHex), tt.now, gate, params)
			assertSentinel(t, err, tt.want)
		})
	}
}
