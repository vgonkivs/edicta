package verifier_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every policy case of the reasons vectors points at a case of the policy
// verify vectors; the two files must say the same about it, because the
// reasons tests skip building those cases.
func TestPolicyReasonCasesMatchTheVerifyVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/policy/verify.json")
	require.NoError(t, err)
	var vd struct {
		Cases []struct {
			ID     string `json:"id"`
			Expect struct {
				Policy struct {
					Status string `json:"status"`
					Rule   string `json:"rule"`
					Reason string `json:"reason"`
				} `json:"policy"`
				Integrity struct {
					Status string  `json:"status"`
					Reason *string `json:"reason"`
				} `json:"gate_integrity"`
				Verdict string `json:"verdict"`
				Exit    string `json:"exit"`
			} `json:"expect"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &vd))
	byID := map[string]int{}
	for i, c := range vd.Cases {
		byID["policy/verify.json#"+c.ID] = i
	}
	// The private-mode cases have the same shape in private.json.
	praw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(t, err)
	n := len(vd.Cases)
	vd.Cases = nil
	require.NoError(t, json.Unmarshal(praw, &vd))
	for i, c := range vd.Cases {
		byID["policy/private.json#"+c.ID] = n + i
	}
	pcases := append(vd.Cases[:0:0], vd.Cases...)
	vd.Cases = nil
	require.NoError(t, json.Unmarshal(raw, &vd))
	vd.Cases = append(vd.Cases, pcases...)

	d := loadReasons(t)
	seen := 0
	for _, group := range [][]reasonCase{d.Cases, d.Boundary} {
		for _, rc := range group {
			if !strings.HasPrefix(rc.ID, "policy_") {
				continue
			}
			require.Len(t, rc.Refs, 1, rc.ID)
			if !strings.HasPrefix(rc.Refs[0], "policy/") {
				continue // an action case of v1/verify.json, TestPrivateActionVectors
			}
			i, ok := byID[rc.Refs[0]]
			require.True(t, ok, "%s refers to a missing case %s", rc.ID, rc.Refs[0])
			vc := vd.Cases[i]
			seen++
			t.Run(rc.ID, func(t *testing.T) {
				assert.Equal(t, rc.Expect.Verdict, vc.Expect.Verdict)
				assert.Equal(t, rc.Expect.Exit, vc.Expect.Exit)
				switch rc.Expect.Check {
				case "policy":
					assert.Equal(t, rc.Expect.Status, vc.Expect.Policy.Status)
					if rc.Expect.Reason != nil {
						assert.Equal(t, *rc.Expect.Reason, vc.Expect.Policy.Reason)
					}
				case "gate_integrity":
					if rc.Expect.Status == "violated" {
						assert.Equal(t, "violated", vc.Expect.Integrity.Status)
						require.NotNil(t, vc.Expect.Integrity.Reason)
						assert.Equal(t, *rc.Expect.Reason, *vc.Expect.Integrity.Reason)
					} else {
						assert.Equal(t, rc.Expect.Status, vc.Expect.Integrity.Status)
						got := vc.Expect.Policy.Reason
						if got == "" && vc.Expect.Integrity.Reason != nil {
							got = *vc.Expect.Integrity.Reason // carried by gate_integrity only
						}
						assert.Equal(t, *rc.Expect.Reason, got)
					}
				default:
					t.Errorf("unknown check %q", rc.Expect.Check)
				}
			})
		}
	}
	assert.GreaterOrEqual(t, seen, 11)
}
