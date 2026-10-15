package verifier_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cases of v1/verify_v1.1.json: in-window evidence that verifies passes
// once header trust reaches its height H, while every other row still waits
// for the deadline (or deadline + 1 with a results proof).
func TestPendingVerifyVectorsV11(t *testing.T) {
	window, cases := loadFastFile(t, verifyV11VectorsPath, "v1.1")
	require.Equal(t, uint64(fastWindow), window)
	require.Len(t, cases, 8)
	assert.Equal(t, len(cases), runFastCases(t, cases), "every case of the file ran")
}

// The v1.1 outcome only ever moves anchor_pending to pass relative to the
// frozen text, and nothing else.
func TestPresenceVectorsMoveOnlyPendingToPass(t *testing.T) {
	_, cases := loadFastFile(t, verifyV11VectorsPath, "v1.1")
	for _, c := range cases {
		require.NotNil(t, c.V10, c.ID)
		require.NotNil(t, c.Expect.Anchor, c.ID)
		now, was := c.Expect.Anchor, c.V10.Anchor
		if now.Status == was.Status && now.Reason == was.Reason {
			continue
		}
		assert.Equal(t, "unchecked", was.Status, c.ID)
		assert.Equal(t, "anchor_pending", was.Reason, c.ID)
		assert.Equal(t, "pass", now.Status, c.ID)
	}
}

// header_trust_needs is the bound of each case: one height below it the
// anchor is anchor_pending, and for in-window evidence that verifies the
// bound is H itself, where the anchor passes.
func TestPresenceVectorsHeaderTrustBound(t *testing.T) {
	_, cases := loadFastFile(t, verifyV11VectorsPath, "v1.1")
	var variants []fastCase
	for _, c := range cases {
		need, err := strconv.ParseUint(c.Expect.HeaderTrustNeeds, 10, 64)
		require.NoError(t, err, c.ID)

		below := c
		below.ID = c.ID + "/below_bound"
		below.TrustedHead = strconv.FormatUint(need-1, 10)
		below.Expect.Anchor = &fastAnchor{Status: "unchecked", Reason: "anchor_pending"}
		below.Expect.Report.AnchorHeight = ""
		below.Expect.Report.Publication = "unknown"
		below.Expect.Verdict = "unchecked"
		variants = append(variants, below)

		if c.Evidence == nil || !c.Evidence.Verifies {
			continue
		}
		deadline, err := strconv.ParseUint(c.Expect.Report.AnchorDeadline, 10, 64)
		require.NoError(t, err, c.ID)
		H, err := strconv.ParseUint(c.Evidence.Height, 10, 64)
		require.NoError(t, err, c.ID)
		require.LessOrEqual(t, H, deadline, c.ID)
		assert.Equal(t, H, need, "%s: evidence inside the window needs header trust up to H only", c.ID)

		at := c
		at.ID = c.ID + "/at_bound"
		at.TrustedHead = c.Expect.HeaderTrustNeeds
		at.Expect.Anchor = &fastAnchor{Status: "pass"}
		at.Expect.Report.AnchorHeight = c.Evidence.Height
		at.Expect.Report.Publication = "anchored"
		at.Expect.Verdict = "valid"
		variants = append(variants, at)
	}
	assert.Equal(t, len(variants), runFastCases(t, variants))
}
