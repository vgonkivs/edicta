// SPDX-License-Identifier: Apache-2.0

package commitcmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenescrow"
	"github.com/vgonkivs/edicta/internal/testkit"
)

func liveBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, "vectors", "profiles", "eden-escrow", "live", name))
	require.NoError(t, err)
	return b
}

func TestPreparedContextBindsTheQuoteAndKeepsTheCallersMembers(t *testing.T) {
	rr := liveBytes(t, "houston-payment-required.json")
	s := &Service{Clock: func() time.Time { return time.Unix(1792466814-200, 0) }}
	pre, f := s.prepareEden(Request{
		Context: []byte(`{"why": "dca", "n": 1.50}`),
		Eden: &EdenInput{
			Build:           liveBytes(t, "houston-deposit-build.json"),
			PaymentRequired: base64.StdEncoding.EncodeToString(rr),
			Resource:        "https://inference.bot.fun/v1/chat/completions",
		},
	})
	require.Nil(t, f)

	var ctx map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(pre.ctx, &ctx))
	assert.JSONEq(t, `"dca"`, string(ctx["why"]))
	assert.Equal(t, "1.50", string(ctx["n"]), "the caller's numbers are not rewritten")

	var ec struct {
		PaymentRequired []byte `json:"payment_required"`
		RequirementsH   string `json:"requirements_hash"`
		Resource        string `json:"resource"`
		Header          string `json:"payment_required_header"`
	}
	require.NoError(t, json.Unmarshal(ctx[ContextKey], &ec))
	assert.Equal(t, rr, ec.PaymentRequired, "an auditor gets R byte for byte")
	assert.Equal(t, base64.StdEncoding.EncodeToString(rr), ec.Header, "the header as received is kept")
	assert.Equal(t, "https://inference.bot.fun/v1/chat/completions", ec.Resource)

	// What an auditor recomputes from the payload equals what the action commits.
	h := edenescrow.RequirementsHash(ec.PaymentRequired)
	assert.Equal(t, hex.EncodeToString(h[:]), ec.RequirementsH)
	assert.Equal(t, h, pre.tx.RequirementsHash)
	decoded, err := edenescrow.DecodeTxAction(pre.action)
	require.NoError(t, err)
	assert.Equal(t, h, decoded.RequirementsHash)
}

func TestPreparedContextWithoutACallerContext(t *testing.T) {
	rr := liveBytes(t, "houston-payment-required.json")
	s := &Service{Clock: func() time.Time { return time.Unix(1792466814-200, 0) }}
	pre, f := s.prepareEden(Request{Eden: &EdenInput{
		Build:           liveBytes(t, "houston-deposit-build.json"),
		PaymentRequired: base64.StdEncoding.EncodeToString(rr),
		Resource:        "https://inference.bot.fun/v1/chat/completions",
	}})
	require.Nil(t, f)
	var ctx map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(pre.ctx, &ctx))
	assert.Len(t, ctx, 1)
}

func TestQuoteResource(t *testing.T) {
	assert.Equal(t, "http://inference.bot.fun/v1/chat/completions", quoteResource(liveBytes(t, "houston-payment-required.json")))
	assert.Empty(t, quoteResource([]byte(`{"resource":"x"}`)))
	assert.Empty(t, quoteResource([]byte(`not json`)))
}

func TestParseProofSignature(t *testing.T) {
	good := []byte("0x" + hex.EncodeToString(make([]byte, 65)))
	_, ok := parseProofSignature(good)
	assert.True(t, ok)
	for _, bad := range []string{"", "0x", "00" + hex.EncodeToString(make([]byte, 65)), "0x" + hex.EncodeToString(make([]byte, 64)), "0xzz"} {
		_, ok := parseProofSignature([]byte(bad))
		assert.False(t, ok, bad)
	}
}
