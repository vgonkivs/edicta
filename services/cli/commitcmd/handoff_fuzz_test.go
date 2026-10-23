// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

func FuzzRecognisedRefusal(f *testing.F) {
	raw, err := hex.DecodeString(livePaymentID)
	require.NoError(f, err)
	pid := [32]byte(raw)
	quote := base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2,"accepts":[{"scheme":"escrow-upto","extra":{"paymentId":"0x` + livePaymentID + `"}}]}`))
	f.Add(402, quote, []byte(nil))
	f.Add(403, "", []byte(buyerText))
	f.Add(500, quote, []byte(buyerText))
	f.Add(402, "e30=", []byte("{}"))
	f.Fuzz(func(t *testing.T, status int, header string, body []byte) {
		got := commitcmd.RecognisedRefusal(status, header, body, pid)
		if len(body) > commitcmd.MaxRetryAnswer {
			require.Empty(t, got)
		}
		switch got {
		case "":
		case commitcmd.RefusalAsksAgain:
			require.Equal(t, 402, status)
			r, err := edenescrow.DecodePaymentRequired(header)
			require.NoError(t, err)
			require.NoError(t, edenescrow.CheckAsksForPayment(r, pid))
		case commitcmd.RefusalBuyer:
			require.Equal(t, 403, status)
			require.True(t, bytes.Contains(body, []byte("neither the escrow buyer")))
		default:
			t.Fatalf("unknown refusal %q", got)
		}
	})
}

func FuzzDecodePaidRetry(f *testing.F) {
	f.Add([]byte(`{"commitment_hash":"ab","payment_signature":"0x00","status":403,"body":"bmVpdGhlcg=="}`))
	f.Add([]byte(`{"status":402,"payment_required":"e30="}`))
	f.Add([]byte(`{"status":1,"status":2}`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte(`{"BodY":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := commitcmd.DecodePaidRetry(bytes.NewReader(data))
		if err != nil {
			return
		}
		again, err := json.Marshal(rep)
		require.NoError(t, err)
		back, err := commitcmd.DecodePaidRetry(bytes.NewReader(again))
		require.NoError(t, err)
		// An empty body is omitted on the way out and comes back as nil.
		assert.True(t, bytes.Equal(rep.Body, back.Body))
		rep.Body, back.Body = nil, nil
		assert.Equal(t, rep, back)
	})
}
