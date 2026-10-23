// SPDX-License-Identifier: Apache-2.0

package commitcmd_test

import (
	"encoding/hex"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/services/cli/commitcmd"
)

func mainnetFile(t *testing.T, run, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testkit.SpecPath(t, "vectors/profiles/eden-escrow/live", run, name))
	require.NoError(t, err)
	return b
}

func TestRecognisedRefusalOnRecordedAnswers(t *testing.T) {
	var refusedPID, paidPID [32]byte
	_, err := hex.Decode(refusedPID[:], []byte("6cba341c3798488c48156cb82cfa9b6bb11557c8c974efa94acc30e5bfab9c49"))
	require.NoError(t, err)
	_, err = hex.Decode(paidPID[:], []byte("5b6d992c5e3090d174e4fedb3f1ab47ef2f9f6e5cc0f25abb425c56c79c1a9a5"))
	require.NoError(t, err)

	body := mainnetFile(t, "mainnet-nonce-refused", "body-paid-retry-403.json")
	assert.Equal(t, commitcmd.RefusalBuyer, commitcmd.RecognisedRefusal(http.StatusForbidden, "", body, refusedPID),
		"the recorded 403 of the buyer check is RR2")
	assert.Empty(t, commitcmd.RecognisedRefusal(http.StatusOK, "", nil, paidPID), "a paid 200 is no refusal")

	header := string(mainnetFile(t, "mainnet-paymentid", "header-payment-required.b64"))
	quoteBody := mainnetFile(t, "mainnet-paymentid", "body-quote-402.json")
	assert.Equal(t, commitcmd.RefusalAsksAgain, commitcmd.RecognisedRefusal(http.StatusPaymentRequired, header, quoteBody, paidPID),
		"a 402 whose wire header names the decision's paymentId would be RR1")
	assert.Empty(t, commitcmd.RecognisedRefusal(http.StatusPaymentRequired, header, quoteBody, refusedPID),
		"the same header for another paymentId is a new quote")
}
