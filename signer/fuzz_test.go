// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/signertest"
)

// FuzzDecodeSignRequest: the request decoder never panics, accepts only the
// canonical encoding (re-encoding gives the input back), and the JSON path
// yields only bytes the CBOR decoder then judges.
func FuzzDecodeSignRequest(f *testing.F) {
	k := signertest.NewKeys("fuzz")
	now := time.Unix(1_800_000_000, 0)
	action, err := signertest.NewDeposit(now).Action()
	require.NoError(f, err)
	d, err := signertest.NewDecision(k, action, now, signertest.DecisionOpts{})
	require.NoError(f, err)
	good := signer.EncodeSignRequest(request(d))
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte(`{"envelope":"AA==","action":"AA==","action_salt":"AA==","signed_authorization":"AA=="}`))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if req, err := signer.DecodeSignRequest(b); err == nil {
			require.True(t, bytes.Equal(b, signer.EncodeSignRequest(req)), "only the canonical encoding decodes")
			require.Len(t, req.Salt, 32)
		}
		if w, err := edictaapi.JSONToWrapper(b, signer.SignRequestSchema); err == nil {
			if req, err := signer.DecodeSignRequest(w); err == nil {
				require.True(t, bytes.Equal(w, signer.EncodeSignRequest(req)))
			}
		}
	})
}
