// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAsksForPaymentOnTheRequirementsVectors(t *testing.T) {
	v, _, a := x402Build(t)
	pid := a.Deposit.PaymentID
	other := pid
	other[0] ^= 1

	require.NoError(t, CheckAsksForPayment(readVectorFile(t, v.Build.RequirementsFromFile), pid), "the recorded quote")
	for _, c := range v.Requirements.Accept {
		r := unhex(t, c.RHex)
		assert.NoError(t, CheckAsksForPayment(r, pid), c.ID)
		err := CheckAsksForPayment(r, other)
		require.ErrorIs(t, err, ErrRequirements, c.ID)
		assert.Equal(t, "S4d", ruleOf(t, err), "another paymentId is a new quote: %s", c.ID)
	}
	for _, c := range v.Requirements.Reject {
		r := unhex(t, c.RHex)
		err := CheckAsksForPayment(r, pid)
		switch c.Expect {
		case "S4a", "S4c", "S4d":
			require.ErrorIs(t, err, ErrRequirements, c.ID)
			assert.Equal(t, c.Expect, ruleOf(t, err), c.ID)
		case "S4e", "S4f":
			assert.NoError(t, err, "only the document and the paymentId are read: %s", c.ID)
		}
	}
}

func TestCheckAsksForPaymentEntries(t *testing.T) {
	id := [32]byte{0xab}
	hexID := "0xab00000000000000000000000000000000000000000000000000000000000000"
	otherID := "0xcd00000000000000000000000000000000000000000000000000000000000000"
	entry := func(scheme, id string) string {
		return `{"scheme":"` + scheme + `","extra":{"paymentId":"` + id + `"}}`
	}
	doc := func(entries ...string) []byte {
		s := `{"x402Version":2,"accepts":[`
		for i, e := range entries {
			if i > 0 {
				s += ","
			}
			s += e
		}
		return []byte(s + `]}`)
	}
	for name, tc := range map[string]struct {
		r    []byte
		rule string
	}{
		"one entry for the payment":          {doc(entry(Scheme, hexID)), ""},
		"other schemes are ignored":          {doc(entry("exact", otherID), entry(Scheme, hexID)), ""},
		"an entry for another paymentId too": {doc(entry(Scheme, otherID), entry(Scheme, hexID)), ""},
		"only another paymentId":             {doc(entry(Scheme, otherID)), "S4d"},
		"two entries for the payment":        {doc(entry(Scheme, hexID), entry(Scheme, hexID)), "S4d"},
		"no entries":                         {doc(), "S4d"},
		"upper-case hex paymentId":           {doc(entry(Scheme, "0xAB00000000000000000000000000000000000000000000000000000000000000")), ""},
		"x402Version 2.0":                    {[]byte(`{"x402Version":2.0,"accepts":[` + entry(Scheme, hexID) + `]}`), "S4c"},
		"a repeated member":                  {[]byte(`{"x402Version":2,"x402Version":2,"accepts":[` + entry(Scheme, hexID) + `]}`), "S4c"},
		"empty":                              {nil, "S4a"},
	} {
		err := CheckAsksForPayment(tc.r, id)
		if tc.rule == "" {
			assert.NoError(t, err, name)
			continue
		}
		require.ErrorIs(t, err, ErrRequirements, name)
		assert.Equal(t, tc.rule, ruleOf(t, err), name)
	}
}
