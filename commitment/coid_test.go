package commitment_test

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestClientOrderIDVectors(t *testing.T) {
	var cf struct {
		Cases []struct {
			ID          string `json:"id"`
			Rail        string `json:"rail"`
			Ref         string `json:"commitment_ref"`
			HashHex     string `json:"commitment_hash_hex"`
			ClientOrder string `json:"client_order_id"`
		} `json:"cases"`
		Reject []struct {
			ID          string `json:"id"`
			Rail        string `json:"rail"`
			HashHex     string `json:"commitment_hash_hex"`
			ExpectError string `json:"expect_error"`
		} `json:"reject"`
	}
	loadJSON(t, "client_order_id.json", &cf)
	vf := loadValid(t)
	require.Lenf(t, cf.Cases, len(vf.Cases), "%d cases, %d rejects", len(cf.Cases), len(cf.Reject))
	require.Lenf(t, cf.Reject, 2, "%d cases, %d rejects", len(cf.Cases), len(cf.Reject))
	seen := map[string]string{}
	seenHash := map[string]string{}
	for _, c := range cf.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var h commitment.Hash
			copy(h[:], mustHex(t, c.HashHex))
			require.Equal(t, validCaseByID(t, vf, c.Ref).CommitmentHashHex, c.HashHex, "vector hash differs from the valid vector it references")
			got, err := commitment.ClientOrderID(commitment.Rail(u64(t, c.Rail)), h)
			require.NoError(t, err)
			require.Equal(t, c.ClientOrder, got)
			require.Equal(t, hex.EncodeToString(h[:]), got)
			require.True(t, hex64.MatchString(got))
			again, _ := commitment.ClientOrderID(commitment.RailIBKR, h)
			require.Equal(t, got, again, "not deterministic")
			prev, dup := seen[got]
			if dup {
				require.Equalf(t, seenHash[prev], c.HashHex, "same id as %s for a different hash", prev)
			}
			seen[got] = c.ID
			seenHash[c.ID] = c.HashHex
		})
	}
	for _, r := range cf.Reject {
		t.Run(r.ID, func(t *testing.T) {
			var h commitment.Hash
			copy(h[:], mustHex(t, r.HashHex))
			got, err := commitment.ClientOrderID(commitment.Rail(u64(t, r.Rail)), h)
			assertSentinel(t, err, r.ExpectError)
			require.Equalf(t, "", got, "id %q returned with an error", got)
		})
	}
}

func TestClientOrderIDZeroHashIsTotal(t *testing.T) {
	got, err := commitment.ClientOrderID(commitment.RailIBKR, commitment.Hash{})
	require.NoErrorf(t, err, "%q", got)
	require.Lenf(t, got, 64, "%q %v", got, err)
}
