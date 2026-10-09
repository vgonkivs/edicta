package verifier

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/sdk/blob"
)

type privCase struct {
	vecCase
	Config struct {
		AuditorKeys []string `json:"auditor_keys"`
	} `json:"config"`
	Expect struct {
		Policy struct {
			Mode       string `json:"mode"`
			AuditorKid string `json:"auditor_kid"`
		} `json:"policy"`
		Integrity struct {
			Walk *struct {
				MaxSteps string  `json:"max_steps"`
				Steps    string  `json:"steps"`
				FromSeq  *string `json:"from_seq"`
				ToSeq    *string `json:"to_seq"`
				Total    *string `json:"total"`
				End      string  `json:"end"`
			} `json:"walk"`
		} `json:"gate_integrity"`
	} `json:"expect"`
}

type privDoc struct {
	vecDoc
	Cases []json.RawMessage `json:"cases"`
}

// privArchive is vecArchive that also reads private blobs.
type privArchive struct{ vecArchive }

func (a privArchive) PrivateBlob(_ context.Context, kind policy.PrivateKind, h commitment.Hash) (*archive.PrivateBlobRecord, error) {
	p, err := archive.PrivateBlobPath(kind, h)
	if err != nil {
		return nil, archive.ErrNotFound
	}
	r, err := a.get(p)
	if err != nil {
		return nil, err
	}
	return r.(*archive.PrivateBlobRecord), nil
}

func auditorRecipientKey(t testing.TB, skHex string) blob.RecipientKey {
	sk, err := ecdh.X25519().NewPrivateKey(unhex(t, skHex))
	require.NoError(t, err)
	k, err := blob.NewRecipientKey(sk)
	require.NoError(t, err)
	return k
}

// TestPrivateVerifyVectors runs the verifier cases of
// spec/vectors/policy/private.json: with and without an auditor key.
func TestPrivateVerifyVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(t, err)
	var d privDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Len(t, d.Cases, 20)
	for _, rc := range d.Cases {
		var c privCase
		require.NoError(t, json.Unmarshal(rc, &c.vecCase))
		require.NoError(t, json.Unmarshal(rc, &c))
		t.Run(c.ID, func(t *testing.T) {
			v, arch := c.vecCase.verifier(t, d.vecDoc)
			v.archive = privArchive{arch}
			for _, k := range c.Config.AuditorKeys {
				v.cfg.AuditorKeys = append(v.cfg.AuditorKeys, auditorRecipientKey(t, k))
			}
			out, err := v.checkPolicy(t.Context(), c.input(t, d.vecDoc))
			require.NoError(t, err)
			require.True(t, out.Ran)
			assert.Equal(t, Status(c.vecCase.Expect.Policy.Status), out.Check.Status, "%v", out.Check.Err)
			switch out.Check.Status {
			case StatusFail:
				var pf *PolicyFailure
				require.ErrorAs(t, out.Check.Err, &pf)
				assert.Equal(t, c.vecCase.Expect.Policy.Rule, pf.Rule)
			case StatusUnchecked:
				assert.Equal(t, Reason(c.vecCase.Expect.Policy.Reason), out.Check.Reason)
			}
			require.NotNil(t, out.Info)
			assert.Equal(t, PolicyMode(c.Expect.Policy.Mode), out.Info.Mode)
			assert.Equal(t, MandateRefStatus(c.vecCase.Expect.Policy.MandateRef), out.Info.MandateRef)
			if c.Expect.Policy.AuditorKid != "" {
				assert.Equal(t, c.Expect.Policy.AuditorKid, policy.Fingerprint(out.Info.AuditorKid))
			} else {
				assert.Empty(t, out.Info.AuditorKid)
			}

			ig := out.Integrity
			assert.Equal(t, IntegrityStatus(c.vecCase.Expect.Integrity.Status), ig.Status)
			want := ""
			if r := c.vecCase.Expect.Integrity.Reason; r != nil {
				want = *r
			}
			assert.Equal(t, want, string(ig.Reason))
			var got []string
			for _, h := range ig.EvidenceHashes {
				got = append(got, hex.EncodeToString(h[:]))
			}
			assert.Equal(t, len(c.vecCase.Expect.Integrity.Evidence), len(got))
			if len(got) > 0 {
				assert.Equal(t, c.vecCase.Expect.Integrity.Evidence, got)
			}
			if w := c.Expect.Integrity.Walk; w != nil {
				require.NotNil(t, ig.Walk)
				u := func(s string) uint64 {
					n, err := strconv.ParseUint(s, 10, 64)
					require.NoError(t, err)
					return n
				}
				assert.Equal(t, u(w.MaxSteps), ig.Walk.MaxSteps)
				assert.Equal(t, u(w.Steps), ig.Walk.Steps)
				assert.Equal(t, WalkEnd(w.End), ig.Walk.End)
				assert.Equal(t, w.ToSeq == nil, ig.Walk.SeqPrivate, "sequence fields absent iff not opened")
				if w.ToSeq != nil {
					assert.Equal(t, u(*w.FromSeq), ig.Walk.FromSeq)
					assert.Equal(t, u(*w.ToSeq), ig.Walk.ToSeq)
					assert.Equal(t, u(*w.Total), ig.Walk.Total)
				}
			} else {
				assert.Nil(t, ig.Walk)
			}

			rep := verdictOf(v, out)
			assert.Equal(t, Verdict(c.vecCase.Expect.Verdict), rep.Verdict)
			assert.Equal(t, c.vecCase.Expect.Exit, exitFor(rep))
		})
	}
}
