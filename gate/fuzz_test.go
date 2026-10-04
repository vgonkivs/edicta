package gate_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// FuzzAdmit: Admit never panics, rejects only with known sentinels, calls the
// executor at most once, and calls it only for an envelope that passes the
// stateless verification with exactly the committed action bytes.
// INTERIM: ported to the authorizer entry point.
func FuzzAdmit(f *testing.F) {
	var vf struct {
		Cases []struct {
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	var rf struct {
		Cases []struct {
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"cases"`
	}
	gatefix.ReadVector(f, "valid.json", &vf)
	gatefix.ReadVector(f, "reject.json", &rf)
	action := gatefix.Action(f)
	for _, c := range vf.Cases {
		f.Add(gatefix.MustHex(f, c.EnvelopeHex), action)
	}
	for _, c := range rf.Cases {
		f.Add(gatefix.MustHex(f, c.EnvelopeHex), action)
	}
	seed, _ := gatefix.Sign(f, "agent1", gatefix.Template(f))
	f.Add(seed, action)
	f.Add(seed, []byte{})
	f.Add(seed, action[:len(action)-1])
	f.Add([]byte{}, action)
	f.Add([]byte{0xa0}, []byte{})

	blob := gatefix.Blob(f)
	f.Fuzz(func(t *testing.T, data, presented []byte) {
		e := gatefix.New(t)
		if s, err := commitment.DecodeSigned(data); err == nil {
			e.StageDA(&s.Commitment, blob)
		}
		res, err := e.AdmitWith(data, presented)
		if err != nil {
			require.Truef(t, gatefix.IsKnown(err), "rejection without a known sentinel: %v", err)
		} else {
			require.NotNil(t, res.Receipt, "admitted without a receipt")
		}
		n := e.Exec.Calls()
		require.LessOrEqual(t, n, 1, "executor called more than once")
		if n == 1 {
			p := commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}
			s, _, verr := commitment.VerifyForGate(data, gatefix.Now, e.Cfg.Scope, p)
			require.NoError(t, verr, "executor called for an envelope that fails verification")
			require.NoError(t, commitment.CheckAction(&s.Commitment, presented), "executor called for bytes other than the committed ones")
		}
		// A second submission never executes again.
		_, _ = e.AdmitWith(data, presented)
		require.LessOrEqual(t, e.Exec.Calls(), 1, "second submission executed")
	})
}
