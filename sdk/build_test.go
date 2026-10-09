package sdk_test

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func inputOf(c *commitment.Commitment) sdk.Input {
	in := sdk.Input{
		AgentID:     c.AgentID,
		AgentPubKey: ed25519.PublicKey(c.AgentPubKey),
		IssuedAt:    c.IssuedAt,
		ValidUntil:  c.ValidUntil,
		Scope:       c.Scope,
		Action:      c.Action,
		Ref:         c.PayloadRef,
		PayloadSize: c.PayloadSize,
	}
	copy(in.Nonce[:], c.Nonce)
	copy(in.CiphertextHash[:], c.CiphertextHash)
	copy(in.PlaintextHash[:], c.PlaintextHash)
	return in
}

type weakKey struct {
	id  string
	pub ed25519.PublicKey
}

// sdkRejectKeys are the agent keys of the stage G public key vectors.
func sdkRejectKeys(t testing.TB) []weakKey {
	var out []weakKey
	for _, in := range sdkfix.RejectInputs(t) {
		if in.Stage == "G" && strings.HasPrefix(in.ID, "pubkey_") {
			out = append(out, weakKey{in.ID, ed25519.PublicKey(in.Commitment.AgentPubKey)})
		}
	}
	require.GreaterOrEqual(t, len(out), 16)
	return out
}

// Positive control: the commitment of a valid vector is rebuilt byte for byte.
func TestBuildCommitmentReproducesAValidVector(t *testing.T) {
	tmpl := gatefix.Template(t)
	want, err := commitment.Encode(tmpl)
	require.NoError(t, err)

	c, err := sdk.BuildCommitment(inputOf(tmpl), params)
	require.NoError(t, err)
	got, err := commitment.Encode(c)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.EqualValues(t, commitment.Version, c.Version)
}

// Every stage S vector of reject.json, rebuilt from its input, is refused with
// the vector's own sentinel. Version 1 has no field in Input: the builder
// always writes version 0.
func TestBuildCommitmentRefusesEveryStageSVector(t *testing.T) {
	n := 0
	for _, in := range sdkfix.RejectInputs(t) {
		// The builder always writes the one version, so the version rule has
		// no input to rebuild.
		if in.Stage != "S" || in.Rule == "S1" {
			continue
		}
		n++
		t.Run(in.ID, func(t *testing.T) {
			want, ok := gatefix.Sentinel(in.Expect)
			require.Truef(t, ok, "unknown sentinel %s", in.Expect)
			require.Len(t, in.Commitment.Nonce, 16)
			require.Len(t, in.Commitment.CiphertextHash, 32)
			require.Len(t, in.Commitment.PlaintextHash, 32)

			c, err := sdk.BuildCommitment(inputOf(in.Commitment), in.Params)
			require.ErrorIs(t, err, want)
			assert.Nil(t, c)
		})
	}
	require.GreaterOrEqual(t, n, 16, "the table must mirror the vectors")
}

// Values the commitment decoder refuses (lengths, charsets, kinds), which the
// gate reports as decode errors.
func TestBuildCommitmentRefusesDecodeLevelValues(t *testing.T) {
	good := func() sdk.Input { return inputOf(gatefix.Template(t)) }
	tests := []struct {
		name string
		mod  func(in *sdk.Input)
		want error
	}{
		{"agent id empty", func(in *sdk.Input) { in.AgentID = "" }, commitment.ErrFieldSize},
		{"agent id 65 chars", func(in *sdk.Input) { in.AgentID = strings.Repeat("a", 65) }, commitment.ErrFieldSize},
		{"agent id 64 chars is fine", func(in *sdk.Input) { in.AgentID = strings.Repeat("a", 64) }, nil},
		{"gate id with a non-ASCII letter", func(in *sdk.Input) { in.Scope.GateID = "gäte" }, commitment.ErrInvalidString},
		{"action type of 129 characters", func(in *sdk.Input) {
			in.Action.Type = "application/" + strings.Repeat("a", 129-len("application/"))
		}, commitment.ErrFieldSize},
		{"action type of 128 characters is fine", func(in *sdk.Input) {
			in.Action.Type = "application/" + strings.Repeat("a", 128-len("application/"))
		}, nil},
		{"action type in upper case", func(in *sdk.Input) { in.Action.Type = "Application/json" }, commitment.ErrInvalidString},
		{"action type with a parameter", func(in *sdk.Input) { in.Action.Type = "application/json; charset=utf-8" }, commitment.ErrInvalidString},
		{"action type without a slash", func(in *sdk.Input) { in.Action.Type = "applicationjson" }, commitment.ErrInvalidString},
		{"action type empty", func(in *sdk.Input) { in.Action.Type = "" }, commitment.ErrFieldSize},
		{"action hash of 31 bytes", func(in *sdk.Input) { in.Action.Hash = in.Action.Hash[:31] }, commitment.ErrFieldSize},
		{"action hash of 33 bytes", func(in *sdk.Input) { in.Action.Hash = append(bytes.Clone(in.Action.Hash), 0) }, commitment.ErrFieldSize},
		{"namespace of 28 bytes", func(in *sdk.Input) { in.Ref.Namespace = in.Ref.Namespace[:28] }, commitment.ErrFieldSize},
		{"share commitment of 31 bytes", func(in *sdk.Input) { in.Ref.Commitment = in.Ref.Commitment[:31] }, commitment.ErrFieldSize},
		{"signer of 19 bytes", func(in *sdk.Input) { in.Ref.Signer = in.Ref.Signer[:19] }, commitment.ErrFieldSize},
		{"signer of 32 bytes", func(in *sdk.Input) { in.Ref.Signer = bytes.Repeat([]byte{1}, 32) }, commitment.ErrFieldSize},
		{"no signer for da 2", func(in *sdk.Input) { in.Ref.Signer = nil }, commitment.ErrMissingField},
		{"signer on a fibre ref", func(in *sdk.Input) {
			in.Ref.DA = commitment.DAFibre
		}, commitment.ErrUnknownKey},
		{"fibre commitment of 33 bytes", func(in *sdk.Input) {
			in.Ref.DA = commitment.DAFibre
			in.Ref.Signer = nil
			in.Ref.Commitment = append(in.Ref.Commitment, 0)
		}, commitment.ErrFieldSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := good()
			in.Ref.Namespace = bytes.Clone(in.Ref.Namespace)
			in.Ref.Commitment = bytes.Clone(in.Ref.Commitment)
			in.Ref.Signer = bytes.Clone(in.Ref.Signer)
			tt.mod(&in)
			c, err := sdk.BuildCommitment(in, params)
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
			assert.Nil(t, c)
		})
	}
}

// The decisions the gate's static stage refuses, reached through the whole
// builder: nothing is published and nothing is signed. The payload is
// re-encoded around the action of the vector, so only static defects remain.
func TestBuilderRefusesStaticVectorsBeforePublishing(t *testing.T) {
	ids := map[string]bool{
		"height_0": true, "height_2pow63": true,
		"da_0": true, "da_3": true, "da_256": true,
	}
	n := 0
	for _, in := range sdkfix.RejectInputs(t) {
		if !ids[in.ID] {
			continue
		}
		n++
		t.Run(in.ID, func(t *testing.T) {
			want, ok := gatefix.Sentinel(in.Expect)
			require.True(t, ok)
			// Height and da come from the publisher, so the defect is injected
			// where the builder takes it from.
			r := newRig(t, func(r *rig) {
				r.rec.mutate = func(p *sdk.Published) {
					p.Ref.DA = in.Commitment.PayloadRef.DA
					p.Ref.Height = in.Commitment.PayloadRef.Height
				}
			})
			res, err := r.builder().Commit(bg, r.payload())
			require.Error(t, err)
			require.Truef(t, isAny(err, want, sdk.ErrPublishResult), "unexpected error %v", err)
			assert.Nil(t, res)
			assert.Zero(t, r.signer.calls())
		})
	}
	require.Len(t, ids, n, "every named vector must exist")
}

// A scope the gate cannot match is refused by the builder at New or at the
// first commitment, never signed: only a well-formed gate id is accepted.
func TestBuilderRefusesMalformedScope(t *testing.T) {
	tests := []struct {
		name string
		mod  func(s *commitment.Scope)
		want error
	}{
		{"gate id empty", func(s *commitment.Scope) { s.GateID = "" }, commitment.ErrFieldSize},
		{"gate id of 65 characters", func(s *commitment.Scope) { s.GateID = strings.Repeat("g", 65) }, commitment.ErrFieldSize},
		{"gate id with a non-ASCII letter", func(s *commitment.Scope) { s.GateID = "g\u00e4te" }, commitment.ErrInvalidString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, func(r *rig) { tt.mod(&r.cfg.Scope) })
			b, err := r.tryNew()
			if err == nil {
				_, err = b.Commit(bg, r.payload())
			}
			require.Error(t, err)
			require.Truef(t, isAny(err, tt.want, sdk.ErrInvalidConfig), "unexpected error %v", err)
			assert.Zero(t, r.rec.calls())
			assert.Zero(t, r.signer.calls())
		})
	}
}

// A time-stage vector is a validity window decision: the builder never emits
// a commitment the gate would find expired or not yet valid.
func TestChooseValidityMirrorsTheTimeVectors(t *testing.T) {
	const n = uint64(1_000_000)
	base := sdk.Window{Now: n, BlockTime: n - 100, DA: commitment.DACelestiaBlob, BlobRetentionS: 14400, SkewS: 30, TTLS: 900, MinValidityS: 60}
	tests := []struct {
		name string
		mod  func(w *sdk.Window)
	}{
		{"expiry inside the skew", func(w *sdk.Window) { w.TTLS = 30 }},
		{"valid_until already past", func(w *sdk.Window) { w.TTLS = 0 }},
		{"window of 59 s", func(w *sdk.Window) { w.TTLS = 59 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := base
			tt.mod(&w)
			_, err := sdk.ChooseValidity(w)
			require.ErrorIs(t, err, sdk.ErrValidityWindow)
		})
	}
}

func TestChooseValidity(t *testing.T) {
	const n = uint64(1_000_000)
	base := func() sdk.Window {
		return sdk.Window{Now: n, BlockTime: n - 10, DA: commitment.DACelestiaBlob,
			BlobRetentionS: 14400, SkewS: 30, TTLS: 900, MinValidityS: 60}
	}
	fibre := func() sdk.Window {
		w := base()
		w.DA = commitment.DAFibre
		w.RetentionStart = n - 200
		w.FibreLatestS, w.FibreAtHeightS = 14400, 14400
		return w
	}
	tests := []struct {
		name    string
		w       sdk.Window
		want    sdk.Validity
		wantErr error
	}{
		{"plain da 2", base(), sdk.Validity{IssuedAt: n, ValidUntil: n + 900, RequestedUntil: n + 900}, nil},
		{"anchor ahead of now within skew", func() sdk.Window { w := base(); w.BlockTime = n + 20; return w }(),
			sdk.Validity{IssuedAt: n + 20, ValidUntil: n + 920, RequestedUntil: n + 920}, nil},
		{"anchor ahead by more than skew", func() sdk.Window { w := base(); w.BlockTime = n + 31; return w }(), sdk.Validity{}, sdk.ErrClockBehindAnchor},
		{"no block time", func() sdk.Window { w := base(); w.BlockTime = 0; return w }(), sdk.Validity{}, sdk.ErrPublishResult},
		{"ttl above the maximum", func() sdk.Window { w := base(); w.TTLS = 4000; return w }(),
			sdk.Validity{IssuedAt: n, ValidUntil: n + 3600, RequestedUntil: n + 4000, Clamped: true, ClampedBy: "max_ttl"}, nil},
		{"maximum depends on the blob retention", func() sdk.Window { w := base(); w.BlobRetentionS = 2400; w.BlockTime = n - 10; return w }(),
			// ttl max = 600, retention bound = n-10+2400-300 = n+2090
			sdk.Validity{IssuedAt: n, ValidUntil: n + 600, RequestedUntil: n + 900, Clamped: true, ClampedBy: "max_ttl"}, nil},
		{"anchor old: retention bound binds", func() sdk.Window { w := base(); w.TTLS = 3600; w.BlockTime = n - 12000; return w }(),
			sdk.Validity{IssuedAt: n, ValidUntil: n + 1800, RequestedUntil: n + 3600, Clamped: true, ClampedBy: "retention"}, nil},
		{"60 s remaining is enough", func() sdk.Window { w := base(); w.BlockTime = n - 13740; return w }(),
			sdk.Validity{IssuedAt: n, ValidUntil: n + 60, RequestedUntil: n + 900, Clamped: true, ClampedBy: "retention"}, nil},
		{"59 s remaining is refused", func() sdk.Window { w := base(); w.BlockTime = n - 13741; return w }(), sdk.Validity{}, sdk.ErrValidityWindow},
		{"retention already gone", func() sdk.Window { w := base(); w.BlockTime = n - 20000; return w }(), sdk.Validity{}, sdk.ErrValidityWindow},
		{"ttl of 60", func() sdk.Window { w := base(); w.TTLS = 60; return w }(),
			sdk.Validity{IssuedAt: n, ValidUntil: n + 60, RequestedUntil: n + 60}, nil},
		{"ttl of 59", func() sdk.Window { w := base(); w.TTLS = 59; return w }(), sdk.Validity{}, sdk.ErrValidityWindow},
		{"ttl of 0", func() sdk.Window { w := base(); w.TTLS = 0; return w }(), sdk.Validity{}, sdk.ErrValidityWindow},
		{"larger minimum", func() sdk.Window { w := base(); w.MinValidityS = 600; w.TTLS = 599; return w }(), sdk.Validity{}, sdk.ErrValidityWindow},

		{"fibre plain", fibre(), sdk.Validity{IssuedAt: n, ValidUntil: n + 900, RequestedUntil: n + 900}, nil},
		{"fibre without a payment promise time", func() sdk.Window { w := fibre(); w.RetentionStart = 0; return w }(), sdk.Validity{}, sdk.ErrPublishResult},
		{"fibre retention at the height is shorter", func() sdk.Window { w := fibre(); w.FibreAtHeightS = 600; return w }(),
			// start = n-200, r = 600, margin 75
			sdk.Validity{IssuedAt: n, ValidUntil: n + 325, RequestedUntil: n + 900, Clamped: true, ClampedBy: "retention"}, nil},
		{"fibre latest retention is shorter", func() sdk.Window { w := fibre(); w.FibreLatestS = 400; return w }(),
			// ttl max = 100; retention bound = n-200+400-50 = n+150
			sdk.Validity{IssuedAt: n, ValidUntil: n + 100, RequestedUntil: n + 900, Clamped: true, ClampedBy: "max_ttl"}, nil},
		{"fibre start is the earlier of block and promise", func() sdk.Window {
			w := fibre()
			w.RetentionStart = n + 5 // after the block: the block time is the start
			w.FibreAtHeightS = 700   // margin 87
			w.TTLS = 3000
			return w
		}(), sdk.Validity{IssuedAt: n, ValidUntil: n - 10 + 700 - 87, RequestedUntil: n + 3000, Clamped: true, ClampedBy: "retention"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := sdk.ChooseValidity(tt.w)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, v)
			checkValidityProperties(t, tt.w, v)
		})
	}
}

// Properties of every successful decision, whatever the inputs.
func checkValidityProperties(t testing.TB, w sdk.Window, v sdk.Validity) {
	t.Helper()
	require.LessOrEqual(t, v.ValidUntil, v.RequestedUntil, "valid_until is never extended")
	require.Greater(t, v.ValidUntil, v.IssuedAt)
	require.Equal(t, max(w.Now, w.BlockTime), v.IssuedAt, "issued_at = max(now, T_H)")
	require.Equal(t, v.ValidUntil < v.RequestedUntil, v.Clamped)
	require.Equal(t, v.Clamped, v.ClampedBy != "")
	if v.Clamped {
		require.Contains(t, []string{"max_ttl", "retention"}, v.ClampedBy)
	}
	require.Equal(t, v.IssuedAt+w.TTLS, v.RequestedUntil, "requested = issued_at + ttl")
	require.GreaterOrEqual(t, v.ValidUntil, w.Now+w.MinValidityS)
	require.Greater(t, v.ValidUntil, w.Now+w.SkewS)
}
