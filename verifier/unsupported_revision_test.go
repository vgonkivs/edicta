// SPDX-License-Identifier: Apache-2.0

package verifier_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/internal/testkit"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const reasonsV105Path = "vectors/verifier/reasons_v1.0.5.json"

type vectorEnvelope struct {
	ID                string `json:"id"`
	EnvelopeHex       string `json:"envelope_hex"`
	CommitmentHashHex string `json:"commitment_hash_hex"`
}

// vectorEnvelopeOf returns the envelope and commitment hash of a case of a
// v1 vector file ("file#id").
func vectorEnvelopeOf(t testing.TB, ref string) ([]byte, commitment.Hash) {
	t.Helper()
	file, id, ok := strings.Cut(ref, "#")
	require.True(t, ok, ref)
	raw, err := os.ReadFile(testkit.SpecPath(t, "vectors", file))
	require.NoError(t, err)
	var d struct {
		Cases  []vectorEnvelope `json:"cases"`
		Reject []vectorEnvelope `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	for _, c := range append(d.Cases, d.Reject...) {
		if c.ID != id {
			continue
		}
		var h commitment.Hash
		copy(h[:], gatefix.MustHex(t, c.CommitmentHashHex))
		return gatefix.MustHex(t, c.EnvelopeHex), h
	}
	require.Failf(t, "no such case", "%s", ref)
	return nil, commitment.Hash{}
}

// vectorParts is an authorized decision whose envelope is the one of the
// case. Nothing after the envelope check reads the rest.
func vectorParts(t testing.TB, ref string) *parts {
	t.Helper()
	env, h := vectorEnvelopeOf(t, ref)
	p := newParts(t)
	p.env, p.hash = env, h
	p.blob, p.k2 = nil, nil
	p.auth = signAuth(t, gateKey(t), p.hash, p.c, commitment.PathDA, authExpires)
	return p
}

// rawDecision serves the given envelope as the authorized decision of any
// reference, as an archive copy would that the store itself refuses to write
// (an envelope that does not decode).
type rawDecision struct {
	verifier.Reader
	env []byte
}

func (rawDecision) State(context.Context, commitment.Hash) (archive.DecisionState, error) {
	return archive.DecisionState{State: archive.StateAuthorized}, nil
}

func (d rawDecision) Decision(context.Context, commitment.Hash) (*archive.DecisionRecord, error) {
	return &archive.DecisionRecord{Envelope: d.env, Form: archive.FormPublic}, nil
}

func rawRig(t testing.TB, env []byte, h commitment.Hash) *rig {
	t.Helper()
	r := newRig(t, newParts(t))
	r.p.hash = h
	r.deps.Archive = rawDecision{r.store, env}
	return r
}

// A da this revision does not define is unchecked, never invalid: a later
// revision may define it. da = 4 counts as unknown until the verifier reads it.
func TestUnknownDAIsUncheckedNotInvalid(t *testing.T) {
	for _, ref := range []string{
		"v1/unknown_da_v1.0.5.json#da_4", "v1/unknown_da_v1.0.5.json#da_5",
		"v1/unknown_da_v1.0.5.json#da_5_key_7", "v1/unknown_da_v1.0.5.json#da_4_signer_19",
	} {
		t.Run(ref, func(t *testing.T) {
			// The rig serves the envelope raw: a writer may refuse one that
			// does not decode strictly (da_5_key_7, da_4_signer_19).
			env, h := vectorEnvelopeOf(t, ref)
			rep := rawRig(t, env, h).verify(t)
			c := unchecked(t, rep, verifier.CheckEnvelope, verifier.ReasonUnsupportedRevision)
			require.ErrorIs(t, c.Err, commitment.ErrInvalidEnum)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			assert.Equal(t, archive.StateAuthorized, rep.State)
			assert.Equal(t, "2", exitOf(rep.Verdict))
			for _, ch := range rep.Checks {
				assert.NotEqual(t, verifier.StatusFail, ch.Status, ch.Name)
			}
		})
	}
}

// Through a real store the opaque-only envelopes are unchecked too, not a
// corrupt source.
func TestUnknownDAThroughARealStore(t *testing.T) {
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			rec, err := archive.Decode(c.Record(t))
			require.NoError(t, err)
			r := newRig(t, newParts(t))
			r.p.hash = c.Hash(t)
			_, err = r.store.Put(context.Background(), rec)
			require.NoError(t, err)
			rep := r.verify(t)
			ch := unchecked(t, rep, verifier.CheckEnvelope, verifier.ReasonUnsupportedRevision)
			require.ErrorIs(t, ch.Err, commitment.ErrInvalidEnum)
			for _, ch := range rep.Checks {
				assert.NotEqual(t, verifier.StatusFail, ch.Status, ch.Name)
				assert.NotEqual(t, verifier.ReasonSourceCorrupt, ch.Reason, ch.Name)
			}
		})
	}
}

// A copy that does not hash to the reference is a bad copy whatever its da,
// and a rule broken outside the opaque payload_ref stays fail.
func TestUnknownDAOtherCasesKeepTheirOutcome(t *testing.T) {
	env, h := vectorEnvelopeOf(t, "v1/unknown_da_v1.0.5.json#da_5_key_7")
	h[0] ^= 1
	rep := rawRig(t, env, h).verify(t)
	unchecked(t, rep, verifier.CheckEnvelope, verifier.ReasonSourceCorrupt)
}

// The opaque reading is the only change: a strict decode of the same
// envelopes still refuses them, which is what the gate does.
func TestGateDecodeStillRefusesUnknownDA(t *testing.T) {
	env, _ := vectorEnvelopeOf(t, "v1/unknown_da_v1.0.5.json#da_5_key_7")
	_, err := commitment.DecodeSigned(env)
	require.ErrorIs(t, err, commitment.ErrUnknownKey)
	env, _ = vectorEnvelopeOf(t, "v1/unknown_da_v1.0.5.json#da_4_signer_19")
	_, err = commitment.DecodeSigned(env)
	require.ErrorIs(t, err, commitment.ErrFieldSize)
}

// The reason's wording is the spec's.
func TestUnsupportedRevisionReasonText(t *testing.T) {
	d := readReasons(t, testkit.SpecPath(t, reasonsV105Path))
	require.Len(t, d.Reasons, 1)
	info, ok := verifier.ReasonUnsupportedRevision.Info()
	require.True(t, ok)
	assert.Equal(t, d.Reasons[0].Name, string(info.Reason))
	assert.Equal(t, d.Reasons[0].Checks, info.Checks)
	assert.Equal(t, d.Reasons[0].Meaning, info.Meaning)
	assert.Equal(t, d.Reasons[0].Advice, info.Advice)
}

// envelopeOf wraps raw commitment bytes the way an envelope is encoded.
func envelopeOf(raw, sig []byte, extra ...byte) []byte {
	n := byte(0xa2)
	if sig == nil {
		n = 0xa1
	}
	out := append([]byte{n + byte(len(extra)/2), 0x01}, raw...)
	if sig != nil {
		out = append(out, 0x02, 0x58, byte(len(sig)))
		out = append(out, sig...)
	}
	return append(out, extra...)
}

func rawAndSig(t testing.TB, ref string) (raw, sig []byte, h commitment.Hash) {
	t.Helper()
	env, h := vectorEnvelopeOf(t, ref)
	raw, err := commitment.EnvelopeCommitment(env)
	require.NoError(t, err)
	require.Equal(t, append([]byte{0xa2, 0x01}, raw...), env[:len(raw)+2])
	return raw, env[len(env)-64:], h
}

// A copy damaged outside the hash is a bad copy, never a verdict, whatever
// the payload_ref holds.
func TestUnknownDADamagedEnvelopeIsCorrupt(t *testing.T) {
	for _, ref := range []string{"v1/unknown_da_v1.0.5.json#da_5_key_7", "v1/unknown_da_v1.0.5.json#da_4_signer_19", "v1/unknown_da_v1.0.5.json#da_5"} {
		raw, sig, h := rawAndSig(t, ref)
		for name, env := range map[string][]byte{
			"no signature":    envelopeOf(raw, nil),
			"short signature": envelopeOf(raw, sig[:63]),
			"extra key":       envelopeOf(raw, sig, 0x03, 0x00),
		} {
			t.Run(ref+"/"+name, func(t *testing.T) {
				rep := rawRig(t, env, h).verify(t)
				unchecked(t, rep, verifier.CheckEnvelope, verifier.ReasonSourceCorrupt)
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			})
		}
	}
}

// A rule broken outside payload_ref still fails, with an undefined da too.
func TestUnknownDARuleBrokenOutsidePayloadRefFails(t *testing.T) {
	for _, ref := range []string{"v1/unknown_da_v1.0.5.json#da_5_key_7", "v1/unknown_da_v1.0.5.json#da_5"} {
		raw, sig, _ := rawAndSig(t, ref)
		for name, mod := range map[string]func([]byte) []byte{
			"version 2": func(b []byte) []byte {
				b = bytes.Clone(b)
				require.Equal(t, []byte{0x01, 0x01}, b[1:3])
				b[2] = 2
				return b
			},
			"agent_id charset": func(b []byte) []byte {
				return bytes.Replace(b, []byte("dca-agent-1"), []byte("dca agent-1"), 1)
			},
		} {
			t.Run(ref+"/"+name, func(t *testing.T) {
				raw := mod(raw)
				rep := rawRig(t, envelopeOf(raw, sig), commitment.HashCanonical(raw)).verify(t)
				failed(t, rep, verifier.CheckEnvelope)
				assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			})
		}
	}
}

// A defined da keeps the strict size check of its signer: a da = 2 commitment
// with a 19-byte signer is invalid.
func TestDefinedDASignerSizeFails(t *testing.T) {
	raw, sig, _ := rawAndSig(t, "v1/unknown_da_v1.0.5.json#da_4_signer_19")
	i := bytes.Index(raw, []byte{0x0a, 0xa5, 0x01, 0x04})
	require.Positive(t, i)
	raw = bytes.Clone(raw)
	raw[i+3] = byte(commitment.DACelestiaBlob)
	rep := rawRig(t, envelopeOf(raw, sig), commitment.HashCanonical(raw)).verify(t)
	failed(t, rep, verifier.CheckEnvelope)
	assert.ErrorIs(t, rep.Checks[len(rep.Checks)-1].Err, commitment.ErrFieldSize)
}

func TestUndefinedDANilDefined(t *testing.T) {
	env, _ := vectorEnvelopeOf(t, "v1/unknown_da_v1.0.5.json#da_5")
	_, ok := commitment.UndefinedDA(env, nil)
	assert.False(t, ok)
}
