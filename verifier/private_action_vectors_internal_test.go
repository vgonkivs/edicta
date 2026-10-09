package verifier

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

// pathArchive serves records by their canonical paths, checking the key
// like a store does.
type pathArchive struct {
	Reader
	files map[string][]byte
}

func (a pathArchive) get(path string) (archive.Record, error) {
	return vecArchive{files: a.files}.get(path)
}

func (a pathArchive) PrivateBlob(_ context.Context, kind policy.PrivateKind, h commitment.Hash) (*archive.PrivateBlobRecord, error) {
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

func (a pathArchive) Reveal(_ context.Context, h commitment.Hash) (*archive.RevealRecord, error) {
	r, err := a.get(archive.HashPath(archive.KindReveal, h))
	if err != nil {
		return nil, err
	}
	return r.(*archive.RevealRecord), nil
}

// revealChecker is the checker of a profile; its ActionFromTx gives the
// vector's action of the executed transaction.
type revealChecker struct {
	public bool
	action []byte
}

func (revealChecker) CheckExecution(context.Context, ExecutionInput) (ExecutionFacts, error) {
	return ExecutionFacts{}, nil
}
func (c revealChecker) PublicExecution() bool { return c.public }
func (c revealChecker) ActionFromTx(context.Context, ExecutionInput) ([]byte, error) {
	return c.action, nil
}

// TestPrivateActionVectors runs the action cases of spec/vectors/v1/verify.json
// that need an auditor key, the kind 15 lookup or the reveal path.
func TestPrivateActionVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d struct {
		Records map[string]struct {
			CBORHex string `json:"record_cbor_hex"`
		} `json:"records"`
		Cases []struct {
			ID            string `json:"id"`
			Decision      string `json:"decision"`
			PrivateRecord string `json:"private_record"`
			AuditorKey    string `json:"auditor_key"`
			Reveal        string `json:"reveal"`
			Checker       *struct {
				Public bool   `json:"public_execution"`
				Action string `json:"tx_action_hex"`
			} `json:"checker"`
			Expect struct {
				Action struct {
					Status       string `json:"status"`
					Reason       string `json:"reason"`
					ActionSource string `json:"action_source"`
				} `json:"action"`
			} `json:"expect"`
		} `json:"action_cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	var keys struct {
		Keys map[string]struct {
			SK string `json:"sk_hex"`
		} `json:"auditor_keys"`
	}
	praw, err := os.ReadFile("../spec/vectors/policy/private.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(praw, &keys))

	ran := 0
	for _, c := range d.Cases {
		if c.Decision != "decision_private_fibre" {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			files := map[string][]byte{}
			add := func(name string) {
				b := unhex(t, d.Records[name].CBORHex)
				rec, err := archive.Decode(b)
				require.NoError(t, err)
				p, err := archive.KeyPath(rec)
				require.NoError(t, err)
				files[p] = b
			}
			add(c.Decision)
			if c.PrivateRecord != "" {
				add(c.PrivateRecord)
			}
			if c.Reveal != "" {
				add(c.Reveal)
			}
			dec, err := archive.Decode(unhex(t, d.Records[c.Decision].CBORHex))
			require.NoError(t, err)
			s, err := commitment.DecodeSigned(dec.(*archive.DecisionRecord).Envelope)
			require.NoError(t, err)
			h, err := commitment.HashOf(&s.Commitment)
			require.NoError(t, err)

			cfg := Config{Params: commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}}
			if c.AuditorKey != "" {
				cfg.AuditorKeys = append(cfg.AuditorKeys, auditorRecipientKey(t, keys.Keys[c.AuditorKey].SK))
			}
			if c.Reveal != "" {
				rv, err := archive.Decode(files[archive.HashPath(archive.KindReveal, h)])
				require.NoError(t, err)
				sr, _, err := commitment.DecodeSignedReceipt(rv.(*archive.RevealRecord).SignedReceipt)
				require.NoError(t, err)
				cfg.GateKeys = []ed25519.PublicKey{sr.Receipt.GatePubKey}
			}
			v := &Verifier{cfg: cfg, archive: pathArchive{files: files}}
			r := &run{v: v, h: h, ctx: t.Context()}
			require.True(t, r.envelope(dec.(*archive.DecisionRecord)))
			require.NoError(t, r.checkAction(dec.(*archive.DecisionRecord)))
			if c.Checker != nil {
				chk := revealChecker{public: c.Checker.Public}
				if c.Checker.Action != "" {
					chk.action, err = hex.DecodeString(c.Checker.Action)
					require.NoError(t, err)
				}
				require.NoError(t, r.reveal(chk))
			}
			got, ok := r.rep.Check(CheckAction)
			require.True(t, ok)
			assert.Equal(t, Status(c.Expect.Action.Status), got.Status, "%v", got.Err)
			assert.Equal(t, Reason(c.Expect.Action.Reason), got.Reason)
			assert.Equal(t, ActionSource(c.Expect.Action.ActionSource), r.rep.ActionSource)
			if got.Status == StatusPass {
				ah, err := commitment.ActionHash(s.Commitment.Action.Type, r.salt, r.action)
				require.NoError(t, err)
				assert.Equal(t, s.Commitment.Action.Hash, ah[:], "the bytes later checks use are the committed action")
			}
		})
	}
	assert.Equal(t, 7, ran)
}
