package archive_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func TestParseKeyAcceptsEveryVectorKey(t *testing.T) {
	fx := archivefix.Load(t)
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			got, err := archive.ParseKey(c.Key)
			require.NoError(t, err)
			assert.Equal(t, c.Record.Kind(), got)

			canon, err := archive.KeyPath(c.Record)
			require.NoError(t, err)
			assert.Equal(t, canon, c.Key)
		})
	}
}

func TestParseKeyRefusesEverythingElse(t *testing.T) {
	const h = "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d"
	upper := strings.ToUpper(h)
	tests := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"slash only", "/"},
		{"leading slash", "/decision/" + h},
		{"trailing slash", "decision/" + h + "/"},
		{"empty segment", "decision//" + h},
		{"dot dot", "decision/../decision/" + h},
		{"dot dot first", "../decision/" + h},
		{"dot segment", "decision/./" + h},
		{"dot file", "decision/." + h[1:]},
		{"temp file", "decision/.tmp-" + h},
		{"upper-case hex", "decision/" + upper},
		{"short hash", "decision/" + h[:62]},
		{"long hash", "decision/" + h + "00"},
		{"non hex", "decision/" + strings.Repeat("zz", 32)},
		{"unknown kind", "secret/" + h},
		{"kind upper case", "Decision/" + h},
		{"directory of a kind", "payload"},
		{"directory of a kind with slash", "payload/"},
		{"directory of a da", "payload/2"},
		{"payload without da", "payload/" + h},
		{"payload da zero", "payload/0/" + h},
		{"payload da three", "payload/3/" + h},
		{"payload da leading zero", "payload/02/" + h},
		{"payload da plus", "payload/+2/" + h},
		{"payload da name", "payload/blob/" + h},
		{"evidence without da", "evidence/" + h},
		{"authorization with da", "authorization/2/" + h},
		{"decision with extra segment", "decision/" + h + "/x"},
		{"rejection without verdict", "rejection/" + h},
		{"rejection directory", "rejection/" + h + "/"},
		{"rejection unknown verdict", "rejection/" + h + "/ErrNothing"},
		{"rejection verdict lower case", "rejection/" + h + "/errnonceused"},
		{"rejection verdict with path", "rejection/" + h + "/../ErrNonceUsed"},
		{"query", "decision/" + h + "?x=1"},
		{"fragment", "decision/" + h + "#x"},
		{"percent escape", "decision/%32" + h[1:]},
		{"backslash", "decision\\" + h},
		{"nul", "decision/" + h[:10] + "\x00" + h[11:]},
		{"space", "decision/" + h + " "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := archive.ParseKey(tc.key)
			assert.Error(t, err, "%q", tc.key)
		})
	}
}

func TestParseKeyKnowsAllThirteenVerdicts(t *testing.T) {
	const h = "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d"
	verdicts := []string{
		"ErrActionMismatch", "ErrAnchorNotFound", "ErrAnchorTooOld", "ErrArchiveRecomputeUnsupported",
		"ErrDACommitmentMismatch", "ErrExpired", "ErrIssuedBeforeAnchor", "ErrNonceUsed", "ErrNotYetValid",
		"ErrPayloadHashMismatch", "ErrPayloadSizeMismatch", "ErrPayloadUnavailable", "ErrRetentionUnavailable",
	}
	for _, v := range verdicts {
		k, err := archive.ParseKey("rejection/" + h + "/" + v)
		require.NoError(t, err, v)
		assert.Equal(t, archive.KindRejection, k)
	}
}

func FuzzParseKey(f *testing.F) {
	fx := archivefix.Load(f)
	for _, c := range fx.Cases {
		f.Add(c.Key)
	}
	f.Add("")
	f.Add("../payload/2/00")
	f.Fuzz(func(t *testing.T, key string) {
		k, err := archive.ParseKey(key)
		if err != nil {
			return
		}
		assert.Contains(t, []archive.Kind{
			archive.KindPayload, archive.KindEvidence, archive.KindDecision, archive.KindAuthorization, archive.KindRejection,
		}, k)
		assert.True(t, strings.HasPrefix(key, k.String()+"/"), "%q", key)
		assert.NotContains(t, key, "..")
		assert.NotContains(t, key, "//")
		assert.False(t, strings.HasSuffix(key, "/"))
	})
}
