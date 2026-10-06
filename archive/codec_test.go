package archive_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
)

func TestVectorsEncodeByteExact(t *testing.T) {
	fx := archivefix.Load(t)
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			got, err := archive.Encode(c.Record)
			require.NoError(t, err)
			if c.CBOR != nil {
				require.Equal(t, hex.EncodeToString(c.CBOR), hex.EncodeToString(got))
				return
			}
			assert.Len(t, got, c.Size)
			sum := sha256.Sum256(got)
			assert.Equal(t, c.SHA256, hex.EncodeToString(sum[:]))
		})
	}
}

func TestVectorsDecodeRoundTrip(t *testing.T) {
	fx := archivefix.Load(t)
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			b := c.CBOR
			if b == nil {
				var err error
				b, err = archive.Encode(c.Record)
				require.NoError(t, err)
			}
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			assert.Equal(t, c.Record, rec)
			again, err := archive.Encode(rec)
			require.NoError(t, err)
			assert.Equal(t, b, again)
		})
	}
}

func TestVectorsKeyPath(t *testing.T) {
	fx := archivefix.Load(t)
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			got, err := archive.KeyPath(c.Record)
			require.NoError(t, err)
			assert.Equal(t, c.Key, got)
		})
	}
}

func TestVectorsRecordKind(t *testing.T) {
	fx := archivefix.Load(t)
	want := map[string]archive.Kind{
		"payload": archive.KindPayload, "evidence": archive.KindEvidence,
		"decision": archive.KindDecision, "authorization": archive.KindAuthorization,
		"rejection": archive.KindRejection,
	}
	for id, c := range fx.Cases {
		t.Run(id, func(t *testing.T) {
			assert.Equal(t, want[c.Kind], c.Record.Kind())
		})
	}
	assert.EqualValues(t, 1, archive.KindPayload)
	assert.EqualValues(t, 5, archive.KindRejection)
}

func TestVectorsReject(t *testing.T) {
	fx := archivefix.Load(t)
	require.NotEmpty(t, fx.Rejects)
	for _, r := range fx.Rejects {
		t.Run(r.ID, func(t *testing.T) {
			cause, ok := archivefix.Causes[r.Cause]
			require.True(t, ok, "unmapped cause %s", r.Cause)
			rec, err := archive.Decode(r.CBOR)
			require.Nil(t, rec)
			require.ErrorIs(t, err, archive.ErrCorrupt)
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestDecodeEmptyAndNil(t *testing.T) {
	for _, b := range [][]byte{nil, {}} {
		rec, err := archive.Decode(b)
		require.Nil(t, rec)
		require.ErrorIs(t, err, archive.ErrCorrupt)
	}
}

func TestDecodeDoesNotAliasInput(t *testing.T) {
	fx := archivefix.Load(t)
	in := append([]byte(nil), fx.Cases["payload_da2_minimal_lmt"].CBOR...)
	rec, err := archive.Decode(in)
	require.NoError(t, err)
	want := *rec.(*archive.PayloadRecord)
	want.Blob = append([]byte(nil), want.Blob...)
	for i := range in {
		in[i] = 0
	}
	assert.Equal(t, want.Blob, rec.(*archive.PayloadRecord).Blob)
}

func TestEncodeRefusesInvalidRecords(t *testing.T) {
	fx := archivefix.Load(t)
	payload := func() *archive.PayloadRecord {
		p := *fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
		return &p
	}
	fibre := func() *archive.PayloadRecord {
		p := *fx.Cases["payload_da1_live"].Record.(*archive.PayloadRecord)
		return &p
	}
	rejection := func() *archive.RejectionRecord {
		r := *fx.Cases["rejection_minimal_lmt_not_yet_valid"].Record.(*archive.RejectionRecord)
		return &r
	}
	cases := []struct {
		name string
		rec  archive.Record
	}{
		{"nil", nil},
		{"da3", func() archive.Record { p := payload(); p.DA = 3; return p }()},
		{"short commitment", func() archive.Record { p := payload(); p.Commitment = p.Commitment[:31]; return p }()},
		{"empty blob", func() archive.Record { p := payload(); p.Blob = nil; return p }()},
		{"zero intent", func() archive.Record { p := payload(); p.IntentHeight = 0; return p }()},
		{"da2 without signer", func() archive.Record { p := payload(); p.Signer = nil; return p }()},
		{"da1 with namespace", func() archive.Record { p := fibre(); p.Namespace = payload().Namespace; return p }()},
		{"operational marker name", func() archive.Record { r := rejection(); r.Error = "ErrChainUnavailable"; return r }()},
		{"marker name with package", func() archive.Record { r := rejection(); r.Error = "gate.ErrExpired"; return r }()},
		{"marker at zero", func() archive.Record { r := rejection(); r.RejectedAt = 0; return r }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := archive.Encode(c.rec)
			require.Error(t, err)
			assert.Nil(t, b)
		})
	}
}

func TestMaxRecordSize(t *testing.T) {
	assert.EqualValues(t, 1<<27+4096, archive.MaxRecordSize)
}

func TestSentinelsDistinct(t *testing.T) {
	require.NotErrorIs(t, archive.ErrNotFound, archive.ErrConflict)
	require.NotErrorIs(t, archive.ErrCorrupt, archive.ErrNotFound)
	require.NotErrorIs(t, archive.ErrCorrupt, commitment.ErrMalformed)
}
