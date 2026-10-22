// SPDX-License-Identifier: Apache-2.0

package edictaapi_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/engine/commitment"
)

func TestWrapperCodecFollowsTheCoreRules(t *testing.T) {
	s := edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "blob", Kind: edictaapi.KindBytes, Min: 1, Required: true},
		edictaapi.Field{Key: 2, Name: "name", Kind: edictaapi.KindText, Max: 4},
		edictaapi.Field{Key: 3, Name: "n", Kind: edictaapi.KindUint},
	)
	enc := edictaapi.EncodeWrapper(edictaapi.BytesItem(1, []byte{1, 2}), edictaapi.TextItem(2, "ab"), edictaapi.UintItem(3, 7))
	f, err := edictaapi.DecodeWrapper(enc, s)
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2}, f.Bytes(1))
	assert.Equal(t, "ab", f.Text(2))
	n, ok := f.Uint(3)
	assert.True(t, ok)
	assert.Equal(t, uint64(7), n)

	js, err := edictaapi.WrapperToJSON(enc, s)
	require.NoError(t, err)
	assert.JSONEq(t, `{"blob":"AQI=","name":"ab","n":7}`, string(js))
	back, err := edictaapi.JSONToWrapper(js, s)
	require.NoError(t, err)
	assert.Equal(t, enc, back)

	_, err = edictaapi.DecodeWrapper(edictaapi.EncodeWrapper(edictaapi.TextItem(2, "abcde")), s)
	require.ErrorIs(t, err, commitment.ErrFieldSize)
	_, err = edictaapi.DecodeWrapper(edictaapi.EncodeWrapper(edictaapi.TextItem(2, "ab")), s)
	require.ErrorIs(t, err, commitment.ErrMissingField)
	_, err = edictaapi.DecodeWrapper(edictaapi.EncodeWrapper(edictaapi.UintItem(9, 1)), s)
	require.ErrorIs(t, err, commitment.ErrUnknownKey)
	_, err = edictaapi.JSONToWrapper([]byte(`{"blob":"AQI=","blob":"AQI="}`), s)
	require.ErrorIs(t, err, commitment.ErrMalformed)

	body, err := edictaapi.WrapperToJSON(edictaapi.ErrorBody("x.ErrY", "no", true), edictaapi.ErrorSchema)
	require.NoError(t, err)
	assert.JSONEq(t, `{"code":"x.ErrY","message":"no","retryable":1}`, string(body))
}
