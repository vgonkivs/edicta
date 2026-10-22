// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/sdk/blob"
)

func TestApplyFlagsWarnsOnlyWhenOverridingTheMandate(t *testing.T) {
	var fileRef [32]byte
	fileRef[0] = 0xaa
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	aud := blob.Recipient{KID: policy.AuditorKid(k.PublicKey().Bytes()), PublicKey: k.PublicKey()}
	k2, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	other := hex.EncodeToString(k2.PublicKey().Bytes())

	var w bytes.Buffer
	ref, rec, err := applyFlags(commonOpts{mandateRef: hex.EncodeToString(fileRef[:])}, fileRef, []blob.Recipient{aud}, true, &w)
	require.NoError(t, err)
	assert.Equal(t, fileRef, ref)
	assert.Len(t, rec, 1)
	assert.Empty(t, w.String(), "the same value is silent")

	w.Reset()
	ref, _, err = applyFlags(commonOpts{mandateRef: strings.Repeat("bb", 32)}, fileRef, []blob.Recipient{aud}, true, &w)
	require.NoError(t, err)
	assert.Equal(t, byte(0xbb), ref[0])
	assert.Contains(t, w.String(), "WARNING: --mandate-ref bbbbbbbbbbbb overrides")
	assert.Contains(t, w.String(), "aa0000000000")

	w.Reset()
	_, rec, err = applyFlags(commonOpts{recipients: stringList{hex.EncodeToString(k.PublicKey().Bytes())}}, fileRef, []blob.Recipient{aud}, true, &w)
	require.NoError(t, err)
	assert.Len(t, rec, 1)
	assert.Empty(t, w.String(), "an auditor already in the mandate is silent")

	w.Reset()
	_, rec, err = applyFlags(commonOpts{recipients: stringList{other}}, fileRef, []blob.Recipient{aud}, true, &w)
	require.NoError(t, err)
	assert.Len(t, rec, 2)
	assert.Contains(t, w.String(), "WARNING: --recipient")

	w.Reset()
	_, _, err = applyFlags(commonOpts{mandateRef: strings.Repeat("bb", 32), recipients: stringList{other}}, [32]byte{}, nil, false, &w)
	require.NoError(t, err)
	assert.Empty(t, w.String(), "no mandate file, nothing to differ from")
}
