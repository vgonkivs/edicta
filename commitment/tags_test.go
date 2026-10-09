package commitment_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

// Every domain tag is written with a one-byte length, so it must be 1..255
// bytes, and no two tags may be equal.
func TestTagConstants(t *testing.T) {
	tags := map[string]string{
		"TagCommitment":       commitment.TagCommitment,
		"TagSig":              commitment.TagSig,
		"TagReceipt":          commitment.TagReceipt,
		"TagReceiptSig":       commitment.TagReceiptSig,
		"TagAction":           commitment.TagAction,
		"TagAuthorization":    commitment.TagAuthorization,
		"TagAuthorizationSig": commitment.TagAuthorizationSig,
	}
	seen := map[string]string{}
	for name, v := range tags {
		assert.GreaterOrEqualf(t, len(v), 1, "%s has %d bytes", name, len(v))
		assert.LessOrEqualf(t, len(v), 255, "%s has %d bytes", name, len(v))
		assert.Truef(t, strings.HasPrefix(v, "edicta/v1/"), "%s = %q", name, v)
		other, dup := seen[v]
		assert.Falsef(t, dup, "%s and %s are equal", name, other)
		seen[v] = name
	}
	require.Equalf(t, "edicta/v1/receipt-sig", commitment.TagReceiptSig, "TagReceiptSig = %q", commitment.TagReceiptSig)
}

// Signed messages of the three signing roles differ in length and in tag, so
// a signature made for one role cannot be replayed as another.
func TestSignedMessageLengths(t *testing.T) {
	var h commitment.Hash
	agent := commitment.SigningMessage(h)
	receipt := commitment.ReceiptSigningMessage(h)
	auth := commitment.AuthorizationSigningMessage(h)
	assert.Len(t, agent, 46)
	assert.Len(t, receipt, 54)
	assert.Len(t, auth, 60)
	assert.EqualValues(t, 0x1b, auth[0])
	assert.Equal(t, "edicta/v1/authorization-sig", string(auth[1:28]))
}

func TestCheckPublicKeyExported(t *testing.T) {
	for _, name := range []string{"agent1", "agent2", "gate1"} {
		err := commitment.CheckPublicKey([]byte(loadKey(t, name).Public().(ed25519.PublicKey)))
		assert.NoErrorf(t, err, "%s", name)
	}
	for _, bk := range badPublicKeys {
		err := commitment.CheckPublicKey(mustHex(t, bk.hex))
		if assert.Errorf(t, err, "%s accepted", bk.name) {
			assertSentinel(t, err, "ErrInvalidPublicKey")
		}
	}
	for _, k := range map[string][]byte{"nil": nil, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33)} {
		assertSentinel(t, commitment.CheckPublicKey(k), "ErrInvalidPublicKey")
	}
}
