package node

import (
	"context"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAnchorSignerRefusesAKeyThatIsNotSecp256k1(t *testing.T) {
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	_, err := kr.SaveOfflineKey("ed", ed25519.GenPrivKey().PubKey())
	require.NoError(t, err)
	ms := multisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{
		cosmossecp.GenPrivKey().PubKey(), cosmossecp.GenPrivKey().PubKey()})
	_, err = kr.SaveMultisig("multi", ms)
	require.NoError(t, err)

	for _, name := range []string{"ed", "multi"} {
		t.Run(name, func(t *testing.T) {
			s, err := NewAnchorSigner(kr, name, "devnet-1")
			require.ErrorIs(t, err, ErrUnsupported)
			assert.Nil(t, s)
		})
	}
}

func TestAnchorSignerPublicKeyIsTheCompressedKeyOfItsAddress(t *testing.T) {
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	rec, _, err := kr.NewMnemonic("anchor", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	s, err := NewAnchorSigner(kr, "anchor", "devnet-1")
	require.NoError(t, err)
	pk, ok := s.(AnchorPublicKey)
	require.True(t, ok, "the keyring signer shows its public key")

	pub, err := pk.PublicKey(context.Background())
	require.NoError(t, err)
	want, err := rec.GetPubKey()
	require.NoError(t, err)
	require.Len(t, pub, 33)
	assert.Equal(t, want.Bytes(), pub)

	addr, err := s.Address(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []byte((&cosmossecp.PubKey{Key: pub}).Address()), addr, "hash160 of the key is the signing account")

	pub[0] ^= 0xff
	again, err := pk.PublicKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, want.Bytes(), again, "the caller gets a copy")
}
