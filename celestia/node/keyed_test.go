package node

import (
	"sync/atomic"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/api/client"
	nodefibre "github.com/celestiaorg/celestia-node/nodebuilder/fibre"
)

// The strict-mode submitters show the keyring key they sign with, so the
// daemon can tell it apart from a mandate principal of the same key; a key the
// keyring cannot show as secp256k1 leaves them address-only.
func TestSigningSubmittersShowTheKeyringKey(t *testing.T) {
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	rec, _, err := kr.NewMnemonic("k", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	want, err := rec.GetPubKey()
	require.NoError(t, err)
	_, err = kr.SaveOfflineKey("ed", ed25519.GenPrivKey().PubKey())
	require.NoError(t, err)

	var closes atomic.Int32
	installSigningSeams(t, func() (*client.Client, error) {
		c := fakeClient(t, true, &closes, nil)
		c.Fibre = struct{ nodefibre.Module }{}
		return c, nil
	})
	b, g := BridgeConfig{Addr: "http://bn.invalid:26658"}, GRPCConfig{Addr: "127.0.0.1:9090"}

	for name, tc := range map[string]struct {
		key  string
		want []byte
	}{
		"secp256k1 key": {"k", want.Bytes()},
		"ed25519 key":   {"ed", nil},
		"missing key":   {"absent", nil},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, sub, err := NewSigning(tctx(t), b, g, kr, tc.key, "mocha-4")
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			fc, _, fsub, err := NewFibreSigning(tctx(t), b, g, kr, tc.key, "mocha-4")
			require.NoError(t, err)
			t.Cleanup(func() { _ = fc.Close() })

			for _, s := range []any{sub, fsub} {
				pk, ok := s.(AnchorPublicKey)
				if tc.want == nil {
					assert.False(t, ok, "no key to show")
					continue
				}
				require.True(t, ok)
				got, err := pk.PublicKey(tctx(t))
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
