package railtx_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/secret"
)

const importPass = "import-passphrase"

func scalar(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func openRail(dir, name, pass string) (*railtx.Rail, error) {
	return railtx.New(railtx.Config{
		Consensus: nodefake.NewConsensus("mocha-4"), Reader: nodefake.NewChain(nil), GasLimit: 1,
		Key: railtx.KeyFromKeyring(dir, name, secret.New([]byte(pass))),
	})
}

func importInto(t *testing.T, dir, name, pass string, key byte) error {
	t.Helper()
	return railtx.ImportKeyring(dir, name, secret.New([]byte(pass)), secret.New(scalar(key)))
}

func TestImportKeyringWritesKeyhash(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kr")
	require.NoError(t, importInto(t, dir, "executor", importPass, 5))

	h, err := os.ReadFile(filepath.Join(dir, "keyring-file", "keyhash"))
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword(h, []byte(importPass)))
	assert.Error(t, bcrypt.CompareHashAndPassword(h, []byte("something-else")))

	cost, err := bcrypt.Cost(h)
	require.NoError(t, err)
	fx, err := os.ReadFile("testdata/file-keyring/keyring-file/keyhash")
	require.NoError(t, err)
	want, err := bcrypt.Cost(fx)
	require.NoError(t, err)
	assert.Equal(t, want, cost, "same cost as a keyhash written by the SDK file backend")
}

func TestImportKeyringReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kr")
	require.NoError(t, importInto(t, dir, "executor", importPass, 5))

	r, err := openRail(dir, "executor", importPass)
	require.NoError(t, err)
	d, err := r.Domain(bg)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(d.Sender, "celestia1"))

	_, err = openRail(dir, "executor", "wrong-passphrase")
	require.ErrorIs(t, err, node.ErrBadPassphrase)

	err = importInto(t, dir, "second", "wrong-passphrase", 6)
	require.Error(t, err)
	_, err = openRail(dir, "second", importPass)
	require.Error(t, err, "a refused import must not add the key")
}

func TestImportKeyringKeyhashOpensWithSDKFileBackend(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kr")
	require.NoError(t, importInto(t, dir, "executor", importPass, 5))

	reg := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(reg)
	in := strings.NewReader(strings.Repeat(importPass+"\n", 16))
	kr, err := keyring.New("celestia", keyring.BackendFile, dir, in, codec.NewProtoCodec(reg))
	require.NoError(t, err)
	k, err := kr.Key("executor")
	require.NoError(t, err)
	got, err := k.GetAddress()
	require.NoError(t, err)

	r, err := openRail(dir, "executor", importPass)
	require.NoError(t, err)
	d, err := r.Domain(bg)
	require.NoError(t, err)
	assert.Equal(t, d.Sender, got.String())
}

func TestImportKeyringNeverOverwritesKeyhash(t *testing.T) {
	dir := fixtureDir(t)
	path := filepath.Join(dir, "keyring-file", "keyhash")
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	require.NoError(t, importInto(t, dir, "second", fixturePass, 6))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)

	err = importInto(t, dir, "third", "wrong-passphrase", 7)
	require.Error(t, err)
	after, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a wrong passphrase must not replace the stored hash")

	_, err = openRail(dir, "executor", fixturePass)
	require.NoError(t, err, "the existing key still opens")
}
