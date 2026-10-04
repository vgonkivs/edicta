package node

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
)

func makeKey(t *testing.T, dir, backend, name, pass string) {
	t.Helper()
	var in = eofReader{}
	var r interface{ Read([]byte) (int, error) } = in
	if backend == keyring.BackendFile {
		r = &repeatReader{line: []byte(pass + "\n")}
	}
	kr, err := keyring.New(app.Name, backend, dir, r, encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	require.NoError(t, err)
	_, _, err = kr.NewMnemonic(name, keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
}

func TestOpenKeyringRefusals(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]KeyringConfig{
		"no dir":              {Name: "k", Backend: "file", Passphrase: []byte("p")},
		"no name":             {Dir: dir, Backend: "file", Passphrase: []byte("p")},
		"file no passphrase":  {Dir: dir, Name: "k", Backend: "file"},
		"test without flag":   {Dir: dir, Name: "k", Backend: "test"},
		"unknown backend":     {Dir: dir, Name: "k", Backend: "os"},
		"missing key in file": {Dir: dir, Name: "k", Backend: "file", Passphrase: []byte("p")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := OpenKeyring(c)
			require.ErrorIs(t, err, ErrKeyring)
		})
	}
}

func TestOpenKeyringTestBackendWarnsAndFileWorks(t *testing.T) {
	dir := t.TempDir()
	makeKey(t, dir, keyring.BackendTest, "recorder", "")
	var buf bytes.Buffer
	kr, err := OpenKeyring(KeyringConfig{Dir: dir, Name: "recorder", Backend: "test", AllowTest: true,
		Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	require.NoError(t, err)
	_, err = kr.Key("recorder")
	require.NoError(t, err)
	require.Contains(t, buf.String(), "development only")

	fdir := t.TempDir()
	makeKey(t, fdir, keyring.BackendFile, "executor", "hunter2-long")
	kr, err = OpenKeyring(KeyringConfig{Dir: fdir, Name: "executor", Backend: "file", Passphrase: []byte("hunter2-long")})
	require.NoError(t, err)
	_, err = kr.Key("executor")
	require.NoError(t, err)
	// Separate keyrings: the recorder key is not in the executor's.
	_, err = OpenKeyring(KeyringConfig{Dir: fdir, Name: "recorder", Backend: "file", Passphrase: []byte("hunter2-long")})
	require.ErrorIs(t, err, ErrKeyring)
	require.False(t, strings.Contains(err.Error(), "hunter2-long"), "passphrase must not leak into errors")
}
