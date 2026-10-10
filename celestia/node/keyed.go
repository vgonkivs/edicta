package node

import (
	"bytes"
	"context"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

// keyringPublicKey is the compressed secp256k1 key of keyName, or nil when kr
// cannot show one. A submitter without it is still usable; only a caller that
// must tell its key apart from another role's key has to refuse it.
func keyringPublicKey(kr keyring.Keyring, keyName string) []byte {
	if kr == nil || keyName == "" {
		return nil
	}
	rec, err := kr.Key(keyName)
	if err != nil {
		return nil
	}
	pk, err := rec.GetPubKey()
	if err != nil {
		return nil
	}
	if _, ok := pk.(*cosmossecp.PubKey); !ok || len(pk.Bytes()) != 33 {
		return nil
	}
	return bytes.Clone(pk.Bytes())
}

type keyedSubmitter struct {
	Submitter
	pub []byte
}

func (k keyedSubmitter) PublicKey(context.Context) ([]byte, error) { return bytes.Clone(k.pub), nil }

type keyedFibreSubmitter struct {
	FibreSubmitter
	pub []byte
}

func (k keyedFibreSubmitter) PublicKey(context.Context) ([]byte, error) {
	return bytes.Clone(k.pub), nil
}

func withSubmitterKey(s Submitter, pub []byte) Submitter {
	if pub == nil {
		return s
	}
	return keyedSubmitter{Submitter: s, pub: pub}
}

func withFibreSubmitterKey(s FibreSubmitter, pub []byte) FibreSubmitter {
	if pub == nil {
		return s
	}
	return keyedFibreSubmitter{FibreSubmitter: s, pub: pub}
}
