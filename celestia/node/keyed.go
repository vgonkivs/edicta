package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

// AnchorKeyUnavailable is shown by a keyring submitter that cannot show its
// public key, so a caller that must refuse it can name the cause.
type AnchorKeyUnavailable interface {
	PublicKeyUnavailable() error
}

// keyringPublicKey is the compressed secp256k1 key of keyName. A submitter
// without it is still usable; only a caller that must tell its key apart from
// another role's key has to refuse it.
func keyringPublicKey(kr keyring.Keyring, keyName string) ([]byte, error) {
	if kr == nil || keyName == "" {
		return nil, errors.New("node: no keyring key to read the public key from")
	}
	rec, err := kr.Key(keyName)
	if err != nil {
		return nil, fmt.Errorf("node: keyring key %q: %w", keyName, err)
	}
	pk, err := rec.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("node: keyring key %q public key: %w", keyName, err)
	}
	if _, ok := pk.(*cosmossecp.PubKey); !ok || len(pk.Bytes()) != 33 {
		return nil, fmt.Errorf("node: keyring key %q is not a compressed secp256k1 key", keyName)
	}
	return bytes.Clone(pk.Bytes()), nil
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

type unkeyedSubmitter struct {
	Submitter
	cause error
}

func (u unkeyedSubmitter) PublicKeyUnavailable() error { return u.cause }

type unkeyedFibreSubmitter struct {
	FibreSubmitter
	cause error
}

func (u unkeyedFibreSubmitter) PublicKeyUnavailable() error { return u.cause }

func withSubmitterKey(s Submitter, pub []byte, err error) Submitter {
	if err != nil {
		return unkeyedSubmitter{Submitter: s, cause: err}
	}
	return keyedSubmitter{Submitter: s, pub: pub}
}

func withFibreSubmitterKey(s FibreSubmitter, pub []byte, err error) FibreSubmitter {
	if err != nil {
		return unkeyedFibreSubmitter{FibreSubmitter: s, cause: err}
	}
	return keyedFibreSubmitter{FibreSubmitter: s, pub: pub}
}
