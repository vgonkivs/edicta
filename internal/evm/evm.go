// SPDX-License-Identifier: Apache-2.0

// Package evm holds the secp256k1 key primitives of EVM chains: the address
// of a key and a recoverable signature over a 32-byte digest.
package evm

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// ErrSignature: no signature could be made.
var ErrSignature = errors.New("evm: cannot sign")

// Keccak256 is the legacy Keccak-256 of the concatenated parts.
func Keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Address is the address of a public key: the last 20 bytes of the
// Keccak-256 of its uncompressed point.
func Address(pub *secp256k1.PublicKey) [20]byte {
	sum := Keccak256(pub.SerializeUncompressed()[1:])
	var a [20]byte
	copy(a[:], sum[12:])
	return a
}

// Sign signs digest with a deterministic (RFC 6979) low-s signature and
// returns r || s || y_parity, r and s big-endian in 32 bytes each and
// y_parity 0 or 1. Signing one digest twice gives one signature.
func Sign(priv *secp256k1.PrivateKey, digest [32]byte) ([65]byte, error) {
	if priv == nil {
		return [65]byte{}, fmt.Errorf("%w: no key", ErrSignature)
	}
	c := ecdsa.SignCompact(priv, digest[:], false)
	code := c[0] - 27
	if code > 1 {
		// r overflowed the group order: no y_parity can express it.
		return [65]byte{}, fmt.Errorf("%w: recovery code %d", ErrSignature, code)
	}
	var out [65]byte
	copy(out[:64], c[1:65])
	out[64] = code
	return out, nil
}
