// SPDX-License-Identifier: Apache-2.0

// Package evm holds the secp256k1 key primitives of EVM chains: the address
// of a key, its EIP-55 form, the personal_sign digest, and a recoverable
// signature over a 32-byte digest.
package evm

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrSignature: no signature could be made.
	ErrSignature = errors.New("evm: cannot sign")
	// ErrRecover: the signature carries no recovery id RecoverAddress
	// accepts.
	ErrRecover = errors.New("evm: cannot recover")
)

// personalPrefix is the EIP-191 version 0x45 prefix of a 32-byte message.
const personalPrefix = "\x19Ethereum Signed Message:\n" + "32"

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

// ChecksumAddress is the EIP-55 form of addr: 40 hex digits without "0x",
// a letter upper-cased when the matching nibble of the Keccak-256 of the
// lower-case digits is 8 or more.
func ChecksumAddress(addr [20]byte) string {
	out := []byte(hex.EncodeToString(addr[:]))
	h := Keccak256(out)
	for i, c := range out {
		nibble := h[i/2] >> 4
		if i%2 == 1 {
			nibble = h[i/2] & 0x0f
		}
		if c >= 'a' && c <= 'f' && nibble >= 8 {
			out[i] = c - 'a' + 'A'
		}
	}
	return string(out)
}

// PersonalDigest32 is the personal_sign (EIP-191 version 0x45) digest of a
// 32-byte message: Keccak-256(0x19 || "Ethereum Signed Message:\n32" || m).
func PersonalDigest32(m [32]byte) [32]byte {
	return Keccak256([]byte(personalPrefix), m[:])
}

// RecoverAddress returns the address whose key made sig over digest. sig is
// r || s || y_parity, the layout Sign returns, with y_parity 0 or 1; a v of
// 27 or 28 must be mapped to 0 or 1 by the caller. r and s must lie in
// 1..n-1; whether a high s is acceptable is the caller's rule. A failed
// recovery returns the secp256k1 library's error unwrapped, so callers that
// wrap it keep their error texts.
func RecoverAddress(digest [32]byte, sig [65]byte) ([20]byte, error) {
	if sig[64] > 1 {
		// 2 and 3 are the overflowed-r recovery ids, which no signature
		// from Sign carries.
		return [20]byte{}, fmt.Errorf("%w: y_parity %d", ErrRecover, sig[64])
	}
	var compact [65]byte
	compact[0] = 27 + sig[64]
	copy(compact[1:], sig[:64])
	pub, _, err := ecdsa.RecoverCompact(compact[:], digest[:])
	if err != nil {
		return [20]byte{}, err
	}
	return Address(pub), nil
}
