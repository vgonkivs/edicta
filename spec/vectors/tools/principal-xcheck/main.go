// Command principal-xcheck confirms spec/vectors/principal/{adr036,eip712}.json with
// go-ethereum (EIP-712 typed-data hashing, RFC 6979 signing, recovery) and
// dcrd secp256k1 (Cosmos ADR-036 signing and verification), independently of
// the Python generator. Run from the repository root:
//
//	go run ./spec/vectors/tools/principal-xcheck   (inside this module: cd here, go run . ../../..)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cosmos/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Cosmos addresses are RIPEMD-160 by definition
)

type file struct {
	Keys map[string]struct {
		Seed string `json:"seed_hex"`
	} `json:"keys"`
	Case   json.RawMessage `json:"case"`
	Reject []struct {
		ID     string `json:"id"`
		Signed string `json:"signed_mandate_hex"`
		Doc    string `json:"signed_signdoc"`
		Want   string `json:"expect_error"`
	} `json:"reject"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func check(ok bool, msg string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL:", msg)
		os.Exit(1)
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func load(root, name string) file {
	b, err := os.ReadFile(filepath.Join(root, "spec/vectors/principal", name))
	must(err)
	var f file
	must(json.Unmarshal(b, &f))
	return f
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	e := load(root, "eip712.json")
	var ec struct {
		Address   string             `json:"address"`
		Typed     apitypes.TypedData `json:"typed_data"`
		Domain    string             `json:"domain_separator_hex"`
		Digest    string             `json:"digest_hex"`
		Signature string             `json:"signature_hex"`
	}
	must(json.Unmarshal(e.Case, &ec))
	digest, _, err := apitypes.TypedDataAndHash(ec.Typed)
	must(err)
	check(hex.EncodeToString(digest) == ec.Digest, "eip712: go-ethereum TypedDataAndHash differs from digest_hex")
	dom, err := ec.Typed.HashStruct("EIP712Domain", ec.Typed.Domain.Map())
	must(err)
	check(hex.EncodeToString(dom) == ec.Domain, "eip712: domain separator")
	priv, err := crypto.ToECDSA(unhex(e.Keys["p1_secp"].Seed))
	must(err)
	sig, err := crypto.Sign(digest, priv)
	must(err)
	sig[64] += 27
	check(hex.EncodeToString(sig) == ec.Signature, "eip712: go-ethereum RFC 6979 signature differs")
	pub, err := crypto.SigToPub(digest, append(append([]byte{}, sig[:64]...), sig[64]-27))
	must(err)
	check("0x"+hex.EncodeToString(crypto.PubkeyToAddress(*pub).Bytes()) == ec.Address, "eip712: recovered address")

	a := load(root, "adr036.json")
	var ac struct {
		Principal string `json:"principal_hex"`
		HRP       string `json:"hrp"`
		Address   string `json:"address"`
		Signdoc   string `json:"signdoc"`
		Digest    string `json:"digest_hex"`
		Signature string `json:"signature_hex"`
	}
	must(json.Unmarshal(a.Case, &ac))
	sk := secp256k1.PrivKeyFromBytes(unhex(a.Keys["p1_secp"].Seed))
	check(bytes.Equal(sk.PubKey().SerializeCompressed(), unhex(ac.Principal)), "adr036: compressed key")
	sh := sha256.Sum256(unhex(ac.Principal))
	r := ripemd160.New()
	r.Write(sh[:])
	conv, err := bech32.ConvertBits(r.Sum(nil), 8, 5, true)
	must(err)
	addr, err := bech32.Encode(ac.HRP, conv)
	must(err)
	check(addr == ac.Address, "adr036: bech32 address")
	h := sha256.Sum256([]byte(ac.Signdoc))
	check(hex.EncodeToString(h[:]) == ac.Digest, "adr036: digest")
	ds := decdsa.Sign(sk, h[:])
	rb, sb := ds.R(), ds.S()
	var out [64]byte
	rb.PutBytesUnchecked(out[:32])
	sb.PutBytesUnchecked(out[32:])
	check(hex.EncodeToString(out[:]) == ac.Signature, "adr036: dcrd RFC 6979 signature differs")
	for _, rj := range a.Reject {
		if rj.Doc == "" {
			continue
		}
		raw := unhex(rj.Signed)
		var rr, ss secp256k1.ModNScalar
		rr.SetByteSlice(raw[len(raw)-64 : len(raw)-32])
		ss.SetByteSlice(raw[len(raw)-32:])
		dh := sha256.Sum256([]byte(rj.Doc))
		check(decdsa.NewSignature(&rr, &ss).Verify(dh[:], sk.PubKey()), rj.ID+": not a valid wallet signature over its own document")
		check(!decdsa.NewSignature(&rr, &ss).Verify(h[:], sk.PubKey()), rj.ID+": verifies over the re-rendered document")
	}
	fmt.Println("OK (principal xcheck): EIP-712 digest, domain, RFC 6979 signature and recovery (go-ethereum); ADR-036 address, digest, RFC 6979 signature and reject signatures (dcrd)")
}
