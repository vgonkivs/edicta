// Command edicta-principal is the principal's tool for mandates: it renders
// a mandate, prints what a wallet signs, signs with a raw key or attaches a
// wallet signature, verifies, and publishes the signed mandate to an archive.
//
//	edicta-principal render     --mandate FILE
//	edicta-principal typed-data --mandate FILE
//	edicta-principal signdoc    --mandate FILE
//	edicta-principal sign       --mandate FILE --scheme ed25519|cosmos|eth (--key FILE | --signature SIG) [--out FILE]
//	edicta-principal verify     --signed FILE
//	edicta-principal publish    --signed FILE --archive DIR
//
// A mandate file holds a canonical Mandate or SignedMandate, as binary CBOR or
// hex text. A key file holds the 32-byte Ed25519 seed or secp256k1 scalar in
// hex. SIG is hex (0x optional) or standard base64, as wallets return it.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
)

const usage = `usage:
  edicta-principal render     --mandate FILE
  edicta-principal typed-data --mandate FILE
  edicta-principal signdoc    --mandate FILE
  edicta-principal sign       --mandate FILE --scheme ed25519|cosmos|eth (--key FILE | --signature SIG) [--out FILE]
  edicta-principal verify     --signed FILE
  edicta-principal publish    --signed FILE --archive DIR`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type usageError struct{ error }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usage)
		return exitUsage
	}
	err := dispatch(args[0], args[1:], out)
	var ue usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &ue):
		fmt.Fprintf(errOut, "edicta-principal: %v\n%s\n", err, usage)
		return exitUsage
	default:
		fmt.Fprintf(errOut, "edicta-principal: %v\n", err)
		return exitInvalid
	}
}

type opts struct {
	mandate, signed, scheme, key, signature, out, archive string
}

func parse(name string, args []string, need ...string) (opts, error) {
	var o opts
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.mandate, "mandate", "", "mandate or signed mandate file")
	fs.StringVar(&o.signed, "signed", "", "signed mandate file")
	fs.StringVar(&o.scheme, "scheme", "", "ed25519, cosmos or eth")
	fs.StringVar(&o.key, "key", "", "raw private key file, hex")
	fs.StringVar(&o.signature, "signature", "", "wallet signature, hex or base64")
	fs.StringVar(&o.out, "out", "", "output file for the signed mandate")
	fs.StringVar(&o.archive, "archive", "", "archive directory")
	if err := fs.Parse(args); err != nil {
		return o, usageError{err}
	}
	if fs.NArg() > 0 {
		return o, usageError{fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	set := map[string]string{"mandate": o.mandate, "signed": o.signed, "scheme": o.scheme, "archive": o.archive}
	for _, n := range need {
		if set[n] == "" {
			return o, usageError{fmt.Errorf("%s needs --%s", name, n)}
		}
	}
	return o, nil
}

func dispatch(cmd string, args []string, out io.Writer) error {
	switch cmd {
	case "render", "typed-data", "signdoc":
		o, err := parse(cmd, args, "mandate")
		if err != nil {
			return err
		}
		m, h, err := readMandate(o.mandate)
		if err != nil {
			return err
		}
		return show(cmd, m, h, out)
	case "sign":
		o, err := parse(cmd, args, "mandate", "scheme")
		if err != nil {
			return err
		}
		return sign(o, out)
	case "verify":
		o, err := parse(cmd, args, "signed")
		if err != nil {
			return err
		}
		sm, h, err := readSigned(o.signed)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "valid\nmandate hash: %s\n%s\n", hex.EncodeToString(h[:]), principalLineOf(&sm.Mandate))
		return nil
	case "publish":
		o, err := parse(cmd, args, "signed", "archive")
		if err != nil {
			return err
		}
		return publish(o, out)
	}
	return usageError{fmt.Errorf("unknown command %q", cmd)}
}

func show(cmd string, m *policy.Mandate, h commitment.Hash, out io.Writer) error {
	switch cmd {
	case "render":
		_, err := io.WriteString(out, policy.Render(m))
		return err
	case "typed-data":
		if m.SigType != policy.SigTypeEIP712 {
			return usageError{errors.New("typed-data needs a mandate with sig_type 3 (eip-712)")}
		}
		b, err := principalsig.EIP712TypedDataJSON(policy.SignedFields(m, h))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", b)
		return err
	default:
		if m.SigType != policy.SigTypeADR036 {
			return usageError{errors.New("signdoc needs a mandate with sig_type 2 (adr-036)")}
		}
		doc, err := principalsig.ADR036SignDoc(m.Principal, m.PrincipalHRP, policy.SignedText(m, h))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "%s\n", doc)
		return err
	}
}

func principalLineOf(m *policy.Mandate) string {
	for _, l := range strings.Split(policy.Render(m), "\n") {
		if strings.HasPrefix(l, "principal: ") {
			return l
		}
	}
	return ""
}

var schemes = map[string]principalsig.Scheme{
	"ed25519": principalsig.Ed25519, "cosmos": principalsig.CosmosADR036, "eth": principalsig.EIP712,
}

func sign(o opts, out io.Writer) error {
	scheme, ok := schemes[o.scheme]
	if !ok {
		return usageError{fmt.Errorf("unknown scheme %q", o.scheme)}
	}
	if (o.key == "") == (o.signature == "") {
		return usageError{errors.New("sign needs exactly one of --key and --signature")}
	}
	m, h, err := readMandate(o.mandate)
	if err != nil {
		return err
	}
	ms, err := m.Scheme()
	if err != nil {
		return err
	}
	if ms != scheme {
		return usageError{fmt.Errorf("the mandate names scheme %s, not %s", ms, scheme)}
	}
	var signed []byte
	if o.key != "" {
		signed, err = signWithKey(scheme, o.key, m)
	} else {
		signed, err = attach(o.signature, m)
	}
	if err != nil {
		return err
	}
	if _, h2, err := policy.VerifyMandate(signed); err != nil {
		return err
	} else if h2 != h {
		return errors.New("the signed mandate hashes differently")
	}
	if o.out == "" {
		_, err = fmt.Fprintf(out, "%s\n", hex.EncodeToString(signed))
		return err
	}
	if err := os.WriteFile(o.out, signed, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signed mandate %s written to %s\n", hex.EncodeToString(h[:]), o.out)
	return err
}

func signWithKey(scheme principalsig.Scheme, path string, m *policy.Mandate) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sk, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil || len(sk) != 32 {
		return nil, usageError{errors.New("the key file must hold 32 bytes in hex")}
	}
	var s principalsig.Signer
	if scheme == principalsig.Ed25519 {
		s = principalsig.NewEd25519Signer(ed25519.NewKeyFromSeed(sk))
	} else if s, err = principalsig.NewSecp256k1Signer(scheme, sk, m.PrincipalHRP); err != nil {
		return nil, err
	}
	b, _, err := policy.SignMandateWith(s, m)
	return b, err
}

func attach(sig string, m *policy.Mandate) ([]byte, error) {
	sig = strings.TrimSpace(sig)
	b, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
	if err != nil {
		if b, err = base64.StdEncoding.DecodeString(sig); err != nil {
			return nil, usageError{errors.New("--signature is neither hex nor base64")}
		}
	}
	return policy.EncodeSignedMandate(&policy.SignedMandate{Mandate: *m, Signature: b})
}

func publish(o opts, out io.Writer) error {
	b, err := readFile(o.signed)
	if err != nil {
		return err
	}
	_, h, err := policy.VerifyMandate(b)
	if err != nil {
		return err
	}
	st, err := fsarchive.Open(o.archive, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := st.Put(ctx, &archive.MandateRecord{SignedMandate: b})
	if err != nil {
		return err
	}
	what := "written"
	if res == archive.Unchanged {
		what = "already present"
	}
	_, err = fmt.Fprintf(out, "mandate %s: %s\n", hex.EncodeToString(h[:]), what)
	return err
}

// readFile returns the file's bytes, decoding hex text when the whole file
// is hex.
func readFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if b, err := hex.DecodeString(string(bytes.TrimSpace(raw))); err == nil && len(b) > 0 {
		return b, nil
	}
	return raw, nil
}

func readMandate(path string) (*policy.Mandate, commitment.Hash, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, commitment.Hash{}, err
	}
	if sm, h, err := policy.DecodeSignedMandate(b); err == nil {
		return &sm.Mandate, h, nil
	}
	return policy.DecodeMandate(b)
}

func readSigned(path string) (*policy.SignedMandate, commitment.Hash, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, commitment.Hash{}, err
	}
	return policy.VerifyMandate(b)
}
