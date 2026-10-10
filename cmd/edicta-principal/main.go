// Command edicta-principal is the principal's tool for mandates: it renders
// a mandate, prints what a wallet signs, signs with a raw key or attaches a
// wallet signature, verifies, and publishes the signed mandate to an archive.
//
//	edicta-principal render     --mandate FILE [--book FILE] [--accept-new-key]
//	edicta-principal typed-data --mandate FILE
//	edicta-principal signdoc    --mandate FILE [--text]
//	edicta-principal private    --mandate FILE --auditor LABEL:PUBKEY... [--new-id] [--out FILE]
//	edicta-principal sign       --mandate FILE --scheme ed25519|cosmos|eth (--key FILE | --signature SIG)
//	                            [--replaces FILE] [--book FILE] [--accept-new-key] [--out FILE]
//	edicta-principal verify     --signed FILE
//	edicta-principal publish    --signed FILE --archive DIR
//
// A mandate file holds a canonical Mandate or SignedMandate, as binary CBOR or
// hex text. A key file holds the 32-byte Ed25519 seed or secp256k1 scalar in
// hex. SIG is hex (0x optional) or standard base64, as wallets return it.
//
// signdoc prints the amino JSON sign document of an ADR-036 mandate; with
// --text it prints only the data D inside it, the rendered mandate ending in
// the mandate hash line, as UTF-8 with no newline after the hash. D is the
// exact text the wallet signs: paste it unchanged as the data argument of
// Keplr signArbitrary.
//
// private makes a mandate private: it sets the auditors from LABEL:PUBKEY
// (an X25519 key in hex; the kid is derived, never typed) and draws the
// counter's state salt, and with --new-id or an all-zero mandate_id a fresh
// mandate_id, all from crypto/rand. The address book (--book, JSON label to
// key) remembers each auditor label's key: render and sign refuse, with a
// warning, a known label that now maps to another key unless
// --accept-new-key is given, and sign adds new labels after it succeeds.
// sign warns when the counters restart at zero: a mandate_id that no
// --replaces version carries, or a switch between public and private mode.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
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
  edicta-principal render     --mandate FILE [--book FILE] [--accept-new-key]
  edicta-principal typed-data --mandate FILE
  edicta-principal signdoc    --mandate FILE [--text]
  edicta-principal private    --mandate FILE --auditor LABEL:PUBKEY... [--new-id] [--out FILE]
  edicta-principal sign       --mandate FILE --scheme ed25519|cosmos|eth (--key FILE | --signature SIG)
                              [--replaces FILE] [--book FILE] [--accept-new-key] [--out FILE]
  edicta-principal verify     --signed FILE
  edicta-principal publish    --signed FILE --archive DIR

signdoc --text prints the data D of the ADR-036 document: the rendered
mandate, an empty line and "mandate hash: <hex>", with no newline after the
hash. D is the exact data the principal signs. Paste it unchanged, without
adding a newline, as the data argument of Keplr signArbitrary(chainId,
address, data), then pass the returned signature to sign --scheme cosmos
--signature.`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type usageError struct{ error }

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usage)
		return exitUsage
	}
	err := dispatch(args[0], args[1:], out, errOut)
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
	mandate, signed, scheme, key, signature, out, archive, book, replaces string
	acceptNewKey, newID, text                                             bool
	auditors                                                              multi
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

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
	fs.StringVar(&o.book, "book", "", "auditor address book, JSON label to X25519 key hex")
	fs.StringVar(&o.replaces, "replaces", "", "signed mandate this version replaces")
	fs.BoolVar(&o.acceptNewKey, "accept-new-key", false, "accept a known auditor label with another key")
	fs.BoolVar(&o.newID, "new-id", false, "draw a fresh mandate_id")
	fs.BoolVar(&o.text, "text", false, "signdoc: print only the signed data D")
	fs.Var(&o.auditors, "auditor", "auditor as LABEL:PUBKEY, repeatable")
	if err := fs.Parse(args); err != nil {
		return o, usageError{err}
	}
	if fs.NArg() > 0 {
		return o, usageError{fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	if o.text && name != "signdoc" {
		return o, usageError{errors.New("--text applies only to signdoc")}
	}
	set := map[string]string{"mandate": o.mandate, "signed": o.signed, "scheme": o.scheme, "archive": o.archive}
	for _, n := range need {
		if set[n] == "" {
			return o, usageError{fmt.Errorf("%s needs --%s", name, n)}
		}
	}
	return o, nil
}

func dispatch(cmd string, args []string, out, errOut io.Writer) error {
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
		if err := show(cmd, m, h, o.text, out); err != nil {
			return err
		}
		if cmd == "render" {
			_, err = checkBook(o, m, errOut)
		}
		return err
	case "private":
		o, err := parse(cmd, args, "mandate")
		if err != nil {
			return err
		}
		return makePrivate(o, out)
	case "sign":
		o, err := parse(cmd, args, "mandate", "scheme")
		if err != nil {
			return err
		}
		return sign(o, out, errOut)
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

func show(cmd string, m *policy.Mandate, h commitment.Hash, text bool, out io.Writer) error {
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
		d := policy.SignedText(m, h)
		if text {
			_, err := out.Write(d)
			return err
		}
		doc, err := principalsig.ADR036SignDoc(m.Principal, m.PrincipalHRP, d)
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

func sign(o opts, out, errOut io.Writer) error {
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
	book, err := checkBook(o, m, errOut)
	if err != nil {
		return err
	}
	if err := warnRestart(o, m, errOut); err != nil {
		return err
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
	if err := saveBook(o.book, book); err != nil {
		return err
	}
	if o.out == "" {
		_, err = fmt.Fprintf(out, "%s\n", hex.EncodeToString(signed))
		return err
	}
	if err := writeMandate(o.out, signed, m); err != nil {
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
	sm, h, err := policy.VerifyMandate(b)
	if err != nil {
		return err
	}
	// A private mandate goes to the archive only encrypted to its auditors,
	// which this tool cannot do yet; a kind 7 record would publish it in clear.
	if len(sm.Mandate.Auditors) > 0 {
		return errors.New("a private mandate (auditors) cannot be published by this tool")
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

// makePrivate sets the auditors and draws the state salt (and, when asked or
// when the mandate has none, the mandate_id) from crypto/rand: a low-entropy
// mandate_id or salt would let a dictionary search test candidate mandates
// against the public mandate hash.
func makePrivate(o opts, out io.Writer) error {
	if len(o.auditors) == 0 {
		return usageError{errors.New("private needs at least one --auditor LABEL:PUBKEY")}
	}
	m, _, err := readMandate(o.mandate)
	if err != nil {
		return err
	}
	m.Auditors = nil
	for _, a := range o.auditors {
		label, key, ok := strings.Cut(a, ":")
		pub, herr := hex.DecodeString(key)
		if !ok || herr != nil || len(pub) != 32 {
			return usageError{fmt.Errorf("--auditor %q is not LABEL:PUBKEY with a 32-byte hex key", a)}
		}
		m.Auditors = append(m.Auditors, policy.Auditor{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: label})
	}
	slices.SortFunc(m.Auditors, func(a, b policy.Auditor) int { return bytes.Compare(a.Kid, b.Kid) })
	m.StateSalt = make([]byte, 32)
	rand.Read(m.StateSalt)
	if o.newID || bytes.Equal(m.MandateID, make([]byte, 16)) {
		m.MandateID = make([]byte, 16)
		rand.Read(m.MandateID)
	}
	if err := m.ValidateBasic(); err != nil {
		return err
	}
	b, err := policy.EncodeMandate(m)
	if err != nil {
		return err
	}
	if o.out == "" {
		_, err = fmt.Fprintf(out, "%s\n", hex.EncodeToString(b))
		return err
	}
	return writeMandate(o.out, b, m)
}

// writeMandate keeps a private mandate readable by its owner only: its
// state_salt blinds the private counter's state hashes. The mode is narrowed
// before the write, so a file that already existed with a wider mode never
// holds the salt readable.
func writeMandate(path string, b []byte, m *policy.Mandate) error {
	if m.StateSalt == nil {
		return os.WriteFile(path, b, 0o644)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// readBook loads the auditor address book; a missing file is an empty book.
func readBook(path string) (map[string]string, error) {
	book := map[string]string{}
	if path == "" {
		return book, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return book, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &book); err != nil {
		return nil, fmt.Errorf("address book %s: %w", path, err)
	}
	return book, nil
}

func saveBook(path string, book map[string]string) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(book, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// checkBook prints every auditor with its fingerprint and compares each
// label with the address book. A known label that now maps to another key is
// the substitution the book exists to catch: refused unless the principal
// accepts it explicitly. It returns the book with the mandate's labels added.
func checkBook(o opts, m *policy.Mandate, errOut io.Writer) (map[string]string, error) {
	book, err := readBook(o.book)
	if err != nil {
		return nil, err
	}
	changed := 0
	for _, a := range m.Auditors {
		fmt.Fprintf(errOut, "%s\n", policy.AuditorLine(a))
		key := hex.EncodeToString(a.Pubkey)
		known, ok := book[a.Label]
		switch {
		case !ok:
			fmt.Fprintf(errOut, "note: auditor label %q is new to the address book; check its fingerprint out of band\n", a.Label)
		case known != key:
			changed++
			fmt.Fprintf(errOut, "WARNING: auditor label %q maps to another key than the address book holds (%s); this may be a substituted key\n",
				a.Label, policy.Fingerprint(policy.AuditorKid(mustHex(known))))
		}
		book[a.Label] = key
	}
	if changed > 0 && !o.acceptNewKey {
		return nil, fmt.Errorf("%d auditor label(s) changed key; check the fingerprints and rerun with --accept-new-key", changed)
	}
	return book, nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// warnRestart warns that the counters start at zero: a mandate_id that the
// replaced version does not carry, or a switch between public and private
// mode, forgets what the period has already spent.
func warnRestart(o opts, m *policy.Mandate, errOut io.Writer) error {
	const restart = "WARNING: the counters of this mandate start at zero; amounts already spent in the current periods are not carried over"
	if o.replaces == "" {
		fmt.Fprintf(errOut, "%s (new mandate_id %s; pass --replaces with the version it replaces to compare)\n", restart, hex.EncodeToString(m.MandateID))
		return nil
	}
	prev, _, err := readSigned(o.replaces)
	if err != nil {
		return fmt.Errorf("--replaces: %w", err)
	}
	switch {
	case !bytes.Equal(prev.Mandate.MandateID, m.MandateID):
		fmt.Fprintf(errOut, "%s (mandate_id changes from %s to %s)\n", restart,
			hex.EncodeToString(prev.Mandate.MandateID), hex.EncodeToString(m.MandateID))
	case (len(prev.Mandate.Auditors) > 0) != (len(m.Auditors) > 0):
		fmt.Fprintf(errOut, "%s (the mandate switches between public and private mode, which needs a new mandate_id)\n", restart)
	}
	return nil
}
