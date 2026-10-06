package fibrecert_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
)

func TestParsePFF_Live(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	d := v.Live.Derived
	p := f.Promise

	assert.Equal(t, d.Binding.ChainID, p.ChainID)
	assert.Equal(t, uint64(d.Promise.Height), p.Height)
	assert.Equal(t, unhex(t, d.Binding.NamespaceHex), p.Namespace)
	assert.Equal(t, uint32(d.Promise.BlobSize), p.BlobSize)
	assert.Equal(t, uint32(d.Promise.BlobVersion), p.BlobVersion)
	assert.Equal(t, unhex(t, d.Binding.CommitmentHex), p.Commitment[:])
	assert.True(t, mustTime(t, d.Promise.CreationTimestamp).Equal(p.CreationTime))
	assert.Equal(t, unhex(t, d.Promise.SignerPublicKeyHex), p.SignerKey)
	assert.Equal(t, unhex(t, d.Promise.OwnerSignatureHex), f.OwnerSig)
	assert.Equal(t, d.MsgSigner, f.Signer)

	require.Len(t, f.Signatures, len(d.ValidatorSigsHex))
	for i, s := range d.ValidatorSigsHex {
		assert.Equal(t, unhex(t, s), append([]byte{}, f.Signatures[i]...), "signature %d", i)
	}
}

func TestParsePFF_NotPFF(t *testing.T) {
	for name, tx := range map[string][]byte{
		"empty":   nil,
		"garbage": {0xff, 0xff, 0xff, 0xff},
		"zeros":   make([]byte, 64),
	} {
		t.Run(name, func(t *testing.T) {
			_, ok, _ := fibrecert.ParsePFF(tx)
			assert.False(t, ok)
		})
	}
}

func TestSignBytes_Live(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	got, err := fibrecert.SignBytes(f.Promise)
	require.NoError(t, err)
	require.Equal(t, unhex(t, v.Live.Derived.SignBytesHex), got)
}

func TestVerifyOwner_Live(t *testing.T) {
	v := loadVectors(t)
	require.True(t, v.Live.Derived.OwnerSignatureValid)
	require.NoError(t, fibrecert.VerifyOwner(parseOK(t, v.pffTx(t))))
}

func TestCheckBinding_Live(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	require.NoError(t, fibrecert.CheckBinding(f.Promise, v.binding(t)))

	for name, mod := range map[string]func(*fibrecert.Binding){
		"chain":      func(b *fibrecert.Binding) { b.ChainID = "mocha-4" },
		"namespace":  func(b *fibrecert.Binding) { b.Namespace[28] ^= 1 },
		"commitment": func(b *fibrecert.Binding) { b.Commitment[0] ^= 1 },
		"blob size":  func(b *fibrecert.Binding) { b.BlobSize += 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			b := v.binding(t)
			mod(&b)
			require.ErrorIs(t, fibrecert.CheckBinding(f.Promise, b), fibrecert.ErrBindingMismatch)
		})
	}
}

func evidence(in inputs) fibrecert.ValsetEvidence {
	return fibrecert.ValsetEvidence{PromiseHeader: in.promiseHeader}
}

func TestValidatorsFor_Live(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	f := parseOK(t, in.tx)
	vals, matched, err := fibrecert.ValidatorsFor(in.historicalInfo, f.Promise, evidence(in))
	require.NoError(t, err)
	assert.Equal(t, v.Live.Derived.Cv7Matched, matched)
	require.Len(t, vals, len(v.Live.Derived.Validators))
	for i, want := range v.Live.Derived.Validators {
		assert.Equal(t, edKey(t, want.PubKeyHex), vals[i].PubKey, "key %d", i)
		assert.Equal(t, int64(want.Tokens), vals[i].Power, "power %d", i)
	}
}

func TestVerifyCertificate_Live(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	f := parseOK(t, in.tx)
	vals, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
	require.NoError(t, err)

	rep, err := fibrecert.VerifyCertificate(f, vals)
	require.NoError(t, err)
	assert.Equal(t, 73, rep.Valid)
	assert.Equal(t, "0.761591", strconv.FormatFloat(rep.Share(), 'f', 6, 64))
	assert.False(t, rep.AtMostTwoThirds)
	assertReport(t, v.Live.Derived.Certificate, rep)
}

// stage failures, one per rule that the vectors list.
type outcome map[string]error

func (v *vectorFile) run(t *testing.T, in inputs) outcome {
	t.Helper()
	out := outcome{}
	f := parseOK(t, in.tx)

	out["CV2"] = fibrecert.CheckBinding(f.Promise, v.binding(t))
	out["CV3"] = fibrecert.VerifyOwner(f)

	vals, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
	require.NoError(t, err)
	_, out["CV6"] = fibrecert.VerifyCertificate(f, vals)
	_, _, out["CV7"] = fibrecert.ValidatorsFor(in.historicalInfo, f.Promise, evidence(in))
	return out
}

var ruleSentinel = map[string][]error{
	"CV2": {fibrecert.ErrBindingMismatch},
	"CV3": {fibrecert.ErrPromiseInvalid},
	"CV4": {fibrecert.ErrCertificateMalformed},
	"CV5": {fibrecert.ErrCertificateMalformed},
	"CV6": {fibrecert.ErrCertificateInvalid, fibrecert.ErrCertificateInsufficient},
	"CV7": {fibrecert.ErrValsetMismatch},
}

func isRule(err error, rule string) bool {
	for _, s := range ruleSentinel[rule] {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// firstRule is the first CV rule of a fails list, which is the order the
// vectors give and the one Verify reports.
func firstRule(fails []string) string {
	for _, r := range fails {
		if strings.HasPrefix(r, "CV") {
			return r
		}
	}
	return ""
}

func TestMutations_MustFail(t *testing.T) {
	v := loadVectors(t)
	require.NotEmpty(t, v.Mutations)
	for _, m := range v.Mutations {
		t.Run(m.ID, func(t *testing.T) {
			require.Equal(t, "reject", m.Expect.Verdict)
			want := map[string]bool{}
			for _, r := range m.Expect.Fails {
				if strings.HasPrefix(r, "CV") {
					want[r] = true
				}
			}
			in := v.applyMutation(t, v.liveInputs(t), m)
			got := v.run(t, in)
			for _, rule := range []string{"CV2", "CV3", "CV6", "CV7"} {
				if !want[rule] {
					assert.NoError(t, got[rule], "%s must pass", rule)
					continue
				}
				require.Error(t, got[rule], "%s must fail", rule)
				assert.True(t, isRule(got[rule], rule), "%s: unexpected error %v", rule, got[rule])
			}

			_, _, err := fibrecert.Verify(in.tx, v.binding(t), in.historicalInfo, evidence(in))
			if first := firstRule(m.Expect.Fails); first == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.True(t, isRule(err, first), "Verify: want %s, got %v", first, err)
			}
		})
	}
}

func TestMutations_SignatureFlipIsInvalidNotInsufficient(t *testing.T) {
	v := loadVectors(t)
	for _, m := range v.Mutations {
		if m.ID != "sig_first_signature" {
			continue
		}
		got := v.run(t, v.applyMutation(t, v.liveInputs(t), m))
		require.ErrorIs(t, got["CV6"], fibrecert.ErrCertificateInvalid)
	}
}

func TestMutations_Undetected(t *testing.T) {
	v := loadVectors(t)
	require.NotEmpty(t, v.UndetectedMutations)
	for _, m := range v.UndetectedMutations {
		t.Run(m.ID, func(t *testing.T) {
			in := v.applyMutation(t, v.liveInputs(t), m)
			for rule, err := range v.run(t, in) {
				assert.NoError(t, err, rule)
			}
			rep, matched, err := fibrecert.Verify(in.tx, v.binding(t), in.historicalInfo, evidence(in))
			require.NoError(t, err)
			assert.Equal(t, v.Live.Derived.Cv7Matched, matched)
			assertReport(t, *m.Expect.Certificate, rep)
		})
	}
}

func TestBoundary_Cases(t *testing.T) {
	v := loadVectors(t)
	require.Len(t, v.Boundary.Cases, 24)
	base := parseOK(t, v.pffTx(t))
	for _, c := range v.Boundary.Cases {
		t.Run(c.ID, func(t *testing.T) {
			vals := make([]fibrecert.Validator, len(c.Validators))
			for i, x := range c.Validators {
				vals[i] = fibrecert.Validator{PubKey: edKey(t, x.PubKeyHex), Power: int64(x.Power)}
			}
			f := base
			f.Signatures = make([][]byte, len(c.SignaturesHex))
			for i, s := range c.SignaturesHex {
				f.Signatures[i] = unhex(t, s)
			}

			rep, err := fibrecert.VerifyCertificate(f, vals)
			if c.Expect.Verdict == "accept" {
				require.NoError(t, err)
				assertReport(t, *c.Expect.Certificate, rep)
				return
			}
			switch c.Expect.Rule {
			case "CV4", "CV5":
				require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
			case "CV6":
				if c.Expect.Certificate.Invalid > 0 && c.Expect.Certificate.InvalidAfterStop == 0 {
					require.ErrorIs(t, err, fibrecert.ErrCertificateInvalid)
					return
				}
				require.ErrorIs(t, err, fibrecert.ErrCertificateInsufficient)
				assertReport(t, *c.Expect.Certificate, rep)
			default:
				require.FailNow(t, "unexpected rule "+c.Expect.Rule)
			}
		})
	}
}

func TestThreshold_Table(t *testing.T) {
	v := loadVectors(t)
	require.Len(t, v.Threshold, 15)
	for _, r := range v.Threshold {
		t.Run(r.ID, func(t *testing.T) {
			required, accept, warn := fibrecert.Threshold(int64(r.Signed), int64(r.Total))
			assert.Equal(t, int64(r.Required), required)
			assert.Equal(t, r.Accept, accept)
			assert.Equal(t, r.AtMostTwoThirds, warn)
		})
	}
}

func TestThreshold_NoOverflowAtMaxPower(t *testing.T) {
	total := int64(math.MaxInt64 / 8)
	required, accept, _ := fibrecert.Threshold(total, total)
	assert.Equal(t, 2*total/3, required)
	assert.True(t, accept)
}

// The certificate check must call Threshold; a copy of the arithmetic
// anywhere else in the package would let the three components diverge.
func TestThreshold_SingleImplementation(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)

	declared, calls := 0, 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, d := range file.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if fn.Name.Name == "Threshold" && fn.Recv == nil {
					declared++
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "Threshold" {
							calls++
						}
					case *ast.BinaryExpr:
						if lit, ok := x.Y.(*ast.BasicLit); ok && x.Op == token.QUO && lit.Value == "3" {
							t.Errorf("%s: division by 3 outside Threshold", fset.Position(x.Pos()))
						}
					}
					return true
				})
			}
		}
	}
	assert.Equal(t, 1, declared, "Threshold must be declared once")
	assert.GreaterOrEqual(t, calls, 1, "certificate check must call Threshold")
}

func FuzzParsePFF(f *testing.F) {
	raw, err := readLivePFF()
	if err == nil {
		f.Add(raw)
		f.Add(raw[:len(raw)/2])
	}
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, tx []byte) {
		pff, ok, err := fibrecert.ParsePFF(tx)
		if !ok || err != nil {
			return
		}
		_, _ = fibrecert.SignBytes(pff.Promise)
		_ = fibrecert.VerifyOwner(pff)
		_, _ = fibrecert.VerifyCertificate(pff, nil)
	})
}

func TestValidatorsFor_Rejects(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	f := parseOK(t, in.tx)
	p := f.Promise

	t.Run("historical info height changed", func(t *testing.T) {
		hi := append([]byte(nil), in.historicalInfo...)
		require.Equal(t, byte(0x18), hi[13], "height field tag")
		hi[14] ^= 1
		_, _, err := fibrecert.ValidatorsFor(hi, p, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
		require.NotErrorIs(t, err, fibrecert.ErrValsetMismatch)

		_, _, err = fibrecert.Verify(in.tx, v.binding(t), hi, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})

	t.Run("promise header from another height", func(t *testing.T) {
		_, _, err := fibrecert.ValidatorsFor(in.historicalInfo, p, fibrecert.ValsetEvidence{
			PromiseHeader: v.header(t, uint64ToNum(p.Height)+1),
		})
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
	})

	t.Run("promise height differs from header", func(t *testing.T) {
		q := p
		q.Height++
		_, _, err := fibrecert.ValidatorsFor(in.historicalInfo, q, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
	})

	t.Run("promise chain differs from header", func(t *testing.T) {
		q := p
		q.ChainID = "mocha-4"
		_, _, err := fibrecert.ValidatorsFor(in.historicalInfo, q, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
	})

	t.Run("no header", func(t *testing.T) {
		_, _, err := fibrecert.ValidatorsFor(in.historicalInfo, p, fibrecert.ValsetEvidence{})
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
	})
}

func seedKey(i byte) ed25519.PublicKey {
	sk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, ed25519.SeedSize))
	return sk.Public().(ed25519.PublicKey)
}

func uint64ToNum(h uint64) num { return num(h) }

// withSignatures swaps the validator signatures inside a PayForFibre
// transaction. The owner signature covers only the promise, so it stays valid.
func withSignatures(t *testing.T, tx []byte, sigs [][]byte) []byte {
	t.Helper()
	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(tx))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	require.Len(t, body.Messages, 1)
	var msg fibretypes.MsgPayForFibre
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	msg.ValidatorSignatures = sigs
	val, err := msg.Marshal()
	require.NoError(t, err)
	body.Messages[0].Value = val
	raw.BodyBytes, err = body.Marshal()
	require.NoError(t, err)
	out, err := raw.Marshal()
	require.NoError(t, err)
	return out
}

func decodeSigs(t *testing.T, hexes []string) [][]byte {
	t.Helper()
	sigs := make([][]byte, len(hexes))
	for i, s := range hexes {
		sigs[i] = unhex(t, s)
	}
	return sigs
}

func TestVerify_Live(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	rep, matched, err := fibrecert.Verify(in.tx, v.binding(t), in.historicalInfo, evidence(in))
	require.NoError(t, err)
	assert.Equal(t, v.Live.Derived.Cv7Matched, matched)
	assertReport(t, v.Live.Derived.Certificate, rep)
}

func TestVerify_NotFibre(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	_, _, err := fibrecert.Verify([]byte{0xff, 0xff, 0xff, 0xff}, v.binding(t), in.historicalInfo, evidence(in))
	require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
}

func TestVerify_BindingChecked(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	b := v.binding(t)
	b.Commitment[0] ^= 1
	_, _, err := fibrecert.Verify(in.tx, b, in.historicalInfo, evidence(in))
	require.ErrorIs(t, err, fibrecert.ErrBindingMismatch)
}

func TestValsetCases(t *testing.T) {
	v := loadVectors(t)
	require.Len(t, v.Valset.Cases, 11)
	live := v.liveInputs(t)
	base := parseOK(t, live.tx)

	for _, c := range v.Valset.Cases {
		t.Run(c.ID, func(t *testing.T) {
			in := inputs{
				tx:             withSignatures(t, live.tx, decodeSigs(t, c.SignaturesHex)),
				historicalInfo: unhex(t, c.HistoricalInfoHex),
				promiseHeader:  unhex(t, c.PromiseHeaderHex),
			}
			f := parseOK(t, in.tx)
			require.Equal(t, base.Promise, f.Promise)
			first := firstRule(c.Expect.Fails)
			require.NotNil(t, c.Expect.Network)
			if c.Expect.Network.Rule == "CV4" {
				require.Equal(t, "CV4", first, "the network rejects the list, so does CV4")
			}

			// Stages in isolation.
			vals, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
			if first == "CV4" {
				require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
			} else {
				require.NoError(t, err)
				for i, want := range c.Validators {
					assert.Equal(t, edKey(t, want.PubKeyHex), vals[i].PubKey, "key %d", i)
					assert.Equal(t, int64(want.Tokens), vals[i].Power, "power %d", i)
				}
				rep, err := fibrecert.VerifyCertificate(f, vals)
				if contains(c.Expect.Fails, "CV6") {
					require.ErrorIs(t, err, fibrecert.ErrCertificateInsufficient)
				} else {
					require.NoError(t, err)
				}
				if c.Expect.Certificate != nil {
					assertReport(t, *c.Expect.Certificate, rep)
				}
				_, matched, err := fibrecert.ValidatorsFor(in.historicalInfo, f.Promise, evidence(in))
				if contains(c.Expect.Fails, "CV7") {
					require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
				} else {
					require.NoError(t, err)
					assert.Equal(t, c.Expect.Cv7Matched, matched)
				}
			}

			// The whole check reports the first failing rule.
			rep, matched, err := fibrecert.Verify(in.tx, v.binding(t), in.historicalInfo, evidence(in))
			if c.Expect.Verdict == "accept" {
				require.NoError(t, err)
				assert.Equal(t, c.Expect.Cv7Matched, matched)
				assertReport(t, *c.Expect.Certificate, rep)
				return
			}
			require.Error(t, err)
			assert.True(t, isRule(err, first), "Verify: want %s, got %v", first, err)
			assert.Empty(t, matched)
		})
	}
}

func contains(s []string, x string) bool {
	for _, e := range s {
		if e == x {
			return true
		}
	}
	return false
}

// A list that repeats one validator must never be accepted: counted per slot
// the repeated signature reaches quorum with a minority of the real power.
func TestVerifyCertificate_DuplicateSignerNeverAccepted(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	sb, err := fibrecert.SignBytes(f.Promise)
	require.NoError(t, err)

	skA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	a, b, c := seedKey(1), seedKey(2), seedKey(3)
	sigA := ed25519.Sign(skA, sb)

	vals := []fibrecert.Validator{
		{PubKey: a, Power: 34_000_000}, {PubKey: a, Power: 34_000_000},
		{PubKey: a, Power: 34_000_000}, {PubKey: a, Power: 34_000_000},
		{PubKey: b, Power: 33_000_000}, {PubKey: c, Power: 33_000_000},
	}
	f.Signatures = [][]byte{sigA, sigA, sigA, sigA}

	_, err = fibrecert.VerifyCertificate(f, vals)
	require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)

	// The distinct set is honest: A alone is a minority.
	honest := []fibrecert.Validator{vals[0], vals[4], vals[5]}
	f.Signatures = [][]byte{sigA}
	_, err = fibrecert.VerifyCertificate(f, honest)
	require.ErrorIs(t, err, fibrecert.ErrCertificateInsufficient)
}

func TestVerifyCertificate_ListRejects(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	a := seedKey(7)
	b := seedKey(8)
	const max = int64(math.MaxInt64 / 8)

	for name, vals := range map[string][]fibrecert.Validator{
		"negative power":  {{PubKey: a, Power: -1}, {PubKey: b, Power: 5}},
		"zero power":      {{PubKey: a, Power: 0}},
		"overflowing sum": {{PubKey: a, Power: math.MaxInt64}, {PubKey: b, Power: math.MaxInt64}},
		"above max":       {{PubKey: a, Power: max}, {PubKey: b, Power: 1}},
		"short key":       {{PubKey: a[:31], Power: 1}},
		"nil key":         {{PubKey: nil, Power: 1}},
		"same key twice":  {{PubKey: a, Power: 1}, {PubKey: a, Power: 2}},
	} {
		t.Run(name, func(t *testing.T) {
			g := f
			g.Signatures = [][]byte{{1}}
			rep, err := fibrecert.VerifyCertificate(g, vals)
			require.ErrorIs(t, err, fibrecert.ErrCertificateMalformed)
			assert.Zero(t, rep.Valid+rep.Invalid+rep.Empty, "no walk")
		})
	}
}

func TestVerifyCertificate_FirstEntryCheckedWhenNothingRequired(t *testing.T) {
	v := loadVectors(t)
	f := parseOK(t, v.pffTx(t))
	a := seedKey(9)
	f.Signatures = [][]byte{bytes.Repeat([]byte{1}, 64)}
	_, err := fibrecert.VerifyCertificate(f, []fibrecert.Validator{{PubKey: a, Power: 1}})
	require.ErrorIs(t, err, fibrecert.ErrCertificateInvalid)
}

func FuzzValidatorsFor(f *testing.F) {
	raw, err := os.ReadFile(vectorPath)
	require.NoError(f, err)
	var v vectorFile
	require.NoError(f, json.Unmarshal(raw, &v))
	tx, err := hex.DecodeString(v.Live.Raw.PFFTxHex)
	require.NoError(f, err)
	pff, ok, err := fibrecert.ParsePFF(tx)
	require.NoError(f, err)
	require.True(f, ok)
	p := pff.Promise

	hi, err := hex.DecodeString(v.Live.Raw.HistoricalInfo.Hex)
	require.NoError(f, err)
	hdr, err := hex.DecodeString(v.Live.Raw.Headers[0].HeaderHex)
	require.NoError(f, err)
	f.Add(hi, hdr)
	f.Add(hi, []byte{})
	f.Add([]byte{}, hdr)
	f.Add(hi[:len(hi)/2], hdr)
	for _, c := range v.Valset.Cases {
		a, err := hex.DecodeString(c.HistoricalInfoHex)
		require.NoError(f, err)
		b, err := hex.DecodeString(c.PromiseHeaderHex)
		require.NoError(f, err)
		f.Add(a, b)
	}

	f.Fuzz(func(t *testing.T, hi, hdr []byte) {
		vals, matched, err := fibrecert.ValidatorsFor(hi, p, fibrecert.ValsetEvidence{PromiseHeader: hdr})
		if err != nil {
			assert.Empty(t, matched)
			assert.Nil(t, vals)
			return
		}
		require.NotEmpty(t, vals)
		assert.NotEmpty(t, matched)
		seen := map[string]bool{}
		for _, x := range vals {
			assert.Len(t, x.PubKey, ed25519.PublicKeySize)
			assert.Positive(t, x.Power)
			assert.False(t, seen[string(x.PubKey)], "duplicate key accepted")
			seen[string(x.PubKey)] = true
		}
	})
}

// keeperOrder is the order SDK NewHistoricalInfo stores a set in: consensus
// power descending, then address.
func keeperOrder(vals []fibrecert.Validator) []fibrecert.Validator {
	out := append([]fibrecert.Validator(nil), vals...)
	addr := func(v fibrecert.Validator) []byte { h := sha256.Sum256(v.PubKey); return h[:20] }
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := out[i].Power/1_000_000, out[j].Power/1_000_000
		if pi != pj {
			return pi > pj
		}
		return bytes.Compare(addr(out[i]), addr(out[j])) < 0
	})
	return out
}

func TestValsetOutOfOrder_Vector(t *testing.T) {
	v := loadVectors(t)
	var c *valsetCase
	for i := range v.Valset.Cases {
		if v.Valset.Cases[i].ID == "valset_out_of_order" {
			c = &v.Valset.Cases[i]
		}
	}
	require.NotNil(t, c)
	require.Equal(t, "reject", c.Expect.Verdict)
	require.Equal(t, []string{"CV7"}, c.Expect.Fails)
	require.Equal(t, "reject", c.Expect.Network.Verdict)
	require.Equal(t, "CV6", c.Expect.Network.Rule)

	live := v.liveInputs(t)
	in := inputs{
		tx:             withSignatures(t, live.tx, decodeSigs(t, c.SignaturesHex)),
		historicalInfo: unhex(t, c.HistoricalInfoHex),
		promiseHeader:  unhex(t, c.PromiseHeaderHex),
	}
	f := parseOK(t, in.tx)
	archived, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
	require.NoError(t, err)

	t.Run("network walks the stored order and rejects", func(t *testing.T) {
		stored := keeperOrder(archived)
		require.NotEqual(t, archived, stored)
		_, err := fibrecert.VerifyCertificate(f, stored)
		require.ErrorIs(t, err, fibrecert.ErrCertificateInvalid)
	})

	t.Run("walk over the archived order alone accepts", func(t *testing.T) {
		_, err := fibrecert.VerifyCertificate(f, archived)
		require.NoError(t, err)
	})

	t.Run("verifier fails on the order", func(t *testing.T) {
		vals, matched, err := fibrecert.ValidatorsFor(in.historicalInfo, f.Promise, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
		assert.Nil(t, vals)
		assert.Empty(t, matched)

		_, matched, err = fibrecert.Verify(in.tx, v.binding(t), in.historicalInfo, evidence(in))
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
		assert.Empty(t, matched)
	})
}

func mutateMsg(t *testing.T, tx []byte, mod func(*fibretypes.MsgPayForFibre)) []byte {
	t.Helper()
	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(tx))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	require.Len(t, body.Messages, 1)
	var msg fibretypes.MsgPayForFibre
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	mod(&msg)
	val, err := msg.Marshal()
	require.NoError(t, err)
	body.Messages[0].Value = val
	raw.BodyBytes, err = body.Marshal()
	require.NoError(t, err)
	out, err := raw.Marshal()
	require.NoError(t, err)
	return out
}

func TestParsePFF_BrokenAfterClassification(t *testing.T) {
	v := loadVectors(t)
	live := v.pffTx(t)

	var raw cosmostx.TxRaw
	require.NoError(t, raw.Unmarshal(live))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(raw.BodyBytes))
	garbageMsg := func(val []byte) []byte {
		body.Messages[0].Value = val
		bb, err := body.Marshal()
		require.NoError(t, err)
		r := raw
		r.BodyBytes = bb
		out, err := r.Marshal()
		require.NoError(t, err)
		return out
	}

	for name, tc := range map[string]struct {
		tx   []byte
		want error
	}{
		"undecodable message": {garbageMsg([]byte{0xff, 0xff}), fibrecert.ErrCertificateMalformed},
		"short namespace": {mutateMsg(t, live, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.Namespace = m.PaymentPromise.Namespace[:5]
		}), fibrecert.ErrCertificateMalformed},
		"short commitment": {mutateMsg(t, live, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.Commitment = m.PaymentPromise.Commitment[:5]
		}), fibrecert.ErrCertificateMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			pff, ok, err := fibrecert.ParsePFF(tc.tx)
			assert.True(t, ok, "still classified as Fibre")
			require.ErrorIs(t, err, tc.want)
			assert.Equal(t, fibrecert.PFF{}, pff)

			_, _, err = fibrecert.Verify(tc.tx, v.binding(t), v.liveInputs(t).historicalInfo, evidence(v.liveInputs(t)))
			require.ErrorIs(t, err, tc.want)
		})
	}
}
