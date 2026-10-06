package fibrecert_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestValidatorsFor_Live(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	vals, matched, err := fibrecert.ValidatorsFor(in.historicalInfo, fibrecert.ValsetEvidence{
		PromiseHeader: in.promiseHeader,
		NextHeader:    in.nextHeader,
		NextValset:    in.nextValset,
	})
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
	f, ok, err := fibrecert.ParsePFF(in.tx)
	require.NoError(t, err)
	require.True(t, ok)

	out["CV2"] = fibrecert.CheckBinding(f.Promise, v.binding(t))
	out["CV3"] = fibrecert.VerifyOwner(f)

	vals, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
	require.NoError(t, err)
	_, out["CV6"] = fibrecert.VerifyCertificate(f, vals)
	_, out["CV7"] = fibrecert.CheckValset(vals, fibrecert.ValsetEvidence{
		PromiseHeader: in.promiseHeader,
		NextHeader:    in.nextHeader,
		NextValset:    in.nextValset,
	})
	return out
}

var ruleSentinel = map[string][]error{
	"CV2": {fibrecert.ErrBindingMismatch},
	"CV3": {fibrecert.ErrPromiseInvalid},
	"CV6": {fibrecert.ErrCertificateInvalid, fibrecert.ErrCertificateInsufficient},
	"CV7": {fibrecert.ErrValsetMismatch},
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
			got := v.run(t, v.applyMutation(t, v.liveInputs(t), m))
			for rule := range ruleSentinel {
				if !want[rule] {
					assert.NoError(t, got[rule], "%s must pass", rule)
					continue
				}
				require.Error(t, got[rule], "%s must fail", rule)
				matched := false
				for _, s := range ruleSentinel[rule] {
					matched = matched || errors.Is(got[rule], s)
				}
				assert.True(t, matched, "%s: unexpected error %v", rule, got[rule])
			}
			if want["CV3"] {
				require.ErrorIs(t, got["CV3"], fibrecert.ErrPromiseInvalid)
			}
			if want["CV7"] {
				require.ErrorIs(t, got["CV7"], fibrecert.ErrValsetMismatch)
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
			got := v.run(t, in)
			for rule, err := range got {
				assert.NoError(t, err, rule)
			}
			f := parseOK(t, in.tx)
			vals, err := fibrecert.ParseHistoricalInfo(in.historicalInfo)
			require.NoError(t, err)
			rep, err := fibrecert.VerifyCertificate(f, vals)
			require.NoError(t, err)
			assertReport(t, *m.Expect.Certificate, rep)
		})
	}
}

func TestBoundary_Cases(t *testing.T) {
	v := loadVectors(t)
	require.Len(t, v.Boundary.Cases, 18)
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
			case "CV5":
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

func TestValidatorsFor_HeightMismatch(t *testing.T) {
	v := loadVectors(t)
	in := v.liveInputs(t)
	p := v.Live.Derived.Promise.Height

	t.Run("historical info height changed", func(t *testing.T) {
		hi := append([]byte(nil), in.historicalInfo...)
		require.Equal(t, byte(0x18), hi[13], "height field tag")
		hi[14] ^= 1
		_, _, err := fibrecert.ValidatorsFor(hi, fibrecert.ValsetEvidence{
			PromiseHeader: in.promiseHeader, NextHeader: in.nextHeader, NextValset: in.nextValset,
		})
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
	})

	t.Run("promise header from another height", func(t *testing.T) {
		_, _, err := fibrecert.ValidatorsFor(in.historicalInfo, fibrecert.ValsetEvidence{
			PromiseHeader: v.header(t, p+1), NextHeader: v.header(t, p+2),
		})
		require.ErrorIs(t, err, fibrecert.ErrValsetMismatch)
	})
}
