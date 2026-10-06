package gatechain_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

const (
	mochaID    = "mocha-5"
	liveCaseID = "h1402819"
	bigCaseID  = "h1439696"
)

func anchorsOver(r node.FibreAnchorReader, chainID string, mod ...func(*gatechain.FibreAnchorOptions)) *gatechain.FibreAnchors {
	var o gatechain.FibreAnchorOptions
	for _, m := range mod {
		m(&o)
	}
	return gatechain.NewFibreAnchors(r, chainID, o)
}

func skipCert(o *gatechain.FibreAnchorOptions) { o.SkipCertificate = true }

func requireNotFound(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, gate.ErrAnchorNotFound)
	assert.NotErrorIs(t, err, gate.ErrChainUnavailable)
}

func requireUnavailable(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
	assert.NotErrorIs(t, err, gate.ErrAnchorNotFound)
}

// hooks overrides single reads of a reader; a nil hook passes through.
type hooks struct {
	node.FibreAnchorReader
	mu      sync.Mutex
	txCode  func(height uint64, hash [32]byte) (uint32, error)
	hist    func(height uint64) ([]byte, error)
	signed  func(height uint64) ([]byte, error)
	txCalls [][32]byte
}

func (h *hooks) TxCode(ctx context.Context, height uint64, hash [32]byte) (uint32, error) {
	h.mu.Lock()
	h.txCalls = append(h.txCalls, hash)
	fn := h.txCode
	h.mu.Unlock()
	if fn != nil {
		return fn(height, hash)
	}
	return h.FibreAnchorReader.TxCode(ctx, height, hash)
}

func (h *hooks) HistoricalInfo(ctx context.Context, height uint64) ([]byte, error) {
	if h.hist != nil {
		return h.hist(height)
	}
	return h.FibreAnchorReader.HistoricalInfo(ctx, height)
}

func (h *hooks) SignedHeader(ctx context.Context, height uint64) ([]byte, error) {
	if h.signed != nil {
		return h.signed(height)
	}
	return h.FibreAnchorReader.SignedHeader(ctx, height)
}

func (h *hooks) calls() [][32]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][32]byte(nil), h.txCalls...)
}

func txsOf(t testing.TB, b block) [][]byte {
	t.Helper()
	txs, err := libshare.ParseTxs(b.nd.Flatten())
	require.NoError(t, err)
	return txs
}

func refFor(l live, ns, commit []byte, height uint64) commitment.PayloadRef {
	return commitment.PayloadRef{DA: commitment.DAFibre, Namespace: bytes.Clone(ns),
		Commitment: bytes.Clone(commit), Height: height}
}

func liveBlock(t testing.TB) block {
	t.Helper()
	return vectorBlock(t, loadAnchorVector(t).caseByID(t, liveCaseID))
}

func TestVectorBlockHoldsTheLivePFF(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)
	assert.Equal(t, l.pffHeight, b.height)
	require.Equal(t, [][]byte{l.pff}, txsOf(t, b))
}

func TestFibreFindAnchorAcceptsTheLivePFF(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)
	c := b.chain(t, l)
	a, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
	require.NoError(t, err)
	assert.Equal(t, l.pffHeight, a.Height)
	assert.Equal(t, txHash(l.pff), a.TxHash)
	assert.Equal(t, l.blobSize, a.Promise.BlobSize)
	assert.Equal(t, l.promiseH, a.Promise.Height)
	assert.EqualValues(t, l.created.UnixNano(), a.Promise.CreationTime.UnixNano())
	assert.Equal(t, 1, c.HeaderReads())
	dah, ns := c.BridgeReads()
	assert.Equal(t, 1, dah)
	assert.Equal(t, 1, ns)

	gotAnchor, err := anchorsOver(b.chain(t, l), mochaID).FindAnchor(bg, l.ref())
	require.NoError(t, err)
	assert.Equal(t, l.pffHeight, gotAnchor.Height)
	assert.EqualValues(t, l.created.Unix(), gotAnchor.RetentionStart, "retention starts at the promise creation time")
}

func TestFibreAnchorProofIsTheArchiveForm(t *testing.T) {
	v := loadAnchorVector(t)
	l := loadLive(t)
	for _, id := range []string{liveCaseID, bigCaseID} {
		t.Run(id, func(t *testing.T) {
			vc := v.caseByID(t, id)
			b := vectorBlock(t, vc)
			q := vc.Expect.Queries[0]
			ref := refFor(l, unhex(t, q.Namespace), unhex(t, q.Commitment), b.height)
			a, err := anchorsOver(b.chain(t, l), mochaID, skipCert).Lookup(bg, ref)
			require.NoError(t, err)
			require.Equal(t, []byte{0xa3, 0x01, 0x01, 0x02}, a.Proof[:4], "form 1: a map of three keys, 1 -> 1, 2 -> DAH")
			want := unhex(t, vc.Expect.ArchiveProof.Hex)
			sum := sha256.Sum256(a.Proof)
			assert.Equal(t, vc.Expect.ArchiveProof.SHA256, hexOf(sum[:]))
			assert.True(t, bytes.Equal(want, a.Proof), "the proof is the vector archive_proof byte for byte")
		})
	}
}

// Every query of the vector: the candidates and the anchor are the ones the
// vector names, assuming every candidate ran with code 0.
func TestFibreVectorQueries(t *testing.T) {
	v := loadAnchorVector(t)
	l := loadLive(t)
	for _, vc := range v.Live.Cases {
		b := vectorBlock(t, vc)
		for i, q := range vc.Expect.Queries {
			t.Run(fmt.Sprintf("%s/%d", vc.ID, i), func(t *testing.T) {
				// Only the first block carries certificate evidence.
				mod := []func(*gatechain.FibreAnchorOptions){}
				if vc.ID != liveCaseID {
					mod = append(mod, skipCert)
				}
				ref := refFor(l, unhex(t, q.Namespace), unhex(t, q.Commitment), b.height)
				a, err := anchorsOver(b.chain(t, l), q.ChainID, mod...).Lookup(bg, ref)
				if q.Anchor == "none" {
					requireNotFound(t, err)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, vc.Expect.Txs[num(t, q.Anchor)].SHA256, hexOf(a.TxHash[:]))
			})
		}
	}
}

func TestFibreFindAnchorRejectsWhatIsNotTheCommittedPFF(t *testing.T) {
	l := loadLive(t)
	cases := []struct {
		name  string
		chain string
		ref   func(r *commitment.PayloadRef)
		tx    func(m *fibretypes.MsgPayForFibre)
		code  uint32
	}{
		{name: "wrong namespace", chain: mochaID, ref: func(r *commitment.PayloadRef) { r.Namespace[len(r.Namespace)-1] ^= 1 }},
		{name: "wrong commitment", chain: mochaID, ref: func(r *commitment.PayloadRef) { r.Commitment[0] ^= 1 }},
		{name: "another chain id", chain: "mocha-4"},
		{name: "blob version 1", chain: mochaID, tx: func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.BlobVersion = 1 }},
		{name: "failed in execution", chain: mochaID, code: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := l.pff
			if tc.tx != nil {
				tx = mutateTx(t, l.pff, tc.tx)
			}
			c := buildBlock(t, l.pffHeight, []byte("unrelated tx"), tx).chain(t, l)
			c.SetTxCode(l.pffHeight, txHash(tx), tc.code)
			ref := l.ref()
			if tc.ref != nil {
				tc.ref(&ref)
			}
			_, err := anchorsOver(c, tc.chain).Lookup(bg, ref)
			requireNotFound(t, err)
		})
	}
	t.Run("no PFF in the block", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireNotFound(t, err)
	})
	t.Run("only other txs in the namespace", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight, []byte("a"), []byte("b")).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireNotFound(t, err)
	})
	t.Run("not da 1", func(t *testing.T) {
		ref := l.ref()
		ref.DA = commitment.DACelestiaBlob
		c := liveBlock(t).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, ref)
		requireNotFound(t, err)
		assert.Zero(t, c.HeaderReads())
	})
	t.Run("commitment of the wrong length", func(t *testing.T) {
		ref := l.ref()
		ref.Commitment = ref.Commitment[:31]
		c := liveBlock(t).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, ref)
		requireNotFound(t, err)
		assert.Zero(t, c.HeaderReads())
	})
}

// The anchor proof steps are the answer of an endpoint, not a statement about
// the chain: any failure of them is unavailable, never an absent anchor.
func TestFibreMutationsOfTheLiveBlock(t *testing.T) {
	v := loadAnchorVector(t)
	l := loadLive(t)
	base := liveBlock(t)
	_, err := anchorsOver(base.chain(t, l), mochaID).Lookup(bg, l.ref())
	require.NoError(t, err, "the unmutated block is the baseline")

	stage := map[string]string{"NA2": "dah at", "NA3": "namespace data at"}
	for _, m := range v.Mutations {
		t.Run(m.ID, func(t *testing.T) {
			require.Equal(t, liveCaseID, m.Case)
			require.Equal(t, "reject", m.Expect.Verdict)
			mut, ok := applyOp(t, base, m.Op)
			if !ok {
				return
			}
			c := mut.chain(t, l)
			_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
			requireUnavailable(t, err)
			assert.Contains(t, err.Error(), stage[m.Expect.Fails], "rejected at the rule the vector names")
			_, nsReads := c.BridgeReads()
			if m.Expect.Fails == "NA2" {
				assert.Zero(t, nsReads, "the namespace data is not read for a DAH that does not match")
			}
		})
	}
}

// The two mutations that act on the encoded stream and the checked namespace
// cannot be served through the reader, so they are checked on the library.
func TestFibreStreamMutationsOfTheVector(t *testing.T) {
	v := loadAnchorVector(t)
	vc := v.caseByID(t, liveCaseID)
	b := vectorBlock(t, vc)
	stream := unhex(t, vc.Raw.NamespaceD)
	for _, m := range v.Mutations {
		switch m.Op.Kind {
		case "truncate_stream":
			var nd shwap.NamespaceData
			require.Error(t, readStream(&nd, stream[:len(stream)-num(t, m.Op.Bytes)]))
		case "verify_namespace":
			other, err := libshare.NewNamespaceFromBytes(unhex(t, m.Op.NS))
			require.NoError(t, err)
			assert.Error(t, b.nd.Verify(b.dah(), other))
		}
	}
	assert.Equal(t, stream, streamOf(t, b.nd), "the stream round-trips")
}

func TestFibreTamperedProofsAndSharesAreUnavailable(t *testing.T) {
	l := loadLive(t)
	base := liveBlock(t)
	cases := []struct {
		name string
		mut  func(b *block)
	}{
		{"a proof node flipped", func(b *block) {
			p := b.nd[1].Proof
			nodes := p.Nodes()
			require.NotEmpty(t, nodes)
			nodes[0] = flipByte(nodes[0], 40, 1)
			np := newInclusion(p, nodes)
			b.nd[1].Proof = &np
		}},
		{"a proof node dropped", func(b *block) {
			p := b.nd[1].Proof
			nodes := p.Nodes()
			require.NotEmpty(t, nodes)
			np := newInclusion(p, nodes[1:])
			b.nd[1].Proof = &np
		}},
		{"proof range moved by one", func(b *block) {
			p := b.nd[1].Proof
			np := newRange(p, p.Start()+1, p.End()+1)
			b.nd[1].Proof = &np
		}},
		{"proof of one row on the shares of another", func(b *block) {
			b.nd[0].Proof, b.nd[1].Proof = b.nd[1].Proof, b.nd[0].Proof
		}},
		{"shares of one row on the proof of another", func(b *block) {
			b.nd[0].Shares, b.nd[1].Shares = b.nd[1].Shares, b.nd[0].Shares
		}},
		{"proof missing", func(b *block) { b.nd[0].Proof = nil }},
		{"shares emptied", func(b *block) { b.nd[0].Shares = nil }},
		{"no rows at all", func(b *block) { b.nd = nil }},
		{"namespace data of another block", func(b *block) {
			other := vectorBlock(t, loadAnchorVector(t).caseByID(t, bigCaseID))
			b.nd = other.nd
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base.clone()
			tc.mut(&mut)
			_, err := anchorsOver(mut.chain(t, l), mochaID).Lookup(bg, l.ref())
			requireUnavailable(t, err)
		})
	}
}

func TestFibreHeaderAndDAHEvidence(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)
	t.Run("the DAH of another block", func(t *testing.T) {
		other := vectorBlock(t, loadAnchorVector(t).caseByID(t, bigCaseID))
		c := b.chain(t, l)
		c.SetDAH(b.height, other.rows, other.cols)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("header without a data hash", func(t *testing.T) {
		c := b.chain(t, l)
		c.AddHeader(b.height, nil, headerTime)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("header of another height", func(t *testing.T) {
		c := b.chain(t, l)
		c.AddHeader(b.height+1, b.dataHash, headerTime)
		c.IgnoreHeights(b.height + 1)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
		dah, _ := c.BridgeReads()
		assert.Zero(t, dah, "nothing is read from the bridge after the header fails")
	})
	t.Run("header not found", func(t *testing.T) {
		c := nodefake.NewFibreChain()
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("consensus endpoint fails", func(t *testing.T) {
		c := b.chain(t, l)
		c.Fail = nodefake.ErrInjected
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
		assert.ErrorIs(t, err, nodefake.ErrInjected)
	})
	t.Run("bridge fails", func(t *testing.T) {
		c := b.chain(t, l)
		c.FailBridge = nodefake.ErrInjected
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
		assert.ErrorIs(t, err, nodefake.ErrInjected)
	})
	t.Run("bridge has no DAH", func(t *testing.T) {
		c := nodefake.NewFibreChain()
		c.AddHeader(b.height, b.dataHash, headerTime)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("bridge has no namespace data", func(t *testing.T) {
		c := nodefake.NewFibreChain()
		c.AddHeader(b.height, b.dataHash, headerTime)
		c.SetDAH(b.height, b.rows, b.cols)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		cancel()
		c := b.chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(ctx, l.ref())
		requireUnavailable(t, err)
		assert.Zero(t, c.HeaderReads())
	})
}

// Cases 1 to 14 of the reassembly vector, as namespace data a bridge could
// really prove: the shares sit in the PayForFibre namespace of a square.
func TestFibreReassemblyThroughTheLookup(t *testing.T) {
	v := loadAnchorVector(t)
	l := loadLive(t)
	for _, rc := range v.Reassembly {
		t.Run(rc.ID, func(t *testing.T) {
			var shares []libshare.Share
			inNamespace := true
			for _, h := range rc.Shares {
				s, err := libshare.NewShare(unhex(t, h))
				require.NoError(t, err)
				inNamespace = inNamespace && s.Namespace().Equals(libshare.PayForFibreNamespace)
				shares = append(shares, s)
			}
			if !inNamespace {
				t.Skip("shares of another namespace cannot be proven as PayForFibre data")
			}
			b := buildBlockFromShares(t, l.pffHeight, shares)
			c := b.chain(t, l)
			_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
			if rc.Expect.Verdict == "accept" {
				// The txs are not Fibre txs for the reference, so the lookup
				// finishes with no anchor, not with a failed proof.
				requireNotFound(t, err)
				return
			}
			requireUnavailable(t, err)
			assert.Contains(t, err.Error(), "namespace data at")
		})
	}
}

func TestFibreFindAnchorCertificate(t *testing.T) {
	l := loadLive(t)
	stripped := func(keep int) []byte {
		return mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
			for i := keep; i < len(m.ValidatorSignatures); i++ {
				m.ValidatorSignatures[i] = nil
			}
		})
	}
	t.Run("below the network rule is no anchor", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight, stripped(5)).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireNotFound(t, err)
		assert.ErrorIs(t, err, fibrecert.ErrCertificateInsufficient)
	})
	t.Run("a flipped validator signature", func(t *testing.T) {
		tx := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
			for i, s := range m.ValidatorSignatures {
				if len(s) > 0 {
					m.ValidatorSignatures[i] = bytes.Clone(s)
					m.ValidatorSignatures[i][0] ^= 1
					return
				}
			}
		})
		c := buildBlock(t, l.pffHeight, tx).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireNotFound(t, err)
	})
	t.Run("the promise header is not for the promise height", func(t *testing.T) {
		c := liveBlock(t).chain(t, l)
		c.SetSignedHeader(l.promiseH, l.headers[l.promiseH+1])
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("historical info at another height", func(t *testing.T) {
		hi := parseHist(t, l.hist)
		hi.Header.Height++
		c := liveBlock(t).chain(t, l)
		c.SetHistoricalInfo(l.promiseH, marshalHist(t, hi))
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("evidence reads that fail", func(t *testing.T) {
		down := fmt.Errorf("%w: down", node.ErrUnavailable)
		for name, h := range map[string]*hooks{
			"historical info":           {hist: func(uint64) ([]byte, error) { return nil, down }},
			"header":                    {signed: func(uint64) ([]byte, error) { return nil, down }},
			"historical info not found": {hist: func(uint64) ([]byte, error) { return nil, node.ErrNotFound }},
			"header not found":          {signed: func(uint64) ([]byte, error) { return nil, node.ErrNotFound }},
		} {
			h.FibreAnchorReader = liveBlock(t).chain(t, l)
			_, err := anchorsOver(h, mochaID).Lookup(bg, l.ref())
			require.Error(t, err, name)
			assert.ErrorIs(t, err, gate.ErrChainUnavailable, name)
			assert.NotErrorIs(t, err, gate.ErrAnchorNotFound, name)
		}
	})
	t.Run("an evidence failure stops the lookup before later candidates", func(t *testing.T) {
		first := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 1) })
		second := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 2) })
		h := &hooks{FibreAnchorReader: buildBlock(t, l.pffHeight, first, second).chain(t, l),
			hist: func(uint64) ([]byte, error) { return nil, fmt.Errorf("%w: down", node.ErrUnavailable) }}
		_, err := anchorsOver(h, mochaID).Lookup(bg, l.ref())
		requireUnavailable(t, err)
		assert.Len(t, h.calls(), 1)
	})
	t.Run("certificate check off skips the evidence reads", func(t *testing.T) {
		h := &hooks{FibreAnchorReader: buildBlock(t, l.pffHeight, stripped(0)).chain(t, l),
			hist:   func(uint64) ([]byte, error) { return nil, assert.AnError },
			signed: func(uint64) ([]byte, error) { return nil, assert.AnError }}
		a, err := anchorsOver(h, mochaID, skipCert).Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, l.pffHeight, a.Height)
	})
	t.Run("the zero value checks the certificate", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight, stripped(0)).chain(t, l)
		_, err := gatechain.NewFibreAnchors(c, mochaID, gatechain.FibreAnchorOptions{}).Lookup(bg, l.ref())
		requireNotFound(t, err)
		assert.ErrorIs(t, err, fibrecert.ErrCertificateInsufficient)
	})
}

func bech32Addr(t testing.TB, b byte) string {
	t.Helper()
	s, err := bech32.ConvertAndEncode("celestia", bytes.Repeat([]byte{b}, 20))
	require.NoError(t, err)
	return s
}

func TestFibreFindAnchorEarliestCreationTimeWins(t *testing.T) {
	l := loadLive(t)
	at := func(sec int64) []byte {
		return mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.CreationTimestamp = l.created.Add(time.Duration(sec) * time.Second)
		})
	}
	lookup := func(t *testing.T, c node.FibreAnchorReader) (gatechain.FibreAnchor, error) {
		return anchorsOver(c, mochaID, skipCert).Lookup(bg, l.ref())
	}
	t.Run("earliest of several, whatever the position", func(t *testing.T) {
		early := at(-20)
		a, err := lookup(t, buildBlock(t, l.pffHeight, at(30), early, at(10)).chain(t, l))
		require.NoError(t, err)
		assert.Equal(t, txHash(early), a.TxHash)
		assert.EqualValues(t, l.created.Unix()-20, a.Promise.CreationTime.Unix())
	})
	t.Run("a failed earlier one does not count", func(t *testing.T) {
		early, mid := at(-20), at(10)
		c := buildBlock(t, l.pffHeight, at(30), early, mid).chain(t, l)
		c.SetTxCode(l.pffHeight, txHash(early), 1)
		a, err := lookup(t, c)
		require.NoError(t, err)
		assert.Equal(t, txHash(mid), a.TxHash)
	})
	t.Run("a tx of another commitment does not count", func(t *testing.T) {
		other := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.Commitment[0] ^= 1
			m.PaymentPromise.CreationTimestamp = l.created.Add(-time.Hour)
		})
		late := at(30)
		a, err := lookup(t, buildBlock(t, l.pffHeight, other, late).chain(t, l))
		require.NoError(t, err)
		assert.Equal(t, txHash(late), a.TxHash)
	})
	t.Run("ties go to the position in the namespace", func(t *testing.T) {
		first := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 1) })
		second := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 2) })
		got, err := lookup(t, buildBlock(t, l.pffHeight, first, second).chain(t, l))
		require.NoError(t, err)
		assert.Equal(t, txHash(first), got.TxHash)
		got, err = lookup(t, buildBlock(t, l.pffHeight, second, first).chain(t, l))
		require.NoError(t, err)
		assert.Equal(t, txHash(second), got.TxHash)
	})
	t.Run("a tie broken by position, not by hash", func(t *testing.T) {
		a, b := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 3) }),
			mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.Signer = bech32Addr(t, 4) })
		lo, hi := a, b
		if bytes.Compare(txHashSlice(a), txHashSlice(b)) > 0 {
			lo, hi = b, a
		}
		got, err := lookup(t, buildBlock(t, l.pffHeight, hi, lo).chain(t, l))
		require.NoError(t, err)
		assert.Equal(t, txHash(hi), got.TxHash)
	})
}

func txHashSlice(tx []byte) []byte { h := txHash(tx); return h[:] }

func TestFibreResultCodes(t *testing.T) {
	l := loadLive(t)
	at := func(sec int64) []byte {
		return mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.CreationTimestamp = l.created.Add(time.Duration(sec) * time.Second)
		})
	}
	early, late := at(-5), at(5)
	t.Run("a non-zero code skips the candidate", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight, late, early).chain(t, l)
		c.SetTxCode(l.pffHeight, txHash(early), 11)
		a, err := anchorsOver(c, mochaID, skipCert).Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, txHash(late), a.TxHash)
	})
	t.Run("every candidate with a non-zero code", func(t *testing.T) {
		c := buildBlock(t, l.pffHeight, late, early).chain(t, l)
		c.SetTxCode(l.pffHeight, txHash(early), 11)
		c.SetTxCode(l.pffHeight, txHash(late), 2)
		_, err := anchorsOver(c, mochaID, skipCert).Lookup(bg, l.ref())
		requireNotFound(t, err)
	})
	t.Run("every candidate fails the certificate", func(t *testing.T) {
		a, b := at(7), at(8)
		c := buildBlock(t, l.pffHeight, a, b).chain(t, l)
		_, err := anchorsOver(c, mochaID).Lookup(bg, l.ref())
		requireNotFound(t, err)
	})
	t.Run("code is asked for the height of the anchor", func(t *testing.T) {
		var heights []uint64
		h := &hooks{FibreAnchorReader: buildBlock(t, l.pffHeight, early).chain(t, l),
			txCode: func(height uint64, _ [32]byte) (uint32, error) { heights = append(heights, height); return 0, nil }}
		_, err := anchorsOver(h, mochaID, skipCert).Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, []uint64{l.pffHeight}, heights)
	})
	errs := map[string]error{
		"result at another height": fmt.Errorf("%w: tx result at height 1, want 2", node.ErrUnavailable),
		"tx not found":             fmt.Errorf("%w: tx result", node.ErrNotFound),
		"read error":               fmt.Errorf("%w: down", node.ErrUnavailable),
		"unclassified error":       assert.AnError,
	}
	for name, e := range errs {
		t.Run(name+" stops the lookup", func(t *testing.T) {
			h := &hooks{FibreAnchorReader: buildBlock(t, l.pffHeight, late, early).chain(t, l),
				txCode: func(uint64, [32]byte) (uint32, error) { return 0, e }}
			_, err := anchorsOver(h, mochaID, skipCert).Lookup(bg, l.ref())
			requireUnavailable(t, err)
			assert.Equal(t, [][32]byte{txHash(early)}, h.calls(), "no later candidate stands in for the one that cannot be read")
		})
	}
	t.Run("an error after a skipped candidate still stops the lookup", func(t *testing.T) {
		n := 0
		h := &hooks{FibreAnchorReader: buildBlock(t, l.pffHeight, late, early).chain(t, l),
			txCode: func(uint64, [32]byte) (uint32, error) {
				n++
				if n == 1 {
					return 3, nil
				}
				return 0, node.ErrUnavailable
			}}
		_, err := anchorsOver(h, mochaID, skipCert).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
}

func TestFibreReadLimit(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)
	size := uint64(len(streamOf(t, b.nd)))
	require.NotZero(t, size)
	lim := func(n uint64) func(*gatechain.FibreAnchorOptions) {
		return func(o *gatechain.FibreAnchorOptions) { o.MaxReadBytes = n }
	}
	t.Run("at the limit", func(t *testing.T) {
		_, err := anchorsOver(b.chain(t, l), mochaID, lim(size)).Lookup(bg, l.ref())
		require.NoError(t, err)
	})
	t.Run("one byte above is unavailable, never absent", func(t *testing.T) {
		_, err := anchorsOver(b.chain(t, l), mochaID, lim(size-1)).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("tiny limit", func(t *testing.T) {
		_, err := anchorsOver(b.chain(t, l), mochaID, lim(1)).Lookup(bg, l.ref())
		requireUnavailable(t, err)
	})
	t.Run("an oversized answer is not cached", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, lim(size-1), func(o *gatechain.FibreAnchorOptions) { o.CacheEntries = 4 })
		_, _ = a.Lookup(bg, l.ref())
		_, err := a.Lookup(bg, l.ref())
		requireUnavailable(t, err)
		assert.Equal(t, 2, c.HeaderReads())
	})
}

func TestFibreFindAnchorCaches(t *testing.T) {
	l := loadLive(t)
	b := liveBlock(t)
	withCache := func(n int) func(*gatechain.FibreAnchorOptions) {
		return func(o *gatechain.FibreAnchorOptions) { o.CacheEntries = n }
	}
	t.Run("one read serves repeated lookups", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, withCache(8))
		for range 3 {
			got, err := a.FindAnchor(bg, l.ref())
			require.NoError(t, err)
			assert.Equal(t, l.pffHeight, got.Height)
		}
		assert.Equal(t, 1, c.HeaderReads())
		dah, ns := c.BridgeReads()
		assert.Equal(t, 1, dah)
		assert.Equal(t, 1, ns)
	})
	t.Run("no cache by default", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID)
		for range 3 {
			_, err := a.Lookup(bg, l.ref())
			require.NoError(t, err)
		}
		assert.Equal(t, 3, c.HeaderReads())
	})
	t.Run("a failure is not cached", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, withCache(8))
		c.FailBridge = nodefake.ErrInjected
		_, err := a.Lookup(bg, l.ref())
		requireUnavailable(t, err)
		c.FailBridge = nil
		_, err = a.Lookup(bg, l.ref())
		require.NoError(t, err)
	})
	t.Run("a missing anchor is not cached", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, withCache(8))
		ref := l.ref()
		ref.Commitment[0] ^= 1
		for range 2 {
			_, err := a.Lookup(bg, ref)
			requireNotFound(t, err)
		}
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("the cache is per reference", func(t *testing.T) {
		c := b.chain(t, l)
		a := anchorsOver(c, mochaID, withCache(8))
		_, err := a.Lookup(bg, l.ref())
		require.NoError(t, err)
		ref := l.ref()
		ref.Namespace[len(ref.Namespace)-1] ^= 1
		_, err = a.Lookup(bg, ref)
		requireNotFound(t, err)
		assert.Equal(t, 2, c.HeaderReads())
	})
	t.Run("the bound evicts the oldest", func(t *testing.T) {
		other := mutateTx(t, l.pff, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment[0] ^= 1 })
		c := buildBlock(t, l.pffHeight, l.pff, other).chain(t, l)
		a := anchorsOver(c, mochaID, skipCert, withCache(1))
		refB := l.ref()
		refB.Commitment[0] ^= 1
		_, err := a.Lookup(bg, l.ref())
		require.NoError(t, err)
		_, err = a.Lookup(bg, refB)
		require.NoError(t, err)
		_, err = a.Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, 3, c.HeaderReads(), "the first reference was evicted")
		_, err = a.Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.Equal(t, 3, c.HeaderReads())
	})
	t.Run("a caller cannot change what the cache holds", func(t *testing.T) {
		a := anchorsOver(b.chain(t, l), mochaID, withCache(2))
		first, err := a.Lookup(bg, l.ref())
		require.NoError(t, err)
		want := bytes.Clone(first.Proof)
		first.Proof[10] ^= 0xff
		second, err := a.Lookup(bg, l.ref())
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, second.Proof))
	})
	t.Run("concurrent lookups", func(t *testing.T) {
		a := anchorsOver(b.chain(t, l), mochaID, withCache(2))
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := a.Lookup(bg, l.ref())
				assert.NoError(t, err)
			}()
		}
		wg.Wait()
	})
}

func TestFibreAnchorsConfig(t *testing.T) {
	l := loadLive(t)
	c := liveBlock(t).chain(t, l)
	cases := []struct {
		name string
		a    *gatechain.FibreAnchors
	}{
		{"no reader", gatechain.NewFibreAnchors(nil, mochaID, gatechain.FibreAnchorOptions{})},
		{"no chain id", gatechain.NewFibreAnchors(c, "", gatechain.FibreAnchorOptions{})},
		{"negative cache", gatechain.NewFibreAnchors(c, mochaID, gatechain.FibreAnchorOptions{CacheEntries: -1})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.a.Lookup(bg, l.ref())
			requireUnavailable(t, err)
			require.ErrorIs(t, err, gatechain.ErrInvalidConfig)
		})
	}
	t.Run("the config error is the lookup answer, nothing is read", func(t *testing.T) {
		assert.Zero(t, c.HeaderReads())
	})
}

func TestFibreAnchorOptionsValidateBasic(t *testing.T) {
	valid := gatechain.FibreAnchorOptions{MaxReadBytes: 1 << 20, CacheEntries: 16}
	require.NoError(t, valid.ValidateBasic())
	cases := []struct {
		name string
		mod  func(*gatechain.FibreAnchorOptions)
		ok   bool
	}{
		{"valid", func(*gatechain.FibreAnchorOptions) {}, true},
		{"no cache", func(o *gatechain.FibreAnchorOptions) { o.CacheEntries = 0 }, true},
		{"certificate check skipped", func(o *gatechain.FibreAnchorOptions) { o.SkipCertificate = true }, true},
		{"one byte limit", func(o *gatechain.FibreAnchorOptions) { o.MaxReadBytes = 1 }, true},
		{"zero limit", func(o *gatechain.FibreAnchorOptions) { o.MaxReadBytes = 0 }, false},
		{"negative cache", func(o *gatechain.FibreAnchorOptions) { o.CacheEntries = -1 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := valid
			tc.mod(&o)
			err := o.ValidateBasic()
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, gatechain.ErrInvalidConfig)
		})
	}
	t.Run("defaults make the zero value valid and check the certificate", func(t *testing.T) {
		o := gatechain.FibreAnchorOptions{}.WithDefaults()
		assert.EqualValues(t, gatechain.DefaultFibreMaxReadBytes, o.MaxReadBytes)
		assert.EqualValues(t, 16<<20, o.MaxReadBytes)
		assert.False(t, o.SkipCertificate)
		require.NoError(t, o.ValidateBasic())
	})
	t.Run("defaults keep what is set", func(t *testing.T) {
		o := gatechain.FibreAnchorOptions{MaxReadBytes: 77, CacheEntries: 3, SkipCertificate: true}.WithDefaults()
		assert.EqualValues(t, 77, o.MaxReadBytes)
		assert.Equal(t, 3, o.CacheEntries)
		assert.True(t, o.SkipCertificate)
	})
}
