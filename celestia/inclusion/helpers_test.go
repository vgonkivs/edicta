package inclusion_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/light/provider"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	"github.com/cometbft/cometbft/types"
	"github.com/cometbft/cometbft/version"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
)

const (
	chainID  = "mocha-4"
	poolSize = 40
	window   = 6
)

var (
	bg = context.Background()
	// The sub-second part checks that block time is floored to seconds.
	base = time.Date(2026, 10, 4, 12, 0, 0, 700_000_000, time.UTC)
	ns   = append([]byte{0}, bytes.Repeat([]byte{7}, 28)...)
	comm = sum("blob commitment")
)

func sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func blockTime(h int64) time.Time { return base.Add(time.Duration(h) * 6 * time.Second) }

// ref is a share v1 reference to the blob that the fake chain holds at h.
func ref(h uint64) commitment.PayloadRef {
	return commitment.PayloadRef{
		DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: comm, Height: h,
		Signer: bytes.Repeat([]byte{9}, 20),
	}
}

// blockOpts bends one block away from an honest one.
type blockOpts struct {
	chainID  string
	time     time.Time
	dataRoot []byte
	signers  int // validators that sign; 0 means all
	badSigs  int // of those signers, how many carry a corrupted signature
	forged   bool
	swapRoot []byte // replaces the data root AFTER the commit signed the original header
}

// testChain makes light blocks whose validator set slides by one key per
// height, so a far skip has too little overlap and needs bisection.
type testChain struct{ pool []crypto.PrivKey }

func newTestChain() *testChain {
	c := &testChain{}
	for i := 0; i < poolSize; i++ {
		c.pool = append(c.pool, ed25519.GenPrivKeyFromSecret([]byte{byte(i)}))
	}
	return c
}

func (c *testChain) keys(h int64) []crypto.PrivKey { return c.pool[h-1 : h-1+window] }

func (c *testChain) valSet(h int64) *types.ValidatorSet {
	var vs []*types.Validator
	for _, k := range c.keys(h) {
		vs = append(vs, types.NewValidator(k.PubKey(), 10))
	}
	return types.NewValidatorSet(vs)
}

func dataRootAt(h int64) []byte { return sum("data root " + string(rune('A'+h))) }

func (c *testChain) block(t testing.TB, h int64, o blockOpts) *types.LightBlock {
	t.Helper()
	id, bt, root := chainID, blockTime(h), dataRootAt(h)
	if o.chainID != "" {
		id = o.chainID
	}
	if !o.time.IsZero() {
		bt = o.time
	}
	if o.dataRoot != nil {
		root = o.dataRoot
	}
	vs, next := c.valSet(h), c.valSet(h+1)
	hdr := &types.Header{
		Version: cmtversion.Consensus{Block: version.BlockProtocol}, ChainID: id, Height: h, Time: bt,
		ValidatorsHash: vs.Hash(), NextValidatorsHash: next.Hash(), DataHash: root,
		AppHash: sum("app"), ConsensusHash: sum("cons"), LastResultsHash: sum("res"),
		ProposerAddress: vs.Validators[0].Address,
	}
	signKeys := c.keys(h)
	if o.forged {
		signKeys = c.pool[poolSize-window:]
	}
	bid := types.BlockID{Hash: hdr.Hash(), PartSetHeader: types.PartSetHeader{Total: 1, Hash: sum("parts")}}
	n := o.signers
	if n == 0 {
		n = len(signKeys)
	}
	sigs := make([]types.CommitSig, len(vs.Validators))
	for i := range sigs {
		sigs[i] = types.NewCommitSigAbsent()
	}
	for i, k := range signKeys[:n] {
		idx, _ := vs.GetByAddress(k.PubKey().Address())
		if o.forged {
			idx = int32(i)
		}
		v := &types.Vote{
			ValidatorAddress: k.PubKey().Address(), ValidatorIndex: idx, Height: h, Round: 1,
			Timestamp: bt, Type: cmtproto.PrecommitType, BlockID: bid,
		}
		pv := v.ToProto()
		sig, err := k.Sign(types.VoteSignBytes(id, pv))
		require.NoError(t, err)
		v.Signature = sig
		v.ExtensionSignature, err = k.Sign(types.VoteExtensionSignBytes(id, pv))
		require.NoError(t, err)
		cs := v.CommitSig()
		if i < o.badSigs {
			cs.Signature = bytes.Clone(cs.Signature)
			cs.Signature[0] ^= 0xff
		}
		sigs[idx] = cs
	}
	if o.swapRoot != nil {
		hdr.DataHash = o.swapRoot
	}
	return &types.LightBlock{
		SignedHeader: &types.SignedHeader{Header: hdr, Commit: &types.Commit{Height: h, Round: 1, BlockID: bid, Signatures: sigs}},
		ValidatorSet: vs,
	}
}

// fakeProvider serves light blocks from a function; height 0 means latest.
type fakeProvider struct {
	id     string
	latest int64
	get    func(h int64) *types.LightBlock
	calls  []int64
	panics bool
}

func (p *fakeProvider) ChainID() string { return p.id }

func (p *fakeProvider) LightBlock(_ context.Context, h int64) (*types.LightBlock, error) {
	if p.panics {
		panic("provider exploded")
	}
	if h == 0 {
		h = p.latest
	}
	p.calls = append(p.calls, h)
	if h > p.latest {
		return nil, provider.ErrHeightTooHigh
	}
	b := p.get(h)
	if b == nil {
		return nil, provider.ErrLightBlockNotFound
	}
	return b, nil
}

func (p *fakeProvider) ReportEvidence(context.Context, types.Evidence) error { return nil }

// honest serves c's honest blocks up to latest.
func honest(t testing.TB, c *testChain, latest int64) *fakeProvider {
	return &fakeProvider{id: chainID, latest: latest, get: func(h int64) *types.LightBlock { return c.block(t, h, blockOpts{}) }}
}

// override serves honest blocks except at height at, where it serves o.
func override(t testing.TB, c *testChain, latest, at int64, o blockOpts) *fakeProvider {
	return &fakeProvider{id: chainID, latest: latest, get: func(h int64) *types.LightBlock {
		if h == at {
			return c.block(t, h, o)
		}
		return c.block(t, h, blockOpts{})
	}}
}

// fakeProof checks the root and commitment it is asked to verify.
type fakeProof struct {
	wantRoot, wantCommitment []byte
	panics                   bool
	gotRoot, gotCommitment   []byte
}

func (p *fakeProof) Verify(dataRoot, commitment []byte) error {
	if p.panics {
		panic("proof exploded")
	}
	p.gotRoot, p.gotCommitment = dataRoot, commitment
	if !bytes.Equal(dataRoot, p.wantRoot) || !bytes.Equal(commitment, p.wantCommitment) {
		return errors.New("fakeProof: does not verify")
	}
	return nil
}

// proofChain is a bridge node holding a proof for the blob at height h
// against root.
func proofChain(h uint64, root []byte) (*nodefake.Chain, *fakeProof) {
	c := nodefake.NewChain(bytes.Repeat([]byte{9}, 20))
	p := &fakeProof{wantRoot: root, wantCommitment: comm}
	c.AddBlob(h, node.Blob{Namespace: ns, Commitment: comm}, p)
	return c, p
}

func nodeHeader(h int64) node.Header {
	return node.Header{ChainID: chainID, Height: uint64(h), Time: blockTime(h), DataRoot: dataRootAt(h)}
}
