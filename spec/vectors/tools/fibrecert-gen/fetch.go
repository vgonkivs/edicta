package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	"github.com/cosmos/cosmos-sdk/types/query"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// The PFF the 009 research checked offline: one byte 0x65 in namespace
// popsmin1, 73 of 83 validator signatures.
const (
	liveChainID       = "mocha-5"
	livePFFHeight     = 1402819
	liveTxHash        = "63CE1560A08212CDE9B126D57A2FECF59FBF04E0F05DD033BE8918A48839B04E"
	livePromiseHeight = 1402813
	// HistoricalInfo(promise height) is read from the state the block
	// carrying the PFF was proposed on: the keeper checked the certificate
	// against that state in CheckTx and ProcessProposal.
	liveStateHeight = livePFFHeight - 1
	heightHeader    = "x-cosmos-block-height"
	maxGRPCMessage  = 64 << 20
)

type endpoints struct{ quick, pops, guru string }

type liveInput struct {
	Source liveSource
	Raw    liveRaw
}

type liveSource struct {
	FetchedAt string       `json:"fetched_at"`
	Note      string       `json:"note"`
	Reads     []sourceRead `json:"reads"`
}

type sourceRead struct {
	What      string `json:"what"`
	Endpoints string `json:"endpoints"`
	AtHeight  string `json:"at_height,omitempty"`
	Echoed    string `json:"echoed_height,omitempty"`
}

type liveRaw struct {
	ChainID        string      `json:"chain_id"`
	PFFHeight      string      `json:"pff_height"`
	TxHash         string      `json:"tx_hash"`
	TxIndex        string      `json:"tx_index"`
	TxResultCode   string      `json:"tx_result_code"`
	PFFTxHex       string      `json:"pff_tx_hex"`
	HistoricalInfo histRaw     `json:"historical_info"`
	CometValsets   []valsetRaw `json:"cometbft_valsets"`
	Headers        []headerRaw `json:"headers"`
	Trusted        trustedRaw  `json:"trusted_header"`
}

type histRaw struct {
	Height      string `json:"height"`
	StateHeight string `json:"state_height"`
	Hex         string `json:"hex"`
}

type valsetRaw struct {
	Height string `json:"height"`
	Hex    string `json:"hex"`
}

type headerRaw struct {
	Height         string `json:"height"`
	HeaderHex      string `json:"header_hex"`
	BlockIDHashHex string `json:"block_id_hash_hex"`
	CommitHex      string `json:"commit_hex,omitempty"`
}

type trustedRaw struct {
	Height  string `json:"height"`
	HashHex string `json:"hash_hex"`
}

type peer struct {
	name    string
	conn    *grpc.ClientConn
	cmt     cmtservice.ServiceClient
	tx      txtypes.ServiceClient
	staking stakingtypes.QueryClient
}

func dial(name, addr string, useTLS bool) (*peer, error) {
	creds := insecure.NewCredentials()
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGRPCMessage)))
	if err != nil {
		return nil, err
	}
	return &peer{name: name + " " + addr, conn: conn, cmt: cmtservice.NewServiceClient(conn),
		tx: txtypes.NewServiceClient(conn), staking: stakingtypes.NewQueryClient(conn)}, nil
}

type fetchedBlock struct {
	header  []byte
	blockID []byte
	commit  []byte // last_commit of this block, i.e. the commit for height-1
	txs     [][]byte
	propose []byte
}

func getBlock(ctx context.Context, p *peer, h int64) (fetchedBlock, error) {
	r, err := p.cmt.GetBlockByHeight(ctx, &cmtservice.GetBlockByHeightRequest{Height: h})
	if err != nil {
		return fetchedBlock{}, fmt.Errorf("%s: block %d: %w", p.name, h, err)
	}
	if r.Block == nil || r.BlockId == nil || r.Block.Header.Height != h {
		return fetchedBlock{}, fmt.Errorf("%s: block %d: response for another height", p.name, h)
	}
	hb, err := r.Block.Header.Marshal()
	if err != nil {
		return fetchedBlock{}, err
	}
	var cb []byte
	if r.Block.LastCommit != nil {
		if cb, err = r.Block.LastCommit.Marshal(); err != nil {
			return fetchedBlock{}, err
		}
	}
	return fetchedBlock{header: hb, blockID: r.BlockId.Hash, commit: cb, txs: r.Block.Data.Txs,
		propose: r.Block.Header.ProposerAddress}, nil
}

func echoed(md metadata.MD) string {
	if v := md.Get(heightHeader); len(v) == 1 {
		return v[0]
	}
	return ""
}

func getHistorical(ctx context.Context, p *peer) ([]byte, string, error) {
	var md metadata.MD
	at := strconv.Itoa(liveStateHeight)
	r, err := p.staking.HistoricalInfo(metadata.AppendToOutgoingContext(ctx, heightHeader, at),
		&stakingtypes.QueryHistoricalInfoRequest{Height: livePromiseHeight}, grpc.Header(&md))
	if err != nil {
		return nil, "", fmt.Errorf("%s: HistoricalInfo(%d) at %s: %w", p.name, livePromiseHeight, at, err)
	}
	if e := echoed(md); e != at {
		return nil, e, fmt.Errorf("%s: HistoricalInfo: requested height %s, echoed %q: endpoint ignores heights", p.name, at, e)
	}
	if r.Hist == nil || r.Hist.Header.Height != livePromiseHeight {
		return nil, "", fmt.Errorf("%s: HistoricalInfo for another height", p.name)
	}
	b, err := r.Hist.Marshal()
	return b, at, err
}

func getValset(ctx context.Context, p *peer, h int64, proposer []byte) ([]byte, error) {
	r, err := p.cmt.GetValidatorSetByHeight(ctx, &cmtservice.GetValidatorSetByHeightRequest{
		Height: h, Pagination: &query.PageRequest{Limit: 100, CountTotal: true}})
	if err != nil {
		return nil, fmt.Errorf("%s: valset %d: %w", p.name, h, err)
	}
	if r.BlockHeight != h {
		return nil, fmt.Errorf("%s: valset for height %d, asked %d", p.name, r.BlockHeight, h)
	}
	if r.Pagination != nil && r.Pagination.Total != uint64(len(r.Validators)) {
		return nil, fmt.Errorf("%s: valset %d paginated: %d of %d", p.name, h, len(r.Validators), r.Pagination.Total)
	}
	vs := cmtproto.ValidatorSet{}
	for _, v := range r.Validators {
		pk, err := ed25519FromAny(v.PubKey)
		if err != nil {
			return nil, err
		}
		addr := sha256.Sum256(pk)
		val := &cmtproto.Validator{Address: addr[:20],
			PubKey:      cmtcrypto.PublicKey{Sum: &cmtcrypto.PublicKey_Ed25519{Ed25519: pk}},
			VotingPower: v.VotingPower, ProposerPriority: v.ProposerPriority}
		vs.Validators = append(vs.Validators, val)
		vs.TotalVotingPower += v.VotingPower
		if bytes.Equal(addr[:20], proposer) {
			vs.Proposer = val
		}
	}
	if vs.Proposer == nil {
		return nil, fmt.Errorf("%s: valset %d: header proposer not in the set", p.name, h)
	}
	return vs.Marshal()
}

func agree(what string, a, b []byte) error {
	if !bytes.Equal(a, b) {
		return fmt.Errorf("%s: providers disagree", what)
	}
	return nil
}

func fetch(ep endpoints) (liveInput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	quick, err := dial("quicknode", ep.quick, true)
	if err != nil {
		return liveInput{}, err
	}
	defer quick.conn.Close()
	pops, err := dial("p-ops", ep.pops, false)
	if err != nil {
		return liveInput{}, err
	}
	defer pops.conn.Close()
	guru, err := dial("nodes.guru", ep.guru, false)
	if err != nil {
		return liveInput{}, err
	}
	defer guru.conn.Close()

	raw := liveRaw{ChainID: liveChainID, PFFHeight: strconv.Itoa(livePFFHeight), TxHash: liveTxHash}
	src := liveSource{FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Note: "Read-only gRPC reads. Blocks and validator sets carry the height in the request and are compared across providers; HistoricalInfo is a state read pinned with x-cosmos-block-height and used only when the response echoes that height."}

	blocks := map[int64]fetchedBlock{}
	for h := int64(livePromiseHeight); h <= livePFFHeight+1; h++ {
		var got []fetchedBlock
		for _, p := range []*peer{quick, pops} {
			b, err := getBlock(ctx, p, h)
			if err != nil {
				return liveInput{}, err
			}
			got = append(got, b)
		}
		if err := agree(fmt.Sprintf("header %d", h), got[0].header, got[1].header); err != nil {
			return liveInput{}, err
		}
		if err := agree(fmt.Sprintf("block id %d", h), got[0].blockID, got[1].blockID); err != nil {
			return liveInput{}, err
		}
		if err := agree(fmt.Sprintf("last commit %d", h), got[0].commit, got[1].commit); err != nil {
			return liveInput{}, err
		}
		blocks[h] = got[0]
	}
	src.Reads = append(src.Reads, sourceRead{What: fmt.Sprintf("GetBlockByHeight %d..%d (headers, block ids, last commits, txs of %d)", livePromiseHeight, livePFFHeight+1, livePFFHeight),
		Endpoints: quick.name + "; " + pops.name})

	for h := int64(livePromiseHeight); h <= livePFFHeight; h++ {
		hr := headerRaw{Height: strconv.FormatInt(h, 10), HeaderHex: hex.EncodeToString(blocks[h].header),
			BlockIDHashHex: hex.EncodeToString(blocks[h].blockID)}
		if h == livePromiseHeight || h == livePromiseHeight+1 || h == livePFFHeight {
			hr.CommitHex = hex.EncodeToString(blocks[h+1].commit)
		}
		raw.Headers = append(raw.Headers, hr)
	}
	raw.Trusted = trustedRaw{Height: strconv.Itoa(livePFFHeight), HashHex: hex.EncodeToString(blocks[livePFFHeight].blockID)}

	want, err := hex.DecodeString(liveTxHash)
	if err != nil {
		return liveInput{}, err
	}
	found := -1
	for i, tx := range blocks[livePFFHeight].txs {
		if s := sha256.Sum256(tx); bytes.Equal(s[:], want) {
			if found >= 0 {
				return liveInput{}, errors.New("PFF tx appears twice in its block")
			}
			found = i
		}
	}
	if found < 0 {
		return liveInput{}, fmt.Errorf("tx %s not in block %d", liveTxHash, livePFFHeight)
	}
	raw.TxIndex = strconv.Itoa(found)
	raw.PFFTxHex = hex.EncodeToString(blocks[livePFFHeight].txs[found])

	var codes []uint32
	for _, p := range []*peer{quick, pops} {
		r, err := p.tx.GetTx(ctx, &txtypes.GetTxRequest{Hash: liveTxHash})
		if err != nil {
			return liveInput{}, fmt.Errorf("%s: GetTx: %w", p.name, err)
		}
		if r.TxResponse == nil || r.TxResponse.Height != livePFFHeight || !strings.EqualFold(r.TxResponse.TxHash, liveTxHash) {
			return liveInput{}, fmt.Errorf("%s: GetTx: wrong height or hash", p.name)
		}
		codes = append(codes, r.TxResponse.Code)
	}
	if codes[0] != codes[1] {
		return liveInput{}, errors.New("GetTx: providers disagree on the result code")
	}
	raw.TxResultCode = strconv.FormatUint(uint64(codes[0]), 10)
	src.Reads = append(src.Reads, sourceRead{What: "GetTx " + liveTxHash + " (result code and height)",
		Endpoints: quick.name + "; " + pops.name})

	var hist [][]byte
	for _, p := range []*peer{pops, guru} {
		b, e, err := getHistorical(ctx, p)
		if err != nil {
			return liveInput{}, err
		}
		hist = append(hist, b)
		src.Reads = append(src.Reads, sourceRead{What: fmt.Sprintf("staking HistoricalInfo(%d)", livePromiseHeight),
			Endpoints: p.name, AtHeight: strconv.Itoa(liveStateHeight), Echoed: e})
	}
	if err := agree("HistoricalInfo", hist[0], hist[1]); err != nil {
		return liveInput{}, err
	}
	raw.HistoricalInfo = histRaw{Height: strconv.Itoa(livePromiseHeight), StateHeight: strconv.Itoa(liveStateHeight),
		Hex: hex.EncodeToString(hist[0])}

	for _, h := range []int64{livePromiseHeight, livePromiseHeight + 1} {
		var got [][]byte
		for _, p := range []*peer{quick, pops} {
			b, err := getValset(ctx, p, h, blocks[h].propose)
			if err != nil {
				return liveInput{}, err
			}
			got = append(got, b)
		}
		if err := agree(fmt.Sprintf("valset %d", h), got[0], got[1]); err != nil {
			return liveInput{}, err
		}
		raw.CometValsets = append(raw.CometValsets, valsetRaw{Height: strconv.FormatInt(h, 10), Hex: hex.EncodeToString(got[0])})
	}
	src.Reads = append(src.Reads, sourceRead{What: fmt.Sprintf("GetValidatorSetByHeight %d and %d (proposer from the header at the same height)", livePromiseHeight, livePromiseHeight+1),
		Endpoints: quick.name + "; " + pops.name})

	return liveInput{Source: src, Raw: raw}, nil
}
