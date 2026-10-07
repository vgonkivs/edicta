package railverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/verifier"
)

type bankSend struct {
	cfg     Config
	primary TxSource
	headers headertrust.HeaderChain
	cross   []TxSource
}

// NewBankSend returns the checker of the bank-send profile. headers is the
// chain the verifier walks, so the header read here is the one header trust
// then checks. A cross source on the primary's host, or two on one host, is
// refused: they would not be independent.
func NewBankSend(cfg Config, primary TxSource, headers headertrust.HeaderChain, cross []TxSource) (verifier.ExecutionChecker, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if primary == nil {
		return nil, errors.New("railverify: no primary source")
	}
	if headers == nil {
		return nil, errors.New("railverify: no header chain")
	}
	seen := map[string]bool{primary.Name(): true}
	for _, c := range cross {
		if c == nil {
			return nil, errors.New("railverify: nil cross source")
		}
		if seen[c.Name()] {
			return nil, fmt.Errorf("railverify: cross source %q repeats another source", c.Name())
		}
		seen[c.Name()] = true
	}
	return &bankSend{cfg: cfg, primary: primary, headers: headers, cross: append([]TxSource(nil), cross...)}, nil
}

func parseLowerHex32(s string) ([32]byte, bool) {
	var out [32]byte
	if len(s) != 64 {
		return out, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return out, false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// bodyOfTxRaw returns body_bytes of a TxRaw that has fields 1 and 2 once
// each, then field 3 at least once, all length-delimited with shortest
// varints, and nothing else. The chain's own decoder keeps the last of a
// repeated field and accepts any order, so anything looser could show a body
// the chain did not execute.
func bodyOfTxRaw(b []byte) ([]byte, error) {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrTxMalformed, why) }
	next := func(want protowire.Number) ([]byte, bool, error) {
		if len(b) == 0 {
			return nil, false, nil
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, false, bad("tag")
		}
		if num != want {
			return nil, false, nil
		}
		if typ != protowire.BytesType {
			return nil, false, bad("wire type")
		}
		if n != 1 {
			return nil, false, bad("tag form")
		}
		rest := b[n:]
		l, ln := protowire.ConsumeVarint(rest)
		if ln < 0 {
			return nil, false, bad("length")
		}
		if ln != protowire.SizeVarint(l) {
			return nil, false, bad("length is not shortest")
		}
		rest = rest[ln:]
		if uint64(len(rest)) < l {
			return nil, false, bad("truncated")
		}
		v := rest[:l]
		b = rest[l:]
		return v, true, nil
	}
	body, ok, err := next(1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, bad("no body_bytes")
	}
	if _, ok, err = next(2); err != nil {
		return nil, err
	} else if !ok {
		return nil, bad("no auth_info_bytes")
	}
	sigs := 0
	for {
		_, ok, err := next(3)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		sigs++
	}
	if sigs == 0 {
		return nil, bad("no signature")
	}
	if len(b) != 0 {
		return nil, bad("trailing or out-of-order data")
	}
	return body, nil
}

func unchecked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", verifier.ErrExecutionUnchecked, fmt.Sprintf(format, a...))
}

// CheckExecution runs the profile's rules in order: lookup, hash, TxRaw,
// chain, body, inclusion, code, cross sources.
func (c *bankSend) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	none := verifier.ExecutionFacts{}
	ref, ok := parseLowerHex32(in.RailRef)
	if !ok {
		return none, fmt.Errorf("%w: rail_ref is not 64 lower-case hex characters", ErrTxHashMismatch)
	}
	tx, err := c.primary.Tx(ctx, ref, true)
	if err != nil {
		if errors.Is(err, verifier.ErrExecutionUnchecked) {
			return none, err
		}
		return none, fmt.Errorf("%w: %w", ErrTxSourceUnavailable, err)
	}
	if sha256.Sum256(tx.Bytes) != ref {
		return none, ErrTxHashMismatch
	}
	body, err := bodyOfTxRaw(tx.Bytes)
	if err != nil {
		return none, err
	}

	act, err := bankaction.Decode(in.Action)
	if err != nil {
		return none, err
	}
	if act.ChainID != c.cfg.ChainID {
		return none, fmt.Errorf("%w: the action names %q, the checker is set to %q", ErrChainMismatch, act.ChainID, c.cfg.ChainID)
	}
	rawHdr, err := c.headers.Header(ctx, tx.Height)
	if err != nil {
		return none, unchecked("header %d: %v", tx.Height, err)
	}
	var ph cmtproto.Header
	if err := ph.Unmarshal(rawHdr); err != nil {
		return none, unchecked("header %d: %v", tx.Height, err)
	}
	hdr, err := core.HeaderFromProto(&ph)
	if err != nil || hdr.Height < 1 || uint64(hdr.Height) != tx.Height {
		return none, unchecked("header %d is unusable", tx.Height)
	}
	if hdr.ChainID != act.ChainID {
		return none, fmt.Errorf("%w: the action names %q, the chain has %q", ErrChainMismatch, act.ChainID, hdr.ChainID)
	}

	if _, err := bankaction.CheckBody(act, in.CommitmentHash, body); err != nil {
		return none, err
	}
	inclusion := "node-attested"
	if len(tx.Proof) > 0 {
		if err := VerifyShareProof(tx.Proof, tx.Bytes, hdr.DataHash); err != nil {
			return none, err
		}
		inclusion = "proven"
	}
	if tx.Code != 0 {
		return none, fmt.Errorf("%w: code %d", ErrTxFailed, tx.Code)
	}

	f := verifier.ExecutionFacts{
		Height: tx.Height, HeaderHash: hdr.Hash(), BlockTime: uint64(hdr.Time.Unix()),
		Inclusion: inclusion, Result: "node-attested", CrossCheck: "off", Sources: []string{c.primary.Name()},
	}
	if len(c.cross) == 0 {
		return f, nil
	}
	f.CrossCheck = "pass"
	for _, s := range c.cross {
		f.Sources = append(f.Sources, s.Name())
		other, err := s.Tx(ctx, ref, false)
		switch {
		case f.CrossCheck == "mismatch":
		case err != nil:
			f.CrossCheck = "unavailable"
		case other.Height != tx.Height || other.Code != tx.Code || !bytes.Equal(other.Bytes, tx.Bytes):
			f.CrossCheck = "mismatch"
		}
	}
	return f, nil
}
