package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/verifier"
)

// maxTrustedFile bounds the trusted header file.
const maxTrustedFile = 64 << 20

// trustedFile is the auditor's trusted header: one header and its hash,
// obtained out of band, plus any headers between it and the heights the
// archive needs. The bundled headers are untrusted; the hash chain checks them.
type trustedFile struct {
	Height  uint64   `json:"height"`
	Hash    string   `json:"hash"`
	Header  string   `json:"header"`
	Headers []string `json:"headers"`
}

// bundle serves the bundled headers by their own height.
type bundle map[uint64][]byte

func (b bundle) Header(_ context.Context, height uint64) ([]byte, error) {
	raw, ok := b[height]
	if !ok {
		return nil, fmt.Errorf("the trusted header file has no header at height %d", height)
	}
	return bytes.Clone(raw), nil
}

func loadTrusted(path string) (verifier.HeaderTrust, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("trusted header file: %w", err)
	}
	if st.Size() > maxTrustedFile {
		return nil, fmt.Errorf("trusted header file: %d bytes is too large", st.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trusted header file: %w", err)
	}
	var f trustedFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("trusted header file: %w", err)
	}
	hash, err := hex.DecodeString(f.Hash)
	if err != nil || len(hash) == 0 {
		return nil, errors.New("trusted header file: hash is not hex")
	}
	header, err := hex.DecodeString(f.Header)
	if err != nil || len(header) == 0 {
		return nil, errors.New("trusted header file: header is not hex")
	}
	if f.Height == 0 {
		return nil, errors.New("trusted header file: height is missing")
	}
	chain := make(bundle, len(f.Headers))
	for i, s := range f.Headers {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("trusted header file: headers[%d] is not hex", i)
		}
		var ph cmtproto.Header
		if err := ph.Unmarshal(b); err != nil || ph.Height < 1 {
			return nil, fmt.Errorf("trusted header file: headers[%d] is not a header", i)
		}
		if _, dup := chain[uint64(ph.Height)]; dup {
			return nil, fmt.Errorf("trusted header file: two headers at height %d", ph.Height)
		}
		chain[uint64(ph.Height)] = b
	}
	cp := headertrust.Checkpoint{Height: f.Height, Hash: hash, Header: header}
	return headertrust.New(cp, chain, nil), nil
}
