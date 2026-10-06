package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/celestiaorg/celestia-node/header"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
)

// Two Mocha blocks with PayForFibre txs: the one the certificate vectors use
// and a later one from the probe's height list.
var liveHeights = []uint64{1402819, 1439696}

const maxResponse = 64 << 20

type liveInput struct {
	Source liveSource
	Raw    []liveRaw
}

type liveSource struct {
	FetchedAt string       `json:"fetched_at"`
	Note      string       `json:"note"`
	Reads     []sourceRead `json:"reads"`
}

type sourceRead struct {
	What     string `json:"what"`
	Endpoint string `json:"endpoint"`
	AtHeight string `json:"at_height"`
	Echoed   string `json:"echoed_height"`
	DataHash string `json:"data_hash,omitempty"`
}

type liveRaw struct {
	Height           string   `json:"height"`
	DataHash         string   `json:"data_hash"`
	RowRoots         []string `json:"row_roots"`
	ColumnRoots      []string `json:"column_roots"`
	NamespaceDataHex string   `json:"namespace_data_hex"`
}

func httpBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, fmt.Errorf("response above %d bytes", maxResponse)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, b)
	}
	return b, nil
}

func bridgeCall(c *http.Client, url, method, params string) (json.RawMessage, error) {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params)
	resp, err := c.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	b, err := httpBody(resp)
	if err != nil {
		return nil, err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, fmt.Errorf("%s: %s", method, env.Error)
	}
	return env.Result, nil
}

func consensusDataHash(c *http.Client, rpc string, height uint64) (uint64, string, error) {
	resp, err := c.Get(fmt.Sprintf("%s/header?height=%d", rpc, height))
	if err != nil {
		return 0, "", err
	}
	b, err := httpBody(resp)
	if err != nil {
		return 0, "", err
	}
	var env struct {
		Result struct {
			Header struct {
				Height   string `json:"height"`
				DataHash string `json:"data_hash"`
			} `json:"header"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return 0, "", err
	}
	h, err := strconv.ParseUint(env.Result.Header.Height, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("consensus header height: %w", err)
	}
	return h, strings.ToLower(env.Result.Header.DataHash), nil
}

func fetch(bridge, rpc string, heights []uint64) (liveInput, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	in := liveInput{Source: liveSource{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Note: "Read-only. DAH and namespace data from the bridge (header.GetByHeight, share.GetNamespaceData for " +
			"PayForFibreNamespace); data_hash cross-checked against the consensus node's header at the same height.",
	}}
	ns := libshare.PayForFibreNamespace
	for _, h := range heights {
		res, err := bridgeCall(c, bridge, "header.GetByHeight", fmt.Sprintf("[%d]", h))
		if err != nil {
			return in, err
		}
		var eh header.ExtendedHeader
		if err := json.Unmarshal(res, &eh); err != nil {
			return in, fmt.Errorf("header %d: %w", h, err)
		}
		if eh.Height() != h {
			return in, fmt.Errorf("bridge header: asked %d, got %d", h, eh.Height())
		}
		if eh.DAH == nil || !bytes.Equal(eh.DAH.Hash(), eh.DataHash) {
			return in, fmt.Errorf("bridge header %d: DAH does not hash to data_hash", h)
		}
		ch, cdh, err := consensusDataHash(c, rpc, h)
		if err != nil {
			return in, fmt.Errorf("consensus header %d: %w", h, err)
		}
		if ch != h || cdh != hex.EncodeToString(eh.DataHash) {
			return in, fmt.Errorf("consensus header %d: height %d data_hash %s, bridge %x", h, ch, cdh, eh.DataHash)
		}

		res, err = bridgeCall(c, bridge, "share.GetNamespaceData",
			fmt.Sprintf(`[%d,%q]`, h, base64.StdEncoding.EncodeToString(ns.Bytes())))
		if err != nil {
			return in, err
		}
		var nd shwap.NamespaceData
		if err := json.Unmarshal(res, &nd); err != nil {
			return in, fmt.Errorf("namespace data %d: %w", h, err)
		}
		var stream bytes.Buffer
		if _, err := nd.WriteTo(&stream); err != nil {
			return in, err
		}

		r := liveRaw{
			Height:           strconv.FormatUint(h, 10),
			DataHash:         hex.EncodeToString(eh.DataHash),
			NamespaceDataHex: hex.EncodeToString(stream.Bytes()),
		}
		for _, x := range eh.DAH.RowRoots {
			r.RowRoots = append(r.RowRoots, hex.EncodeToString(x))
		}
		for _, x := range eh.DAH.ColumnRoots {
			r.ColumnRoots = append(r.ColumnRoots, hex.EncodeToString(x))
		}
		in.Raw = append(in.Raw, r)
		hs := strconv.FormatUint(h, 10)
		in.Source.Reads = append(in.Source.Reads,
			sourceRead{What: "header.GetByHeight (DAH)", Endpoint: bridge, AtHeight: hs, Echoed: strconv.FormatUint(eh.Height(), 10), DataHash: r.DataHash},
			sourceRead{What: "share.GetNamespaceData (PayForFibreNamespace)", Endpoint: bridge, AtHeight: hs, Echoed: "none (verified against the DAH)"},
			sourceRead{What: "CometBFT /header (data_hash cross-check)", Endpoint: rpc, AtHeight: hs, Echoed: strconv.FormatUint(ch, 10), DataHash: cdh},
		)
	}
	return in, nil
}
