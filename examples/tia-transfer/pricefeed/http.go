package pricefeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxBody        = 1 << 20
	requestTimeout = 10 * time.Second
)

// ErrFeed means the source answered with something unusable.
var ErrFeed = errors.New("pricefeed: unusable answer")

func get(ctx context.Context, c *http.Client, u string) ([]byte, error) {
	if c == nil {
		c = &http.Client{Timeout: requestTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("pricefeed: request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pricefeed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrFeed, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("pricefeed: read: %w", err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("%w: body too large", ErrFeed)
	}
	return b, nil
}

// decode reads JSON keeping numbers as text, so no value passes through a
// float, and refuses trailing data.
func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrFeed, err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrFeed)
	}
	return nil
}

func unixNow() uint64 {
	t := time.Now().Unix()
	if t < 0 {
		return 0
	}
	return uint64(t)
}

type coinGecko struct {
	base, asset, quote string
	c                  *http.Client
}

// NewCoinGecko reads the simple price endpoint under baseURL, for example
// "https://api.coingecko.com/api/v3". quote is an upper-case currency such
// as "USD". A nil client gets a 10 second timeout.
func NewCoinGecko(baseURL, assetID, quote string, c *http.Client) Feed {
	return &coinGecko{base: strings.TrimRight(baseURL, "/"), asset: assetID, quote: quote, c: c}
}

func (g *coinGecko) Observe(ctx context.Context) (Observation, error) {
	q := url.Values{}
	q.Set("ids", g.asset)
	q.Set("vs_currencies", strings.ToLower(g.quote))
	q.Set("include_last_updated_at", "true")
	b, err := get(ctx, g.c, g.base+"/simple/price?"+q.Encode())
	if err != nil {
		return Observation{}, err
	}
	fetched := unixNow()
	var ans map[string]map[string]json.Number
	if err := decode(b, &ans); err != nil {
		return Observation{}, err
	}
	row, ok := ans[g.asset]
	if !ok {
		return Observation{}, fmt.Errorf("%w: no entry for %q", ErrFeed, g.asset)
	}
	text, ok := row[strings.ToLower(g.quote)]
	if !ok {
		return Observation{}, fmt.Errorf("%w: no %s price", ErrFeed, g.quote)
	}
	price, err := ParseDecimal(text.String())
	if err != nil {
		return Observation{}, err
	}
	observed := fetched
	if lu, ok := row["last_updated_at"]; ok {
		u, err := strconv.ParseUint(lu.String(), 10, 63)
		if err != nil || u == 0 {
			return Observation{}, fmt.Errorf("%w: last_updated_at", ErrFeed)
		}
		observed = u
	}
	return Observation{
		Source: "coingecko:" + g.asset, AssetID: g.asset, Quote: g.quote,
		Price: price, ObservedAt: observed, FetchedAt: fetched,
	}, nil
}

type kraken struct {
	base, pair string
	c          *http.Client
}

// NewKraken reads the last trade price of pair, for example "TIAUSD", from
// the ticker endpoint under baseURL ("https://api.kraken.com"). The pair
// ends in a three-letter quote currency. A nil client gets a 10 second
// timeout.
func NewKraken(baseURL, pair string, c *http.Client) Feed {
	return &kraken{base: strings.TrimRight(baseURL, "/"), pair: pair, c: c}
}

func (k *kraken) Observe(ctx context.Context) (Observation, error) {
	if len(k.pair) < 4 {
		return Observation{}, fmt.Errorf("%w: pair %q", ErrFeed, k.pair)
	}
	b, err := get(ctx, k.c, k.base+"/0/public/Ticker?pair="+url.QueryEscape(k.pair))
	if err != nil {
		return Observation{}, err
	}
	fetched := unixNow()
	var ans struct {
		Error  []string `json:"error"`
		Result map[string]struct {
			C []string `json:"c"`
		} `json:"result"`
	}
	if err := decode(b, &ans); err != nil {
		return Observation{}, err
	}
	if len(ans.Error) > 0 {
		return Observation{}, fmt.Errorf("%w: %s", ErrFeed, strings.Join(ans.Error, "; "))
	}
	if len(ans.Result) != 1 {
		return Observation{}, fmt.Errorf("%w: %d tickers", ErrFeed, len(ans.Result))
	}
	for _, t := range ans.Result {
		if len(t.C) < 1 {
			return Observation{}, fmt.Errorf("%w: no last trade", ErrFeed)
		}
		price, err := ParseDecimal(t.C[0])
		if err != nil {
			return Observation{}, err
		}
		n := len(k.pair) - 3
		return Observation{
			Source: "kraken:" + k.pair, AssetID: k.pair[:n], Quote: k.pair[n:],
			Price: price, ObservedAt: fetched, FetchedAt: fetched,
		}, nil
	}
	return Observation{}, fmt.Errorf("%w: no ticker", ErrFeed)
}
