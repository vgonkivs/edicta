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

// ErrInvalidConfig means a feed constructor refused its arguments.
var ErrInvalidConfig = errors.New("pricefeed: invalid configuration")

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
	lu, ok := row["last_updated_at"]
	if !ok {
		return Observation{}, fmt.Errorf("%w: no last_updated_at", ErrFeed)
	}
	observed, err := strconv.ParseUint(lu.String(), 10, 63)
	if err != nil || observed == 0 {
		return Observation{}, fmt.Errorf("%w: last_updated_at", ErrFeed)
	}
	return Observation{
		Source: "coingecko:" + g.asset, AssetID: g.asset, Quote: g.quote,
		Price: price, ObservedAt: observed, FetchedAt: fetched,
	}, nil
}

type kraken struct {
	base, pair, asset, quote string
	c                        *http.Client
}

// NewKraken reads the last trade of pair, for example "TIAUSD", from the
// trades endpoint under baseURL ("https://api.kraken.com"); the observation
// time is that trade's own time. When trades are unusable the latest candle
// is read instead, with the candle's time. The ticker carries no time, so it
// is never a source. assetID and quote name the asset in the payload exactly
// as given; quote is an upper-case currency. A nil client gets a 10 second
// timeout.
func NewKraken(baseURL, pair, assetID, quote string, c *http.Client) (Feed, error) {
	if pair == "" || assetID == "" || quote == "" || quote != strings.ToUpper(quote) {
		return nil, fmt.Errorf("%w: kraken pair, asset id and upper-case quote are required", ErrInvalidConfig)
	}
	return &kraken{base: strings.TrimRight(baseURL, "/"), pair: pair, asset: assetID, quote: quote, c: c}, nil
}

func (k *kraken) Observe(ctx context.Context) (Observation, error) {
	fetched := unixNow()
	// Trades rows: price, volume, time, ...; OHLC rows: time, open, high,
	// low, close, ...
	price, at, err := k.lastRow(ctx, "Trades", 0, 2)
	if err != nil {
		var err2 error
		price, at, err2 = k.lastRow(ctx, "OHLC", 4, 0)
		if err2 != nil {
			return Observation{}, fmt.Errorf("%w: no source timestamp: trades: %v; ohlc: %v", ErrFeed, err, err2)
		}
	}
	return Observation{
		Source: "kraken:" + k.pair, AssetID: k.asset, Quote: k.quote,
		Price: price, ObservedAt: at, FetchedAt: fetched,
	}, nil
}

// lastRow returns the price and the whole-second time of the newest row of a
// Kraken endpoint.
func (k *kraken) lastRow(ctx context.Context, endpoint string, priceIdx, timeIdx int) (price, at uint64, err error) {
	b, err := get(ctx, k.c, k.base+"/0/public/"+endpoint+"?pair="+url.QueryEscape(k.pair))
	if err != nil {
		return 0, 0, err
	}
	var ans struct {
		Error  []string                   `json:"error"`
		Result map[string]json.RawMessage `json:"result"`
	}
	if err := decode(b, &ans); err != nil {
		return 0, 0, err
	}
	if len(ans.Error) > 0 {
		return 0, 0, fmt.Errorf("%w: %s", ErrFeed, strings.Join(ans.Error, "; "))
	}
	var rows [][]any
	for name, raw := range ans.Result {
		if name == "last" {
			continue
		}
		if rows != nil {
			return 0, 0, fmt.Errorf("%w: more than one pair", ErrFeed)
		}
		if err := decode(raw, &rows); err != nil {
			return 0, 0, err
		}
	}
	if len(rows) == 0 {
		return 0, 0, fmt.Errorf("%w: no %s rows", ErrFeed, endpoint)
	}
	row := rows[len(rows)-1]
	if len(row) <= max(priceIdx, timeIdx) {
		return 0, 0, fmt.Errorf("%w: short %s row", ErrFeed, endpoint)
	}
	ps, ok := row[priceIdx].(string)
	if !ok {
		return 0, 0, fmt.Errorf("%w: %s price is not a string", ErrFeed, endpoint)
	}
	if price, err = ParseDecimal(ps); err != nil {
		return 0, 0, err
	}
	tn, ok := row[timeIdx].(json.Number)
	if !ok {
		return 0, 0, fmt.Errorf("%w: %s time is not a number", ErrFeed, endpoint)
	}
	whole, _, _ := strings.Cut(tn.String(), ".")
	if at, err = strconv.ParseUint(whole, 10, 63); err != nil || at == 0 {
		return 0, 0, fmt.Errorf("%w: %s time", ErrFeed, endpoint)
	}
	return price, at, nil
}
