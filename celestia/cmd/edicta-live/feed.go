package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

// Public price sources; the base URLs can be overridden with --price-base-url.
const (
	defaultCoinGeckoBase = "https://api.coingecko.com/api/v3"
	defaultKrakenBase    = "https://api.kraken.com"
)

// newFeed builds the real price feed. There is no fake: a live run reads a
// public source or does not run.
func newFeed(c Config) (pricefeed.Feed, error) {
	hc := &http.Client{Timeout: 15 * time.Second}
	switch c.PriceSource {
	case "coingecko":
		base := c.PriceBaseURL
		if base == "" {
			base = defaultCoinGeckoBase
		}
		return pricefeed.NewCoinGecko(base, c.PriceAsset, c.PriceQuote, hc), nil
	case "kraken":
		base := c.PriceBaseURL
		if base == "" {
			base = defaultKrakenBase
		}
		return pricefeed.NewKraken(base, c.KrakenPair, c.PriceAsset, c.PriceQuote, hc)
	}
	return nil, cfgErr("price source %q", c.PriceSource)
}

// loggingFeed reports every reading, so the human sees the baseline and the move.
type loggingFeed struct {
	inner pricefeed.Feed
	logf  func(string, ...any)
}

func (f loggingFeed) Observe(ctx context.Context) (pricefeed.Observation, error) {
	o, err := f.inner.Observe(ctx)
	if err != nil {
		f.logf("price read failed: %v", err)
		return o, err
	}
	f.logf("price %s = %s %s", o.Source, fmtPrice(o.Price), o.Quote)
	return o, nil
}

// fmtPrice renders a 1e8-scaled price without a float.
func fmtPrice(p uint64) string { return fmt.Sprintf("%d.%08d", p/100_000_000, p%100_000_000) }
