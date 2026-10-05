package pricefeed_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

// Kraken: observed_at is the source's own timestamp, or the call errors. Any
// endpoint that carries a time (Trades, OHLC) will do; the ticker carries none.

const krakenTime = uint64(1791000000)

func krakenServer(t *testing.T, ticker, trades, ohlc string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "Ticker"):
			_, _ = w.Write([]byte(ticker))
		case strings.Contains(r.URL.Path, "Trades"):
			_, _ = w.Write([]byte(trades))
		case strings.Contains(r.URL.Path, "OHLC"):
			_, _ = w.Write([]byte(ohlc))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func observeKraken(t *testing.T, s *httptest.Server) (pricefeed.Observation, error) {
	t.Helper()
	f, err := pricefeed.NewKraken(s.URL, "TIAUSD", "celestia", "USD", s.Client())
	require.NoError(t, err)
	return f.Observe(bg)
}

func TestKrakenWithoutASourceTimestampIsAnError(t *testing.T) {
	const ticker = `{"error":[],"result":{"TIAUSD":{"c":["4.1234","1.0"]}}}`
	s := krakenServer(t, ticker, `{"error":["EGeneral:Internal error"],"result":{}}`, `{"error":["EGeneral:Internal error"],"result":{}}`)
	got, err := observeKraken(t, s)
	require.Error(t, err, "a ticker has no time; the fetch time must not stand in for it, got %+v", got)
	require.ErrorIs(t, err, pricefeed.ErrFeed)
}

func TestKrakenUsesTheSourceTimestamp(t *testing.T) {
	const (
		ticker = `{"error":[],"result":{"TIAUSD":{"c":["4.1234","1.0"]}}}`
		trades = `{"error":[],"result":{"TIAUSD":[["4.1234","1.0",1791000000.1234,"b","l",""]],"last":"1791000000123400000"}}`
		ohlc   = `{"error":[],"result":{"TIAUSD":[[1791000000,"4.0","4.2","3.9","4.1234","4.1","10.0",5]],"last":1791000000}}`
	)
	before := uint64(time.Now().Unix())
	s := krakenServer(t, ticker, trades, ohlc)
	got, err := observeKraken(t, s)
	require.NoError(t, err)
	assert.Equal(t, krakenTime, got.ObservedAt, "the source's time")
	assert.NotEqual(t, got.FetchedAt, got.ObservedAt, "never the fetch time unless the source says so")
	assert.GreaterOrEqual(t, got.FetchedAt, before)
	assert.Equal(t, uint64(4_12340000), got.Price)
}
