//go:build pricefeed

package pricefeed_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

func serve(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestCoinGeckoParsesWithoutFloats(t *testing.T) {
	s := serve(t, `{"celestia":{"usd":4.12345678,"last_updated_at":1791000000}}`)
	before := uint64(time.Now().Unix())
	got, err := pricefeed.NewCoinGecko(s.URL, "celestia", "USD", s.Client()).Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, uint64(4_12345678), got.Price)
	assert.Equal(t, "celestia", got.AssetID)
	assert.Equal(t, "USD", got.Quote)
	assert.GreaterOrEqual(t, got.FetchedAt, before)
}

func krakenObserve(t *testing.T, s *httptest.Server) (pricefeed.Observation, error) {
	t.Helper()
	f, err := pricefeed.NewKraken(s.URL, "TIAUSD", "celestia", "USD", s.Client())
	require.NoError(t, err)
	return f.Observe(bg)
}

func TestKrakenParsesWithoutFloats(t *testing.T) {
	// observed_at is the source's time (Trades or OHLC); a ticker carries none.
	s := krakenServer(t,
		`{"error":[],"result":{"TIAUSD":{"c":["4.1234","1.0"]}}}`,
		`{"error":[],"result":{"TIAUSD":[["4.1234","1.0",1791000000.1234,"b","l",""]],"last":"1791000000123400000"}}`,
		`{"error":[],"result":{"TIAUSD":[[1791000000,"4.0","4.2","3.9","4.1234","4.1","10.0",5]],"last":1791000000}}`)
	got, err := krakenObserve(t, s)
	require.NoError(t, err)
	assert.Equal(t, uint64(4_12340000), got.Price)
	assert.Equal(t, krakenTime, got.ObservedAt, "the source's time, not the fetch time")
	assert.NotEmpty(t, got.Source)

	_, err = krakenObserve(t, serve(t, `{"error":[],"result":{"TIAUSD":{"c":["4.1234","1.0"]}}}`))
	assert.Error(t, err, "ticker-only has no source timestamp")
}

func TestFeedsRefuseBadAnswers(t *testing.T) {
	for _, body := range []string{`{}`, `not json`, `{"celestia":{"usd":0}}`, `{"celestia":{"usd":-1}}`, `{"error":["EQuery:Unknown asset pair"],"result":{}}`} {
		s := serve(t, body)
		_, err := pricefeed.NewCoinGecko(s.URL, "celestia", "USD", s.Client()).Observe(bg)
		assert.Error(t, err, body)
		_, err = krakenObserve(t, s)
		assert.Error(t, err, body)
	}
}
