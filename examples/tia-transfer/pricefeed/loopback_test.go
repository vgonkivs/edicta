package pricefeed_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
)

func loopback(t *testing.T, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestCoinGeckoWithoutObservationTimeIsAnError(t *testing.T) {
	s := loopback(t, `{"celestia":{"usd":4.12345678}}`)
	_, err := pricefeed.NewCoinGecko(s.URL, "celestia", "USD", s.Client()).Observe(bg)
	require.ErrorIs(t, err, pricefeed.ErrFeed, "no fabricated observed_at")
}

func TestCoinGeckoKeepsTheReportedObservationTime(t *testing.T) {
	s := loopback(t, `{"celestia":{"usd":4.12345678,"last_updated_at":1791000000}}`)
	got, err := pricefeed.NewCoinGecko(s.URL, "celestia", "USD", s.Client()).Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, uint64(1791000000), got.ObservedAt)
	assert.Equal(t, uint64(4_12345678), got.Price)
}

func TestKrakenIdentityComesFromConfig(t *testing.T) {
	s := loopback(t, `{"error":[],"result":{"TIAUSD":{"c":["4.1234","1.0"]}}}`)

	f, err := pricefeed.NewKraken(s.URL, "TIAUSD", "celestia", "USD", s.Client())
	require.NoError(t, err)
	got, err := f.Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, "celestia", got.AssetID)
	assert.Equal(t, "USD", got.Quote)

	f, err = pricefeed.NewKraken(s.URL, "TIAUSD", "tia-custom", "EUR", s.Client())
	require.NoError(t, err)
	got, err = f.Observe(bg)
	require.NoError(t, err)
	assert.Equal(t, "tia-custom", got.AssetID, "never derived from the pair name")
	assert.Equal(t, "EUR", got.Quote)
}

func TestKrakenConfigWithoutIdentityIsInvalid(t *testing.T) {
	for _, c := range [][2]string{{"", "USD"}, {"celestia", ""}, {"", ""}, {"celestia", "usd"}} {
		_, err := pricefeed.NewKraken("http://127.0.0.1:1", "TIAUSD", c[0], c[1], nil)
		require.ErrorIs(t, err, pricefeed.ErrInvalidConfig, "%q %q", c[0], c[1])
	}
}
