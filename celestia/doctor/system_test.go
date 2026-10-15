package doctor_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/doctor"
	"github.com/vgonkivs/edicta/celestia/node"
)

func TestSystemEVM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "eth_chainId":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x14a34"}`))
		case "eth_call":
			call := req.Params[0].(map[string]any)
			if call["data"] != "0x70a08231000000000000000000000000000000000000000000000000000000000000dead" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"bad data"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x2faf080"}`))
		}
	}))
	defer srv.Close()
	e := doctor.SystemEVM{}
	id, err := e.ChainID(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, uint64(84532), id)
	bal, err := e.USDCBalance(context.Background(), srv.URL, "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "0x000000000000000000000000000000000000dEaD")
	require.NoError(t, err)
	assert.Equal(t, "50000000", bal.String())
	_, err = e.USDCBalance(context.Background(), srv.URL, "0x0", "0x12")
	require.Error(t, err)
}

func TestSystemNetHTTPGetBoundsAndReportsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write(make([]byte, 2<<20))
	}))
	defer srv.Close()
	r, err := doctor.SystemNet{}.HTTPGet(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTeapot, r.Status)
	assert.LessOrEqual(t, len(r.Body), 1<<20)
	_, err = doctor.SystemNet{}.HTTPGet(context.Background(), "http://127.0.0.1:1")
	require.Error(t, err)
}

// ntpServer answers one request with a clock shifted by skew.
func ntpServer(t *testing.T, skew time.Duration) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 48)
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		out := make([]byte, 48)
		out[0] = 0x24
		out[1] = 2
		put := func(b []byte, ts time.Time) {
			sec := uint64(ts.Unix()) + 2208988800
			binary.BigEndian.PutUint32(b[0:4], uint32(sec))
			binary.BigEndian.PutUint32(b[4:8], uint32((uint64(ts.Nanosecond())<<32)/1_000_000_000))
		}
		now := time.Now().Add(skew)
		put(out[32:40], now)
		put(out[40:48], now)
		_, _ = pc.WriteTo(out, addr)
	}()
	return pc.LocalAddr().String()
}

func TestSNTPOffsetSign(t *testing.T) {
	// The server is 3 s behind the local clock, so the local clock is ahead.
	off, err := doctor.SNTP{Server: ntpServer(t, -3*time.Second)}.Offset(context.Background())
	require.NoError(t, err)
	assert.InDelta(t, float64(3*time.Second), float64(off), float64(200*time.Millisecond))

	off, err = doctor.SNTP{Server: ntpServer(t, 0)}.Offset(context.Background())
	require.NoError(t, err)
	assert.Less(t, off.Abs(), 200*time.Millisecond)
}

func TestSystemProbesDoNotEchoTheURLKey(t *testing.T) {
	// Port 1 on loopback refuses, so both probes fail without the network.
	const u = "http://user:SECRET@127.0.0.1:1/v2/SECRET?key=SECRET"
	_, err := doctor.SystemNet{}.HTTPGet(context.Background(), u)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET")
	assert.Contains(t, err.Error(), "127.0.0.1:1")

	_, err = doctor.SystemEVM{}.ChainID(context.Background(), u)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET")
}

func TestSystemEVMRedactsAURLInARemoteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"key invalid for https://rpc.example/v2/SECRET"}}`))
	}))
	defer srv.Close()
	_, err := doctor.SystemEVM{}.ChainID(context.Background(), srv.URL)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET")
}

func TestSystemKeyring(t *testing.T) {
	dir := t.TempDir()
	pass := filepath.Join(dir, "pass")
	require.NoError(t, os.WriteFile(pass, []byte("fixture-passphrase\n"), 0o600))
	fixture, err := filepath.Abs("../node/testdata/file-keyring")
	require.NoError(t, err)
	kr := filepath.Join(dir, "kr")
	require.NoError(t, os.CopyFS(kr, os.DirFS(fixture)))

	addr, err := doctor.SystemKeyring{}.Address(context.Background(), kr, "executor", pass)
	require.NoError(t, err)
	assert.Equal(t, "celestia13hzxpm30m23tfp90sv767u0fhc9xj0qk82ytnd", addr)

	require.NoError(t, os.WriteFile(pass, []byte("wrong-passphrase\n"), 0o600))
	_, err = doctor.SystemKeyring{}.Address(context.Background(), kr, "executor", pass)
	require.ErrorIs(t, err, node.ErrBadPassphrase)
}
