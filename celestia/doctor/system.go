package doctor

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/vgonkivs/edicta/celestia/clearerr"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/policy"
	"github.com/vgonkivs/edicta/internal/secret"
)

// maxBody bounds what a probe reads from any HTTP answer.
const maxBody = 1 << 20

// NewSystemEnv is the Env that talks to the real network and disk.
func NewSystemEnv() *Env {
	return &Env{
		Net:       SystemNet{},
		OpenChain: openChain,
		EVM:       SystemEVM{Client: &http.Client{Timeout: 15 * time.Second}},
		Clocks: []TimeSource{
			SNTP{Server: "time.cloudflare.com:123"},
			SNTP{Server: "time.google.com:123"},
		},
		Keyring:  SystemKeyring{},
		Signer:   unavailableSigner{},
		Sessions: noSessions{},
	}
}

// SystemNet probes with the standard library.
type SystemNet struct {
	// TLS overrides the TLS client config; nil uses the system roots.
	TLS *tls.Config
}

func (SystemNet) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (SystemNet) DialTCP(ctx context.Context, hostPort string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return err
	}
	return c.Close()
}

func (n SystemNet) DialTLS(ctx context.Context, hostPort, serverName string) error {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if n.TLS != nil {
		cfg = n.TLS.Clone()
	}
	cfg.ServerName = serverName
	d := tls.Dialer{Config: cfg}
	c, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return err
	}
	return c.Close()
}

func (n SystemNet) HTTPGet(ctx context.Context, url string) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Response{}, clearerr.RedactErr(err, url)
	}
	tr := &http.Transport{TLSClientConfig: n.TLS, DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Timeout: 15 * time.Second, Transport: tr}).Do(req)
	if err != nil {
		return Response{}, clearerr.RedactErr(err, url)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: resp.StatusCode, Body: b}, nil
}

// SystemEVM talks JSON-RPC to a provider.
type SystemEVM struct{ Client *http.Client }

func (e SystemEVM) call(ctx context.Context, rpcURL, method string, params ...any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, clearerr.RedactErr(err, rpcURL)
	}
	req.Header.Set("Content-Type", "application/json")
	c := e.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, clearerr.RedactErr(err, rpcURL)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, errors.New("not a JSON-RPC answer")
	}
	if out.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error: %s", clearerr.RedactText(out.Error.Message))
	}
	return out.Result, nil
}

func hexQuantity(raw json.RawMessage) (*big.Int, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || !strings.HasPrefix(s, "0x") || len(s) == 2 {
		return nil, errors.New("not a hex quantity")
	}
	v, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, errors.New("not a hex quantity")
	}
	return v, nil
}

func (e SystemEVM) ChainID(ctx context.Context, rpcURL string) (uint64, error) {
	raw, err := e.call(ctx, rpcURL, "eth_chainId")
	if err != nil {
		return 0, err
	}
	v, err := hexQuantity(raw)
	if err != nil {
		return 0, err
	}
	if !v.IsUint64() {
		return 0, errors.New("chain id out of range")
	}
	return v.Uint64(), nil
}

// balanceOfSelector is the ERC-20 balanceOf(address) selector.
const balanceOfSelector = "70a08231"

func (e SystemEVM) USDCBalance(ctx context.Context, rpcURL, token, holder string) (*big.Int, error) {
	h := strings.TrimPrefix(strings.ToLower(holder), "0x")
	if len(h) != 40 {
		return nil, errors.New("holder is not a 20-byte address")
	}
	if _, err := hex.DecodeString(h); err != nil {
		return nil, errors.New("holder is not hex")
	}
	data := "0x" + balanceOfSelector + strings.Repeat("0", 24) + h
	raw, err := e.call(ctx, rpcURL, "eth_call", map[string]string{"to": token, "data": data}, "latest")
	if err != nil {
		return nil, err
	}
	v, err := hexQuantity(raw)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// SNTP reads the time of one NTP server over UDP. The offset is positive
// when the local clock is ahead.
type SNTP struct {
	Server  string
	Timeout time.Duration
	// Now is the local clock; nil is time.Now.
	Now func() time.Time
}

func (s SNTP) Name() string { return s.Server }

const (
	ntpPacket = 48
	// ntpEpoch is the offset from 1900 to 1970 in seconds.
	ntpEpoch = 2208988800
)

func ntpTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if sec == 0 && frac == 0 {
		return time.Time{}
	}
	nsec := (uint64(frac) * 1_000_000_000) >> 32
	return time.Unix(int64(sec)-ntpEpoch, int64(nsec))
}

func putNTPTime(b []byte, t time.Time) {
	sec := uint64(t.Unix()) + ntpEpoch
	frac := (uint64(t.Nanosecond()) << 32) / 1_000_000_000
	binary.BigEndian.PutUint32(b[0:4], uint32(sec))
	binary.BigEndian.PutUint32(b[4:8], uint32(frac))
}

func (s SNTP) Offset(ctx context.Context) (time.Duration, error) {
	now := s.Now
	if now == nil {
		now = time.Now
	}
	to := s.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", s.Server)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline := now().Add(to)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	req := make([]byte, ntpPacket)
	req[0] = 0x1b // version 3, client mode
	t1 := now()
	putNTPTime(req[40:48], t1)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	resp := make([]byte, ntpPacket)
	if n, err := conn.Read(resp); err != nil || n < ntpPacket {
		if err == nil {
			err = errors.New("short NTP answer")
		}
		return 0, err
	}
	t4 := now()
	if resp[0]&0x07 != 4 {
		return 0, errors.New("not an NTP server answer")
	}
	if resp[1] == 0 {
		return 0, errors.New("NTP server refused (kiss-of-death)")
	}
	t2, t3 := ntpTime(resp[32:40]), ntpTime(resp[40:48])
	if t2.IsZero() || t3.IsZero() {
		return 0, errors.New("NTP server has no time")
	}
	// theta is the server clock minus the local clock.
	theta := (t2.Sub(t1) + t3.Sub(t4)) / 2
	return -theta, nil
}

// SystemKeyring opens file keyrings through the same non-prompting opener the
// Recorder uses.
type SystemKeyring struct{}

func (SystemKeyring) Address(_ context.Context, dir, name, passphraseFile string) (string, error) {
	pass, err := secret.FromFile(passphraseFile)
	if err != nil {
		return "", err
	}
	defer pass.Zero()
	p := pass.Reveal()
	defer clear(p)
	kr, err := node.OpenKeyring(node.KeyringConfig{Dir: dir, Name: name, Backend: "file", Passphrase: p})
	if err != nil {
		return "", err
	}
	k, err := kr.Key(name)
	if err != nil {
		return "", err
	}
	addr, err := k.GetAddress()
	if err != nil {
		return "", err
	}
	return bech32.ConvertAndEncode("celestia", addr.Bytes())
}

type unavailableSigner struct{}

func (unavailableSigner) Info(context.Context, string) (SignerInfo, error) {
	return SignerInfo{}, fmt.Errorf("%w: the signer service", ErrNotAvailable)
}

type noSessions struct{}

func (noSessions) Supported() bool                                  { return false }
func (noSessions) MinPublishSlackBlocks() uint64                    { return 0 }
func (noSessions) MaxDelay(*policy.Mandate) (delay uint64, ok bool) { return 0, false }

// sysChain adapts the node clients to Chain.
type sysChain struct {
	cons   *node.ConsensusClient
	reader node.Reader
	closer io.Closer
}

func openChain(ctx context.Context, n config.Network) (Chain, error) {
	g := node.GRPCConfig{Addr: n.ConsensusGRPC.Addr, TLS: n.ConsensusGRPC.TLS}
	if n.ConsensusGRPC.TokenFile != "" {
		s, err := secret.FromFile(n.ConsensusGRPC.TokenFile)
		if err != nil {
			return nil, err
		}
		g.Token = s.RevealString()
		s.Zero()
	}
	cons, err := node.NewConsensus(g)
	if err != nil {
		return nil, err
	}
	b := node.BridgeConfig{Addr: n.Bridge.Addr, TLS: n.Bridge.TLS}
	if n.Bridge.TokenFile != "" {
		s, err := secret.FromFile(n.Bridge.TokenFile)
		if err != nil {
			_ = cons.Close()
			return nil, err
		}
		b.Token = s.RevealString()
		s.Zero()
	}
	rc, rd, err := node.NewReadOnly(ctx, b)
	if err != nil {
		_ = cons.Close()
		return nil, err
	}
	return &sysChain{cons: cons, reader: rd, closer: rc}, nil
}

func (c *sysChain) ConsensusChainID(ctx context.Context) (string, error) { return c.cons.Network(ctx) }
func (c *sysChain) BridgeHead(ctx context.Context) (node.Header, error)  { return c.reader.Head(ctx) }
func (c *sysChain) LatestHeight(ctx context.Context) (uint64, error)     { return c.cons.LatestHeight(ctx) }
func (c *sysChain) FibreParams(ctx context.Context) (node.FibreParams, error) {
	return c.cons.FibreParams(ctx)
}
func (c *sysChain) Escrow(ctx context.Context, bech string) (node.Escrow, error) {
	return c.cons.EscrowAccount(ctx, bech)
}
func (c *sysChain) MinGasPrice(ctx context.Context) (*big.Rat, error) { return c.cons.MinGasPrice(ctx) }
func (c *sysChain) Balance(ctx context.Context, addr, denom string) (uint64, error) {
	return c.cons.Balance(ctx, addr, denom)
}
func (c *sysChain) Close() error {
	err := c.cons.Close()
	if cerr := c.closer.Close(); err == nil {
		err = cerr
	}
	return err
}
