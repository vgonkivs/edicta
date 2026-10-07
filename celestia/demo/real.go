package demo

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/edictad/wire"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/verifycli"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

// realClients holds the connections to the funding node and the bridge.
type realClients struct {
	preset Preset
	cons   *node.ConsensusClient

	mu     sync.Mutex
	bridge io.Closer
	reader node.Reader
}

func (c *realClients) bridgeReader(ctx context.Context) (node.Reader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reader != nil {
		return c.reader, nil
	}
	rc, rd, err := node.NewReadOnly(ctx, node.BridgeConfig{Addr: c.preset.Bridge.Addr, TLS: c.preset.Bridge.TLS})
	if err != nil {
		return nil, err
	}
	c.bridge, c.reader = rc, rd
	return rd, nil
}

func (c *realClients) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bridge != nil {
		_ = c.bridge.Close()
	}
	_ = c.cons.Close()
}

type realChain struct{ c *realClients }

func (r realChain) ChainID(ctx context.Context) (string, error) { return r.c.cons.Network(ctx) }

func (r realChain) Head(ctx context.Context) (uint64, time.Time, error) {
	h, err := r.c.cons.LatestHeight(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	rd, err := r.c.bridgeReader(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	hd, err := rd.Head(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	return h, hd.Time, nil
}

func (r realChain) BalanceAt(ctx context.Context, addr, denom string, minHeight uint64) (uint64, uint64, error) {
	head, err := r.c.cons.LatestHeight(ctx)
	if err != nil {
		return 0, 0, err
	}
	h := max(head, minHeight)
	v, err := r.c.cons.BalanceAt(ctx, addr, denom, h)
	return v, h, err
}

func (r realChain) MinGasPrice(ctx context.Context) (*big.Rat, error) {
	return r.c.cons.MinGasPrice(ctx)
}
func (r realChain) TxIndex(ctx context.Context) error { return r.c.cons.TxIndex(ctx) }

type realGate struct{}

func (realGate) Start(ctx context.Context, cfg edictad.Config, d edictad.Deps) (GateHandle, error) {
	s, err := edictad.Start(ctx, cfg, d)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// fallbackFeed asks the sources in order and takes the first answer.
type fallbackFeed []pricefeed.Feed

func (f fallbackFeed) Observe(ctx context.Context) (pricefeed.Observation, error) {
	var errs []error
	for _, s := range f {
		o, err := s.Observe(ctx)
		if err == nil {
			return o, nil
		}
		errs = append(errs, err)
	}
	return pricefeed.Observation{}, errors.Join(errs...)
}

// RealDeps wires the demo to the network of the preset. The returned
// function closes the connections.
func RealDeps(cfg Config, console Console, screen Screen) (Deps, func(), error) {
	cfg = cfg.WithDefaults()
	p, err := LoadPreset(cfg.Network)
	if err != nil {
		return Deps{}, nil, err
	}
	p = p.Apply(cfg.Overrides)
	cons, err := node.NewConsensus(node.GRPCConfig{Addr: p.GRPC.Addr, TLS: p.GRPC.TLS})
	if err != nil {
		return Deps{}, nil, err
	}
	c := &realClients{preset: p, cons: cons}
	hc := &http.Client{Timeout: 15 * time.Second}
	d := Deps{
		Chain: realChain{c}, Console: console, Screen: screen, Gate: realGate{}, HTTP: hc,
		NewFunder: func(ctx context.Context, fc railtx.FunderConfig) (Funding, Abandoner, error) {
			fc.Consensus = cons
			f, err := railtx.NewFunder(ctx, fc)
			if err != nil {
				return nil, nil, err
			}
			return f, f, nil
		},
		NewGateDeps: func(ctx context.Context, ec edictad.Config) (edictad.Deps, func(), error) {
			logPath := filepath.Join(filepath.Dir(ec.Archive.Dir), "edictad.log")
			lf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				return edictad.Deps{}, nil, err
			}
			deps, closeAll, err := wire.Adapters(ctx, ec, slog.New(slog.NewTextHandler(lf, nil)))
			if err != nil {
				_ = lf.Close()
				return edictad.Deps{}, nil, err
			}
			return deps, func() { closeAll(); _ = lf.Close() }, nil
		},
		NewRail: func(ctx context.Context, key railtx.KeySource) (transfer.Rail, error) {
			rd, err := c.bridgeReader(ctx)
			if err != nil {
				return nil, err
			}
			fee, err := railtx.DeriveFee(ctx, cons, p.Funding.GasLimit, nil)
			if err != nil {
				return nil, err
			}
			return railtx.New(railtx.Config{Consensus: cons, Reader: rd, Key: key, GasLimit: p.Funding.GasLimit, Fee: fee})
		},
		NewFeed: func() (pricefeed.Feed, error) {
			kr, err := pricefeed.NewKraken("https://api.kraken.com", "TIAUSD", "celestia", "USD", hc)
			if err != nil {
				return nil, err
			}
			return fallbackFeed{kr, pricefeed.NewCoinGecko("https://api.coingecko.com/api/v3", "celestia", "USD", hc)}, nil
		},
		Verify: verifycli.Run,
	}
	return d, c.Close, nil
}
