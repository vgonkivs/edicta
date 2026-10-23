// SPDX-License-Identifier: Apache-2.0

package gatechain

import (
	"context"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/celestia/chain/anchor"
	"github.com/vgonkivs/edicta/plugins/celestia/node"
)

// The anchor reading lives in package anchor; these names forward to it.
type (
	FibreAnchors       = anchor.FibreAnchors
	FibreAnchor        = anchor.FibreAnchor
	FibreAnchorOptions = anchor.FibreAnchorOptions
	BridgeProbe        = anchor.BridgeProbe
	ProbeResult        = anchor.ProbeResult
	RawDownloader      = anchor.RawDownloader
)

const (
	DefaultFibreMaxReadBytes  = anchor.DefaultFibreMaxReadBytes
	DefaultFibreLookupTimeout = anchor.DefaultFibreLookupTimeout
	DefaultProbeWindow        = anchor.DefaultProbeWindow
	DefaultProbeMargin        = anchor.DefaultProbeMargin
)

var (
	ErrInvalidConfig     = anchor.ErrInvalidConfig
	ErrProbeInconclusive = anchor.ErrProbeInconclusive
)

func NewFibreAnchors(r node.FibreAnchorReader, chainID string, o FibreAnchorOptions) *FibreAnchors {
	return anchor.NewFibreAnchors(r, chainID, o)
}

func WithAnchorScope(ctx context.Context) context.Context { return anchor.WithAnchorScope(ctx) }

func CheckPFB(tx []byte, ref commitment.PayloadRef) (uint64, error) { return anchor.CheckPFB(tx, ref) }

// configError is a refusal of gatechain's own wiring. It reads as a gatechain
// error and still matches the shared ErrInvalidConfig sentinel.
type configError struct{ detail string }

func (e *configError) Error() string { return "gatechain: invalid config: " + e.detail }

func (e *configError) Is(target error) bool { return target == ErrInvalidConfig }

func invalidConfig(detail string) error { return &configError{detail: detail} }
