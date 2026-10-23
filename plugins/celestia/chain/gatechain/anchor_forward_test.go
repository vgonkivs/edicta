// SPDX-License-Identifier: Apache-2.0

package gatechain_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/gate"
	"github.com/vgonkivs/edicta/plugins/celestia/chain/anchor"
	"github.com/vgonkivs/edicta/plugins/celestia/chain/gatechain"
)

// The gatechain names of the anchor reading are the anchor package's own
// values and types, so errors.Is and every caller see no difference.
func TestAnchorNamesForward(t *testing.T) {
	assert.Same(t, anchor.ErrInvalidConfig, gatechain.ErrInvalidConfig)
	assert.Same(t, anchor.ErrProbeInconclusive, gatechain.ErrProbeInconclusive)
	assert.EqualError(t, gatechain.ErrInvalidConfig, "gatechain: invalid config")
	assert.EqualError(t, gatechain.ErrProbeInconclusive, "gatechain: bridge probe inconclusive")

	assert.Equal(t, reflect.TypeFor[anchor.FibreAnchors](), reflect.TypeFor[gatechain.FibreAnchors]())
	assert.Equal(t, reflect.TypeFor[anchor.FibreAnchor](), reflect.TypeFor[gatechain.FibreAnchor]())
	assert.Equal(t, reflect.TypeFor[anchor.FibreAnchorOptions](), reflect.TypeFor[gatechain.FibreAnchorOptions]())
	assert.Equal(t, reflect.TypeFor[anchor.BridgeProbe](), reflect.TypeFor[gatechain.BridgeProbe]())
	assert.Equal(t, reflect.TypeFor[anchor.ProbeResult](), reflect.TypeFor[gatechain.ProbeResult]())
	assert.Equal(t, reflect.TypeFor[anchor.RawDownloader](), reflect.TypeFor[gatechain.RawDownloader]())

	assert.EqualValues(t, anchor.DefaultFibreMaxReadBytes, gatechain.DefaultFibreMaxReadBytes)
	assert.EqualValues(t, anchor.DefaultFibreLookupTimeout, gatechain.DefaultFibreLookupTimeout)
	assert.EqualValues(t, anchor.DefaultProbeWindow, gatechain.DefaultProbeWindow)
	assert.EqualValues(t, anchor.DefaultProbeMargin, gatechain.DefaultProbeMargin)
}

func TestAnchorFunctionsForward(t *testing.T) {
	ref := commitment.PayloadRef{DA: commitment.DACelestiaBlob, Height: 10}
	_, gotErr := gatechain.CheckPFB([]byte{0xff}, ref)
	_, wantErr := anchor.CheckPFB([]byte{0xff}, ref)
	require.ErrorIs(t, gotErr, gate.ErrAnchorIntentInvalid)
	assert.Equal(t, wantErr.Error(), gotErr.Error())

	a := gatechain.NewFibreAnchors(nil, "", gatechain.FibreAnchorOptions{})
	_, err := a.Lookup(context.Background(), ref)
	require.ErrorIs(t, err, gatechain.ErrInvalidConfig, "a missing reader fails closed")

	ctx := gatechain.WithAnchorScope(context.Background())
	assert.NotEqual(t, context.Background(), ctx)
}
