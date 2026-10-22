// SPDX-License-Identifier: Apache-2.0

package edictad_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
)

func TestRecorderFastMinGasPriceDefault(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	c, err := p.parseBlobFast(gateFastFor(), recFast())
	require.NoError(t, err)
	assert.Equal(t, edictad.DefaultFastMinGasPrice, c.Recorder.FastMinGasPrice)
	assert.Equal(t, "0.002", edictad.DefaultFastMinGasPrice)

	c, err = p.parseBlobFast(gateFastFor(), recFast(recFastKeys+`fast_min_gas_price = "0.01"`))
	require.NoError(t, err)
	assert.Equal(t, "0.01", c.Recorder.FastMinGasPrice)

	c, err = p.parseFibreFast(gateFastFor(), recFast(append(fibreFastKeys(maxUploadCost(t)), `fast_min_gas_price = "0.004"`)...))
	require.NoError(t, err)
	assert.Equal(t, "0.004", c.Recorder.FastMinGasPrice)
}

func TestRecorderFastMinGasPriceIsAbsentWithoutFast(t *testing.T) {
	p := mandateFor(t, newEnv(t))
	c, err := p.parseBlobFast(gateFastFor())
	require.NoError(t, err)
	assert.Empty(t, c.Recorder.FastMinGasPrice)

	_, err = p.parseBlobFast(gateFastFor(), recFast(`fast_min_gas_price = "0.002"`))
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "fast_min_gas_price")
}

func TestRecorderFastMinGasPriceRefusals(t *testing.T) {
	for name, v := range map[string]string{
		"zero":        "0",
		"zero dotted": "0.000",
		"negative":    "-0.1",
		"exponent":    "1e-3",
		"fraction":    "1/500",
		"word":        "cheap",
		"leading dot": ".5",
		"two dots":    "0.0.2",
		"unit suffix": "0.002utia",
	} {
		t.Run(name, func(t *testing.T) {
			p := mandateFor(t, newEnv(t))
			_, err := p.parseBlobFast(gateFastFor(), recFast(recFastKeys+`fast_min_gas_price = "`+v+`"`))
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), "recorder.fast_min_gas_price")
		})
	}
}
