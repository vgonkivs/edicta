package absence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	abci "github.com/cometbft/cometbft/abci/types"
	core "github.com/cometbft/cometbft/types"
)

// provenCodes reads the result codes of a block from the JSON result object
// of /block_results and returns them only if the deterministic part of the
// results hashes to root (last_results_hash of the next header). A field the
// node omits reads as zero: the hash check then fails unless zero was the
// real value, so leniency here cannot change a proven code.
func provenCodes(results, root []byte) ([]uint32, error) {
	var res struct {
		TxsResults []struct {
			Code      *json.Number `json:"code"`
			Data      *string      `json:"data"`
			GasWanted *string      `json:"gas_wanted"`
			GasUsed   *string      `json:"gas_used"`
		} `json:"txs_results"`
	}
	dec := json.NewDecoder(bytes.NewReader(results))
	dec.UseNumber()
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("results: %w", err)
	}
	rs := make([]*abci.ExecTxResult, len(res.TxsResults))
	codes := make([]uint32, len(res.TxsResults))
	for i, t := range res.TxsResults {
		r := &abci.ExecTxResult{}
		if t.Code != nil {
			c, err := strconv.ParseUint(t.Code.String(), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("result %d code: %w", i, err)
			}
			r.Code = uint32(c)
		}
		if t.Data != nil {
			d, err := base64.StdEncoding.DecodeString(*t.Data)
			if err != nil {
				return nil, fmt.Errorf("result %d data: %w", i, err)
			}
			if len(d) > 0 {
				r.Data = d
			}
		}
		for _, g := range []struct {
			in  *string
			out *int64
		}{{t.GasWanted, &r.GasWanted}, {t.GasUsed, &r.GasUsed}} {
			if g.in == nil {
				continue
			}
			v, err := strconv.ParseInt(*g.in, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("result %d gas: %w", i, err)
			}
			*g.out = v
		}
		rs[i], codes[i] = r, r.Code
	}
	if !bytes.Equal(core.NewResults(rs).Hash(), root) {
		return nil, fmt.Errorf("results do not hash to last_results_hash of the next header")
	}
	return codes, nil
}
