package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

type synthDoc struct {
	Synthetic []liveCase `json:"synthetic"`
}

// checkSynthetic classifies every height of the synthetic cases with
// upstream code and compares the outcome with the vector file. The why text
// is the Python generator's prose, so it is not compared.
func checkSynthetic(b []byte) (int, error) {
	var d synthDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return 0, err
	}
	if len(d.Synthetic) == 0 {
		return 0, errors.New("no synthetic cases")
	}
	for _, c := range d.Synthetic {
		if err := checkSynthCase(c); err != nil {
			return 0, fmt.Errorf("%s: %w", c.ID, err)
		}
	}
	return len(d.Synthetic), nil
}

func checkSynthCase(c liveCase) error {
	ns, com, signer, h0, dl, err := decodeQuery(c.Query)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	byH := map[uint64]parts{}
	for _, r := range c.Records {
		b, err := hex.DecodeString(r.RecordHex)
		if err != nil {
			return err
		}
		p, err := decodeRecord(b)
		if err != nil {
			return fmt.Errorf("record at %s: %w", r.Height, err)
		}
		if utoa(p.height) != r.Height || sha(b) != r.SHA256 {
			return fmt.Errorf("record at %s: height or hash", r.Height)
		}
		byH[p.height] = p
	}
	var got []heightDoc
	for h := h0; h <= dl; h++ {
		p, ok := byH[h]
		if !ok {
			got = append(got, heightDoc{Height: utoa(h), Result: "unproven", Rule: "none"})
			continue
		}
		hd, err := classify(p, c.Query, ns, com, signer, h, c.TrustedHeaders)
		var u unproven
		if errors.As(err, &u) {
			hd = heightDoc{Height: utoa(h), Result: "unproven", Rule: u.rule}
		} else if err != nil {
			return fmt.Errorf("at %d: %w", h, err)
		}
		got = append(got, hd)
	}
	if len(got) != len(c.Expect.Heights) {
		return fmt.Errorf("%d heights, the vector has %d", len(got), len(c.Expect.Heights))
	}
	for i := range got {
		g, e := got[i], c.Expect.Heights[i]
		g.Why, e.Why = "", ""
		if !reflect.DeepEqual(g, e) {
			return fmt.Errorf("at %s: vector %+v, upstream %+v", e.Height, e, g)
		}
	}
	if w := window(got); w != c.Expect.Window {
		return fmt.Errorf("window: vector %+v, upstream %+v", c.Expect.Window, w)
	}
	return nil
}
