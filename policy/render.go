package policy

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

func fmtAmount(b []byte, scale uint64) string {
	s := amountBig(b).String()
	if scale == 0 {
		return s
	}
	n := int(scale)
	if len(s) <= n {
		s = strings.Repeat("0", n-len(s)+1) + s
	}
	return s[:len(s)-n] + "." + s[len(s)-n:]
}

func fmtTime(t uint64) string { return time.Unix(int64(t), 0).UTC().Format("2006-01-02T15:04:05Z") }

// Render is the deterministic text a wallet or CLI shows before the principal
// signs. The signature covers the CBOR, not this text.
func Render(m *Mandate) string {
	var sb strings.Builder
	line := func(s string) { sb.WriteString(s); sb.WriteByte('\n') }
	line("Edicta mandate v1")
	line("principal: " + hex.EncodeToString(m.Principal))
	line("mandate_id: " + hex.EncodeToString(m.MandateID))
	line("version: " + strconv.FormatUint(m.Version, 10))
	line("gate: " + m.GateID)
	line("valid: anchor time from " + fmtTime(m.NotBefore) + " ; decision valid_until up to " + fmtTime(m.NotAfter))
	if m.MaxDecisionAge == 0 {
		line("max decision age: default (MaxTTL of the payload's DA)")
	} else {
		line("max decision age: " + strconv.FormatUint(m.MaxDecisionAge, 10) + "s")
	}
	if m.MinSpacing == 0 {
		line("min spacing: none")
	} else {
		line("min spacing: " + strconv.FormatUint(m.MinSpacing, 10) + "s")
	}
	line("agents (" + strconv.Itoa(len(m.Agents)) + ", shared counter):")
	for _, a := range m.Agents {
		line("  - " + hex.EncodeToString(a))
	}
	if len(m.Kinds) == 0 {
		line("kinds: any")
	} else {
		line("kinds: " + strings.Join(m.Kinds, ", "))
	}
	window := func(h uint64) string {
		return "per rolling " + strconv.FormatUint(h, 10) + "h (may count up to " + strconv.FormatUint(h+1, 10) + "h)"
	}
	for _, r := range m.Assets {
		line("asset " + r.Asset + " (scale " + strconv.FormatUint(r.Scale, 10) + "):")
		if r.PerActionMax == nil {
			line("  per action: no limit")
		} else {
			line("  per action: max " + fmtAmount(r.PerActionMax, r.Scale))
		}
		if len(r.Periods) == 0 {
			line("  period: no limit")
		}
		for _, p := range r.Periods {
			line("  period: max " + fmtAmount(p.Max, r.Scale) + " " + window(p.Hours))
		}
		if r.Recipients == nil {
			line("  recipients: any")
		} else {
			line("  recipients:")
			for _, x := range r.Recipients {
				line("    - " + x)
			}
		}
	}
	if len(m.CountLimits) == 0 {
		line("count: no limit")
	}
	for _, c := range m.CountLimits {
		line("count: max " + strconv.FormatUint(c.MaxCount, 10) + " actions " + window(c.Hours))
	}
	line("notes:")
	line("  - Limits are measured on the anchor time of each decision (block time of its payload), not on execution time.")
	line("  - Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to one extra hour (a \"per 1h\" limit may span up to 2h): the gate may deny early, never allow extra.")
	line("  - Limits count authorizations, not executions.")
	line("  - Counters continue across versions of this mandate_id; a new mandate_id starts from zero.")
	return sb.String()
}
