package celestia_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadmeRunCommands(t *testing.T) {
	b, err := os.ReadFile("README.md")
	require.NoError(t, err)
	s := string(b)

	require.NotRegexp(t, regexp.MustCompile(`(?m)\bcd\s+-(\s|$)`), s, "no `cd -`")
	for i, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "go run ") {
			t.Errorf("line %d: use `go -C celestia run ...`: %q", i+1, l)
		}
	}
	require.Contains(t, s, "go -C celestia run")
	require.NotContains(t, strings.ToLower(s), "itrocket", "the itrocket gRPC host uses an origin cert and is not listed")
}

// section returns the body of the first heading whose text contains title, up
// to the next heading of the same or a higher level.
func section(t *testing.T, doc, title string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	head := regexp.MustCompile(`^(#+)\s+(.*)$`)
	for i, l := range lines {
		m := head.FindStringSubmatch(l)
		if m == nil || !strings.Contains(m[2], title) {
			continue
		}
		level := len(m[1])
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if n := head.FindStringSubmatch(lines[j]); n != nil && len(n[1]) <= level {
				end = j
				break
			}
		}
		return strings.Join(lines[i+1:end], "\n")
	}
	require.Failf(t, "missing section", "no heading containing %q", title)
	return ""
}

// mentions fails with the missing text only, not the whole document.
func mentions(t *testing.T, doc, want string) {
	t.Helper()
	assert.True(t, strings.Contains(doc, want), "README does not mention %q", want)
}

func TestReadmeEndpointsAndEscrowSections(t *testing.T) {
	b, err := os.ReadFile("README.md")
	require.NoError(t, err)
	doc := string(b)

	t.Run("endpoints", func(t *testing.T) {
		s := section(t, doc, "Endpoints")
		for _, want := range []string{
			"x-cosmos-block-height", "observations-only", "ErrRetentionUnavailable",
			"own_node", "bridge",
		} {
			mentions(t, s, want)
		}
		mentions(t, strings.ToLower(s), "height-ignoring")
		mentions(t, s, "at-height reads")
	})
	t.Run("fibre escrow", func(t *testing.T) {
		s := section(t, doc, "Fibre escrow")
		mentions(t, s, "MsgDepositToEscrow")
		mentions(t, s, "650000")
		mentions(t, s, "45000")
		mentions(t, s, "ErrEscrowInsufficient")
		mentions(t, s, "UNVERIFIED")
		assert.True(t, regexp.MustCompile(`(?i)never automatic|not automatic|AutoFund`).MatchString(s), "escrow is never funded automatically")
		mentions(t, s, "24 h")
		assert.True(t, regexp.MustCompile(`(?s)UNVERIFIED.{0,800}MsgDepositToEscrow|MsgDepositToEscrow.{0,800}UNVERIFIED`).MatchString(s),
			"UNVERIFIED sits with the deposit command")
	})
	t.Run("archive outage behaviour", func(t *testing.T) {
		s := strings.ToLower(doc)
		mentions(t, s, "retry-after")
		assert.True(t, regexp.MustCompile(`(?s)archive.{0,400}503|503.{0,400}archive`).MatchString(s),
			"a retry of an authorized decision gets 503 while the archive is down")
	})
	t.Run("configuration", func(t *testing.T) {
		for _, key := range []string{"celestia_blob", "fibre_chain_ids", "[archive]", "sweep_interval_s", "bridge_fallback"} {
			mentions(t, doc, key)
		}
		assert.False(t, strings.Contains(doc, `da = "blob"`), `the "blob" alias is gone`)
	})
}
