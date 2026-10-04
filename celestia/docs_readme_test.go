package celestia_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

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
