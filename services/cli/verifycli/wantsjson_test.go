package verifycli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWantsJSONSpellings(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"verify", "--json", "abc"}, true},
		{[]string{"verify", "-json", "abc"}, true},
		{[]string{"--json=true"}, true},
		{[]string{"-json=true"}, true},
		{[]string{"--json=1"}, true},
		{[]string{"--json=t"}, true},
		{[]string{"--json=T"}, true},
		{[]string{"--json=TRUE"}, true},
		{[]string{"-json=True"}, true},
		{[]string{"--json=false"}, false},
		{[]string{"--json=0"}, false},
		{[]string{"-json=f"}, false},
		{[]string{"--json="}, false},
		{[]string{"--json=yes"}, false},
		{[]string{"--json=false", "--json"}, true},
		{[]string{"---json"}, false},
		{[]string{"json"}, false},
		{[]string{"--jsonx"}, false},
		{[]string{"--no-json"}, false},
		{[]string{"--", "--json"}, false},
		{[]string{"--json", "--"}, true},
		{nil, false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, wantsJSON(tc.args), "%q", tc.args)
	}
}
