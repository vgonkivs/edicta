// Command deploytx prints the CREATE2 deployment of EdictaPublish as JSON:
// the factory, the call data and the resulting address. It never connects to
// a node and never signs; sending the transaction is a separate manual step.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vgonkivs/edicta/contracts/edictapublish"
)

func main() {
	if err := edictapublish.Check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	addr := edictapublish.Create2Address()
	salt := edictapublish.Salt()
	out := struct {
		To      string `json:"to"`
		Value   string `json:"value"`
		Data    string `json:"data"`
		Address string `json:"create2_address"`
		Salt    string `json:"salt"`
	}{
		To:      "0x" + strings.ToLower(edictapublish.DeterministicDeployer),
		Value:   "0x0",
		Data:    fmt.Sprintf("0x%x", edictapublish.DeployCalldata()),
		Address: fmt.Sprintf("0x%x", addr[:]),
		Salt:    fmt.Sprintf("0x%x", salt[:]),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
