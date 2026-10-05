package main

import (
	"fmt"
	"os"

	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

func main() {
	err := fibrecommit.CheckBuild()
	fmt.Printf("checkbuild=%v\n", err)
	if err != nil {
		os.Exit(1)
	}
}
