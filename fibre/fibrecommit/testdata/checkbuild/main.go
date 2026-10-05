package main

import (
	"fmt"

	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

func main() {
	fmt.Printf("selftest=%v\n", fibrecommit.SelfTest())
	fmt.Printf("checkbuild=%v\n", fibrecommit.CheckBuild())
}
