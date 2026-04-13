package cmd

import (
	"fmt"

	"github.com/suisrc/zoo"
)

func init() {
	zoo.AddCmd("hello", hello)
}

func hello() {
	fmt.Println("hello world!")
}
