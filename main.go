package main

import (
	"flag"
	"fmt"
	"github.com/oxilgk/hexi/io"
	"os"
)

func round(n int) int {
	a := int(n/10) * 10
	b := a + 10

	if a-n > b {
		return a
	} else if b-n > a {
		return b
	} else {
		return 0
	}

}

func draw(buf []byte) {

	flag := false

	for i := 0x0; i < 0x100; i = i + 0x10 {
		fmt.Printf("%.8X: ", i)
		for j := 0x0; j < 0x10; j++ {
			fmt.Printf("%.2X", buf[j+i])
			if flag {
				flag = false
				fmt.Print(" ")
				continue
			}
			flag = true
		}

		for z := 0x0; z < 0x10; z++ {
			if buf[z+i] > 0x7e || buf[z+i] < 0x21 {
				fmt.Printf("%c", 0x2e)
			} else if buf[z+i] == 0 {
				fmt.Printf(".")
			} else {
				fmt.Printf("%c", buf[z+i])
			}
		}
		fmt.Printf("\n")
	}
}

var flagvar bool

func init() {
	flag.BoolVar(&flagvar, "color", false, "Set the color or not")
	flag.Parse()
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	buff := io.Open_file(os.Args[1])
	draw(buff)
}
