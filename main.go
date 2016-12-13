package main

import (
	"flag"
	"fmt"
	"github.com/chenyoufu/yfstream/g"
	"os"
	"runtime"
)

func main() {
	fmt.Println("hello yfstream!")
	runtime.GOMAXPROCS(runtime.NumCPU())

	cfg := flag.String("c", "cfg.json", "configuration file")
	version := flag.Bool("v", false, "show version")
	flag.Parse()

	if *version {
		fmt.Println(g.VERSION)
		os.Exit(0)
	}

	g.ParseConfig(*cfg)
	fmt.Println(g.Config())
}
