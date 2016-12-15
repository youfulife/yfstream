package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/chenyoufu/yfstream/alert"
	"github.com/chenyoufu/yfstream/cook"
	"github.com/chenyoufu/yfstream/dump"
	"github.com/chenyoufu/yfstream/g"
	"github.com/chenyoufu/yfstream/pull"
	"os"
	"runtime"
)

func input(out chan<- string) {
	var kafkaPCs = pull.InitKafkaPCS()
	for {
		for _, pc := range kafkaPCs {
			select {
			case msg := <-pc.Messages():
				b, err := pull.SemiCooKafkaMsg(msg)
				if err != nil {
					break
				}
				out <- string(b)
			default:
			}
		}
	}
}

func filter(in <-chan string, outC ...chan<- string) {
	var cooker = cook.InitCooker()

	for msg := range in {
		b, err := cooker.Cook(msg)
		if err != nil {
			continue
		}
		//output cooked message to all out channels
		for i, c := range outC {
			select {
			case c <- string(b):
			default:
				log.Printf("Length Channel %d: %d, Send failed!\n", i, len(outC))
			}
		}
	}

}

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

	var pipeC = make(chan string, 64)
	var alertC = make(chan string, 64)
	var esC = make(chan string, 64)

	go input(pipeC)
	go filter(pipeC, alertC, esC)
	go alert.Alerter(alertC)
	go dump.Dump2ES(esC)

	select {}
}
