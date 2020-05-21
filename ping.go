package main

import (
	"log"
	"net"
	"sync"
	"time"

	ping "github.com/digineo/go-ping"
)

var (
	pings   []time.Duration
	pingsMu sync.Mutex
)

func pinger() {

	p, err := ping.New("0.0.0.0", "")
	if err != nil {
		panic(err)
	}
	for {
		log.Println(p.Ping(&net.IPAddr{IP: net.ParseIP("1.1.1.1")}, time.Second))
		time.Sleep(2 * time.Second)
	}

}
