package main

import (
	"net"

	"github.com/haxii/socks5"
)

func main() {
	conf := &socks5.Config{
		BindIP:   net.IPv4(127, 0, 0, 1),
		BindPort: 8000,
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)
	}
}
