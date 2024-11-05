package main

import (
	"flag"
	"net"

	"github.com/pion/dtls/v3/examples/util"
	tls "github.com/refraction-networking/utls"
)

func main() {
	var listenAddr = flag.String("laddr", "127.0.0.1:6666", "listen address")
	flag.Parse()

	certificate, err := tls.LoadX509KeyPair("certificates/server.pub.pem", "certificates/server.pem")
	util.Check(err)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		panic(err.Error())
	}

	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})

	hub := util.NewHub()

	go func() {
		for {
			conn, err := tlsListener.Accept()
			util.Check(err)
			hub.Register(conn)
		}

	}()

	hub.Chat()

}
