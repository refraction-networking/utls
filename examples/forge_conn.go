package main

import (
	"fmt"
	"net"
	"time"

	tls "github.com/refraction-networking/utls"
)

func main() {
	// this gets tls connection with google.com
	// then replaces underlying connection of that tls connection with an in-memory pipe
	// to a forged local in-memory "server-side" connection,
	// that uses cryptographic parameters passed by a client
	clientTcp, err := net.DialTimeout("tcp", "google.com:443", 10*time.Second)
	if err != nil {
		fmt.Printf("net.DialTimeout error: %+v", err)
		return
	}

	clientUtls := tls.UClient(clientTcp, nil, tls.HelloGolang)
	defer clientUtls.Close()
	clientUtls.SetSNI("google.com") // have to set SNI, if config was nil
	err = clientUtls.Handshake()
	if err != nil {
		fmt.Printf("clientUtls.Handshake() error: %+v", err)
	}

	serverConn, clientConn := net.Pipe()

	clientUtls.SetNetConn(clientConn)

	hs := clientUtls.HandshakeState
	serverTls := tls.MakeConnWithCompleteHandshake(serverConn, hs.ServerHello.Vers, hs.ServerHello.CipherSuite,
		hs.MasterSecret, hs.Hello.Random, hs.ServerHello.Random, false)

	go func() {
		clientUtls.Write([]byte("Hello, world!"))
		resp := make([]byte, 13)
		read, err := clientUtls.Read(resp)
		if err != nil {
			fmt.Printf("error reading client: %+v\n", err)
		}
		fmt.Printf("Client read %d bytes: %s\n", read, string(resp))
		fmt.Println("Client closing...")
		clientUtls.Close()
		fmt.Println("client closed")
	}()

	buf := make([]byte, 13)
	read, err := serverTls.Read(buf)
	if err != nil {
		fmt.Printf("error reading server: %+v\n", err)
	}

	fmt.Printf("Server read %d bytes: %s\n", read, string(buf))
	serverTls.Write([]byte("Test response"))

	// Have to do a final read (that will error)
	// to consume client's closeNotify
	// because net Pipes are weird
	serverTls.Read(buf)
	fmt.Println("Server closed")

}
