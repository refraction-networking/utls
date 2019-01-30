package main

import (
	"../../utls"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func main() {

	clientTcp, err := net.DialTimeout("tcp", "google.com:443", 10*time.Second)
	if err != nil {
		fmt.Printf("net.DialTimeout error: %+v", err)
		return
	}

	clientUtls := tls.UClient(clientTcp, nil, tls.HelloGolang)
	defer clientUtls.Close()

	clientUtls.SetSNI("google.com") // have to set SNI, if config was nil
	err = clientUtls.BuildHandshakeState()
	if err != nil {
		// have to call BuildHandshakeState() first, when using default UClient, to avoid settings' overwriting
		fmt.Printf("clientUtls.BuildHandshakeState() error: %+v", err)
		return
	}

	cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131}
	clientUtls.SetClientRandom(cRandom)
	err = clientUtls.Handshake()
	if err != nil {
		fmt.Printf("clientUtls.Handshake() error: %+v", err)
	}
	// These fields are accessible regardless of setting client hello explicitly
	fmt.Printf("#> MasterSecret:\n%s", hex.Dump(clientUtls.HandshakeState.MasterSecret))
	fmt.Printf("#> ClientHello Random:\n%s", hex.Dump(clientUtls.HandshakeState.Hello.Random))
	fmt.Printf("#> ServerHello Random:\n%s", hex.Dump(clientUtls.HandshakeState.ServerHello.Random))

	serverConn, clientConn := net.Pipe()

	serverUtls := tls.UClient(serverConn, nil, tls.HelloGolang)
	serverUtls.SetSecret(clientUtls.HandshakeState, false)
	clientUtls.SetNetConn(clientConn)

	//return httpGetOverConn(clientUtls, clientUtls.HandshakeState.ServerHello.AlpnProtocol)

	go func() {
		clientUtls.Write([]byte("Hello, world!"))
		resp := make([]byte, 20)
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
	read, err := serverUtls.Read(buf)
	if err != nil {
		fmt.Printf("error reading server: %+v\n", err)
	}

	fmt.Printf("Server read %d bytes: %s\n", read, string(buf))
	serverUtls.Write([]byte("Test response"))

	// Have to do a final read (that will error)
	// to consume client's closeNotify
	// because net Pipes are weird
	serverUtls.Read(buf)
	fmt.Println("Server closed")

}
