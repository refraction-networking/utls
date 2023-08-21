package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

type ClientSessionCache struct {
	sessionKeyMap map[string]*tls.ClientSessionState
}

func NewClientSessionCache() tls.ClientSessionCache {
	return &ClientSessionCache{
		sessionKeyMap: make(map[string]*tls.ClientSessionState),
	}
}

func (csc *ClientSessionCache) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	if session, ok = csc.sessionKeyMap[sessionKey]; ok {
		fmt.Printf("Getting session for %s\n", sessionKey)
		return session, true
	}
	fmt.Printf("Missing session for %s\n", sessionKey)
	return nil, false
}

func (csc *ClientSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	if csc.sessionKeyMap == nil {
		fmt.Printf("Deleting session for %s\n", sessionKey)
		delete(csc.sessionKeyMap, sessionKey)
	} else {
		fmt.Printf("Putting session for %s\n", sessionKey)
		csc.sessionKeyMap[sessionKey] = cs
	}
}

func runPskCheck(helloID tls.ClientHelloID) {
	const serverAddr string = "refraction.network:443"
	csc := NewClientSessionCache()
	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		panic(err)
	}

	// Everything below this line is brought to you by uTLS API, enjoy!

	// use chs
	tlsConn := tls.UClient(tcpConn, &tls.Config{
		ServerName: strings.Split(serverAddr, ":")[0],
		// NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: csc, // set this so session tickets will be saved
	}, helloID)

	// HS
	err = tlsConn.Handshake()
	if err != nil {
		panic(err)
	}

	if tlsConn.ConnectionState().HandshakeComplete {
		fmt.Println("Handshake complete")
		fmt.Printf("TLS Version: %04x\n", tlsConn.ConnectionState().Version)
		if tlsConn.ConnectionState().Version != tls.VersionTLS13 {
			fmt.Printf("Only TLS 1.3 suppports PSK\n")
			return
		}

		if tlsConn.HandshakeState.State13.UsingPSK {
			panic("unintended using of PSK happened...")
		} else {
			fmt.Println("First connection, no PSK to use.")
		}

		tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		tlsConn.Read(make([]byte, 1024)) // trigger a read so NewSessionTicket gets handled
	}
	tlsConn.Close()

	tcpConnPSK, err := net.Dial("tcp", serverAddr)
	if err != nil {
		panic(err)
	}

	tlsConnPSK := tls.UClient(tcpConnPSK, &tls.Config{
		ServerName:         strings.Split(serverAddr, ":")[0],
		ClientSessionCache: csc,
	}, helloID)

	// HS
	err = tlsConnPSK.Handshake()
	fmt.Println(tlsConnPSK.HandshakeState.Hello.Raw)
	fmt.Println(tlsConnPSK.HandshakeState.Hello.PskIdentities)
	if err != nil {
		panic(err)
	}

	if tlsConnPSK.ConnectionState().HandshakeComplete {
		fmt.Println("Handshake complete")
		fmt.Printf("TLS Version: %04x\n", tlsConnPSK.ConnectionState().Version)
		if tlsConnPSK.ConnectionState().Version != tls.VersionTLS13 {
			fmt.Printf("Only TLS 1.3 suppports PSK\n")
			return
		}

		if tlsConnPSK.HandshakeState.State13.UsingPSK {
			fmt.Println("PSK used!")
		} else {
			panic("PSK not used for a resumption session!")
		}
	}
}

func main() {
	runPskCheck(tls.HelloChrome_100_PSK)
	runPskCheck(tls.HelloGolang)
}
