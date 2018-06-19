package main

import (
	"encoding/hex"
	"fmt"
	tls "github.com/refraction-networking/utls"
	"net"
	"strings"
	"time"
)

var (
	dialTimeout   = time.Duration(15) * time.Second
	sessionTicket = []uint8(`Here goes phony session ticket: phony enough to get into ASCII range
Ticket could be of any length, but for camouflage purposes it's better to use uniformly random contents
and standard length such as 228`)
)

func HttpGetDefault(hostname string, addr string) (string, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	tlsConn := tls.Client(dialConn, &config)
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("tlsConn.Handshake() error: %+v", err)
	}
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	tlsConn.Read(buf)
	return string(buf), nil
}

func HttpGetByHelloID(hostname string, addr string, helloID tls.ClientHelloID) (string, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, helloID)
	defer uTlsConn.Close()

	err = uTlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	uTlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	uTlsConn.Read(buf)
	return string(buf), nil
}

func HttpGetExplicitRandom(hostname string, addr string) (string, error) {
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, nil, tls.HelloGolang)
	defer uTlsConn.Close()

	uTlsConn.SetSNI(hostname) // have to set SNI, if config was nil
	err = uTlsConn.BuildHandshakeState()
	if err != nil {
		// have to call BuildHandshakeState() first, when using default UClient, to avoid settings' overwriting
		return "", fmt.Errorf("uTlsConn.BuildHandshakeState() error: %+v", err)
	}

	cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131}
	uTlsConn.SetClientRandom(cRandom)
	err = uTlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	// These fields are accessible regardless of setting client hello explicitly
	fmt.Printf("#> MasterSecret:\n%s", hex.Dump(uTlsConn.HandshakeState.MasterSecret))
	fmt.Printf("#> ClientHello Random:\n%s", hex.Dump(uTlsConn.HandshakeState.Hello.Random))
	fmt.Printf("#> ServerHello Random:\n%s", hex.Dump(uTlsConn.HandshakeState.ServerHello.Random))

	uTlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	uTlsConn.Read(buf)
	return string(buf), nil
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func HttpGetTicket(hostname string, addr string) (string, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloGolang)
	defer uTlsConn.Close()

	err = uTlsConn.BuildHandshakeState()
	if err != nil {
		// have to call BuildHandshakeState() first, when using default UClient, to avoid settings' overwriting
		return "", fmt.Errorf("uTlsConn.BuildHandshakeState() error: %+v", err)
	}

	masterSecret := make([]byte, 48)
	copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		masterSecret,
		nil, nil)

	uTlsConn.SetSessionState(sessionState)

	err = uTlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	fmt.Println("#> This is how client hello with session ticket looked:")
	fmt.Print(hex.Dump(uTlsConn.HandshakeState.Hello.Raw))

	uTlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	uTlsConn.Read(buf)
	return string(buf), nil
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func HttpGetTicketHelloID(hostname string, addr string, helloID tls.ClientHelloID) (string, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, helloID)
	defer uTlsConn.Close()

	masterSecret := make([]byte, 48)
	copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		masterSecret,
		nil, nil)

	uTlsConn.SetSessionState(sessionState)
	err = uTlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	fmt.Println("#> This is how client hello with session ticket looked:")
	fmt.Print(hex.Dump(uTlsConn.HandshakeState.Hello.Raw))

	uTlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	uTlsConn.Read(buf)
	return string(buf), nil
}

func main() {
	var response string
	var err error
	requestHostname := "www.google.com"
	requestAddr := "172.217.11.46:443"

	response, err = HttpGetDefault(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetDefault failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetDefault response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetByHelloID(requestHostname, requestAddr, tls.HelloAndroid_5_1_Browser)
	if err != nil {
		fmt.Printf("#> HttpGetByHelloID(Android_5_1) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetByHelloID(Android_5_1) response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetByHelloID(requestHostname, requestAddr, tls.HelloRandomizedNoALPN)
	if err != nil {
		fmt.Printf("#> HttpGetByHelloID(Randomized) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetByHelloID(Randomized) response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetExplicitRandom(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetExplicitRandom failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetExplicitRandom response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetTicket(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetTicket failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetTicket response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetTicketHelloID(requestHostname, requestAddr, tls.HelloAndroid_5_1_Browser)
	if err != nil {
		fmt.Printf("#> HttpGetTicketHelloID(Android_5_1) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetTicketHelloID(Android_5_1) response: %+s\n", getFirstLine(response))
	}

	return
}

func getFirstLine(s string) string {
	ss := strings.Split(s, "\r\n")
	if len(ss) == 0 {
		return ""
	} else {
		return ss[0]
	}
}
