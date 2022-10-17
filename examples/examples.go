package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	dialTimeout   = time.Duration(15) * time.Second
	sessionTicket = []uint8(`Here goes phony session ticket: phony enough to get into ASCII range
Ticket could be of any length, but for camouflage purposes it's better to use uniformly random contents
and common length. See https://tlsfingerprint.io/session-tickets`)
)

var requestHostname = "facebook.com" // speaks http2 and TLS 1.3
var requestAddr = "31.13.72.36:443"

func HttpGetDefault(hostname string, addr string) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	tlsConn := tls.Client(dialConn, &config)
	defer tlsConn.Close()
	return httpGetOverConn(tlsConn, tlsConn.ConnectionState().NegotiatedProtocol)
}

func HttpGetByHelloID(hostname string, addr string, helloID tls.ClientHelloID) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, helloID)
	defer uTlsConn.Close()

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

// this example generates a randomized fingeprint, then re-uses it in a follow-up connection
func HttpGetConsistentRandomized(hostname string, addr string) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	tcpConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(tcpConn, &config, tls.HelloRandomized)
	defer uTlsConn.Close()
	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	uTlsConn.Close()

	// At this point uTlsConn.ClientHelloID holds a seed that was used to generate
	// randomized fingerprint. Now we can establish second connection with same fp
	tcpConn2, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn2 := tls.UClient(tcpConn2, &config, uTlsConn.ClientHelloID)
	defer uTlsConn2.Close()
	err = uTlsConn2.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return httpGetOverConn(uTlsConn2, uTlsConn2.HandshakeState.ServerHello.AlpnProtocol)
}

func HttpGetExplicitRandom(hostname string, addr string) (*http.Response, error) {
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, nil, tls.HelloGolang)
	defer uTlsConn.Close()

	uTlsConn.SetSNI(hostname) // have to set SNI, if config was nil
	err = uTlsConn.BuildHandshakeState()
	if err != nil {
		// have to call BuildHandshakeState() first, when using default UClient, to avoid settings' overwriting
		return nil, fmt.Errorf("uTlsConn.BuildHandshakeState() error: %+v", err)
	}

	cRandom := []byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131}
	uTlsConn.SetClientRandom(cRandom)
	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	// These fields are accessible regardless of setting client hello explicitly
	fmt.Printf("#> MasterSecret:\n%s", hex.Dump(uTlsConn.HandshakeState.MasterSecret))
	fmt.Printf("#> ClientHello Random:\n%s", hex.Dump(uTlsConn.HandshakeState.Hello.Random))
	fmt.Printf("#> ServerHello Random:\n%s", hex.Dump(uTlsConn.HandshakeState.ServerHello.Random))

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func HttpGetTicket(hostname string, addr string) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloGolang)
	defer uTlsConn.Close()

	err = uTlsConn.BuildHandshakeState()
	if err != nil {
		// have to call BuildHandshakeState() first, when using default UClient, to avoid settings' overwriting
		return nil, fmt.Errorf("uTlsConn.BuildHandshakeState() error: %+v", err)
	}

	masterSecret := make([]byte, 48)
	copy(masterSecret, []byte("masterSecret is NOT sent over the wire")) // you may use it for real security

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		masterSecret,
		nil, nil)

	err = uTlsConn.SetSessionState(sessionState)
	if err != nil {
		return nil, err
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	fmt.Println("#> This is how client hello with session ticket looked:")
	fmt.Print(hex.Dump(uTlsConn.HandshakeState.Hello.Raw))

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

// Note that the server will reject the fake ticket(unless you set up your server to accept them) and do full handshake
func HttpGetTicketHelloID(hostname string, addr string, helloID tls.ClientHelloID) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
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
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	fmt.Println("#> This is how client hello with session ticket looked:")
	fmt.Print(hex.Dump(uTlsConn.HandshakeState.Hello.Raw))

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

func HttpGetCustom(hostname string, addr string) (*http.Response, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	// do not use this particular spec in production
	// make sure to generate a separate copy of ClientHelloSpec for every connection
	spec := tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		TLSVersMin: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256, // tls 1.3
			tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"myFancyProtocol", "http/1.1"}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1}},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{[]uint8{1}}, // pskModeDHE
			&tls.SupportedVersionsExtension{[]uint16{
				tls.VersionTLS13,
				tls.VersionTLS12,
				tls.VersionTLS11,
				tls.VersionTLS10}},
		},
		GetSessionID: nil,
	}
	err = uTlsConn.ApplyPreset(&spec)

	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return httpGetOverConn(uTlsConn, uTlsConn.HandshakeState.ServerHello.AlpnProtocol)
}

var roller *tls.Roller

// this example creates a new roller for each function call,
// however it is advised to reuse the Roller
func HttpGetGoogleWithRoller() (*http.Response, error) {
	var err error
	if roller == nil {
		roller, err = tls.NewRoller()
		if err != nil {
			return nil, err
		}
	}

	// As of 2018-07-24 this tries to connect with Chrome, fails due to ChannelID extension
	// being selected by Google, but not supported by utls, and seamlessly moves on to either
	// Firefox or iOS fingerprints, which work.
	c, err := roller.Dial("tcp4", requestHostname+":443", requestHostname)
	if err != nil {
		return nil, err
	}

	return httpGetOverConn(c, c.HandshakeState.ServerHello.AlpnProtocol)
}

func forgeConn() {
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

	clientUtls.SetUnderlyingConn(clientConn)

	hs := clientUtls.HandshakeState

	// TODO: Redesign this part to use TLS 1.3
	serverTls := tls.MakeConnWithCompleteHandshake(serverConn, hs.ServerHello.Vers, hs.ServerHello.CipherSuite,
		hs.MasterSecret, hs.Hello.Random, hs.ServerHello.Random, false)
	if serverTls == nil {
		fmt.Printf("tls.MakeConnWithCompleteHandshake error, unsupported TLS protocol?")
		return
	}

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

func main() {
	var response *http.Response
	var err error

	response, err = HttpGetDefault(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetDefault failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetDefault response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetByHelloID(requestHostname, requestAddr, tls.HelloChrome_62)
	if err != nil {
		fmt.Printf("#> HttpGetByHelloID(HelloChrome_62) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetByHelloID(HelloChrome_62) response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetConsistentRandomized(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetConsistentRandomized() failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetConsistentRandomized() response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetExplicitRandom(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetExplicitRandom failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetExplicitRandom response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetTicket(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetTicket failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetTicket response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetTicketHelloID(requestHostname, requestAddr, tls.HelloFirefox_56)
	if err != nil {
		fmt.Printf("#> HttpGetTicketHelloID(HelloFirefox_56) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetTicketHelloID(HelloFirefox_56) response: %+s\n", dumpResponseNoBody(response))
	}

	response, err = HttpGetCustom(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetCustom() failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetCustom() response: %+s\n", dumpResponseNoBody(response))
	}

	for i := 0; i < 5; i++ {
		response, err = HttpGetGoogleWithRoller()
		if err != nil {
			fmt.Printf("#> HttpGetGoogleWithRoller() #%v failed: %+v\n", i, err)
		} else {
			fmt.Printf("#> HttpGetGoogleWithRoller() #%v response: %+s\n",
				i, dumpResponseNoBody(response))
		}
	}

	forgeConn()

	return
}

func httpGetOverConn(conn net.Conn, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Host: "www." + requestHostname + "/"},
		Header: make(http.Header),
		Host:   "www." + requestHostname,
	}

	switch alpn {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(conn)
		if err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(conn), req)
	default:
		return nil, fmt.Errorf("unsupported ALPN: %v", alpn)
	}
}

func dumpResponseNoBody(response *http.Response) string {
	resp, err := httputil.DumpResponse(response, false)
	if err != nil {
		return fmt.Sprintf("failed to dump response: %v", err)
	}
	return string(resp)
}
