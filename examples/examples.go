package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
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

func HttpGetCustom(hostname string, addr string) (string, error) {
	config := tls.Config{ServerName: hostname}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	spec := tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"myFancyProtocol", "h2", "http/1.1"}},
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
				tls.PKCS1WithSHA1},
			},
		},
		GetSessionID: nil,
	}
	err = uTlsConn.ApplyPreset(&spec)

	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	uTlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
	buf := make([]byte, 14096)
	uTlsConn.Read(buf)
	return string(buf), nil
}

var roller *tls.Roller

func HttpGetGoogleWithRoller() (string, error) {
	var err error
	hostname := "www.google.com"
	if roller == nil {
		roller, err = tls.NewRoller()
		if err != nil {
			return "", err
		}
	}

	// As of 2018-07-24 this tries to connect with Chrome, fails due to ChannelID extension
	// being selected by Google, but not supported by utls, and seamlessly moves on to either
	// Firefox or iOS fingerprints, which work.
	c, err := roller.Dial("tcp4", hostname+":443", hostname)
	if err != nil {
		return "", err
	}
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		t := http2.Transport{}
		h2c, err := t.NewClientConn(c)
		if err != nil {
			return "", err
		}
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			return "", err
		}
		resp, err := h2c.RoundTrip(req)
		if err != nil {
			return "", err
		}
		respbytes, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return "", err
		}
		return string(respbytes), nil
	} else {
		c.Write([]byte("GET / HTTP/1.1\r\nHost: " + hostname + "\r\n\r\n"))
		buf := make([]byte, 14096)
		c.Read(buf)
		return string(buf), nil
	}
}

func main() {
	var response string
	var err error

	requestHostname := "tlsfingerprint.io"
	requestAddr := "54.145.209.94:443"

	response, err = HttpGetDefault(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetDefault failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetDefault response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetByHelloID(requestHostname, requestAddr, tls.HelloChrome_62)
	if err != nil {
		fmt.Printf("#> HttpGetByHelloID(HelloChrome_62) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetByHelloID(HelloChrome_62) response: %+s\n", getFirstLine(response))
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

	response, err = HttpGetTicketHelloID(requestHostname, requestAddr, tls.HelloFirefox_56)
	if err != nil {
		fmt.Printf("#> HttpGetTicketHelloID(HelloFirefox_56) failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetTicketHelloID(HelloFirefox_56) response: %+s\n", getFirstLine(response))
	}

	response, err = HttpGetCustom(requestHostname, requestAddr)
	if err != nil {
		fmt.Printf("#> HttpGetCustom() failed: %+v\n", err)
	} else {
		fmt.Printf("#> HttpGetCustom() response: %+s\n", getFirstLine(response))
	}

	for i := 0; i < 5; i++ {
		response, err = HttpGetGoogleWithRoller()
		if err != nil {
			fmt.Printf("#> HttpGetGoogleWithRoller() failed: %+v\n", err)
		} else {
			fmt.Printf("#> HttpGetGoogleWithRoller() response: %+s\n", getFirstLine(response))
		}
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
