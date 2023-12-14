package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var (
	dialTimeout = time.Duration(15) * time.Second
)

// var requestHostname = "crypto.cloudflare.com" // speaks http2 and TLS 1.3 and ECH and PQ
// var requestAddr = "crypto.cloudflare.com:443"
// var requestPath = "/cdn-cgi/trace"

// var requestHostname = "tls-ech.dev" // speaks http2 and TLS 1.3 and ECH and PQ
// var requestAddr = "tls-ech.dev:443"
// var requestPath = "/"

var requestHostname = "defo.ie" // speaks http2 and TLS 1.3 and ECH and PQ
var requestAddr = "defo.ie:443"
var requestPath = "/ech-check.php"

// var requestHostname = "client.tlsfingerprint.io" // speaks http2 and TLS 1.3 and ECH and PQ
// var requestAddr = "client.tlsfingerprint.io:443"
// var requestPath = "/"

func HttpGetCustom(hostname string, addr string) (*http.Response, error) {
	klw, err := os.OpenFile("./sslkeylogging.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("os.OpenFile error: %+v", err)
	}
	config := tls.Config{
		ServerName:   hostname,
		KeyLogWriter: klw,
	}
	dialConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.DialTimeout error: %+v", err)
	}
	uTlsConn := tls.UClient(dialConn, &config, tls.HelloCustom)
	defer uTlsConn.Close()

	// do not use this particular spec in production
	// make sure to generate a separate copy of ClientHelloSpec for every connection
	spec, err := tls.UTLSIdToSpec(tls.HelloChrome_120)
	// spec, err := tls.UTLSIdToSpec(tls.HelloFirefox_120)
	if err != nil {
		return nil, fmt.Errorf("tls.UTLSIdToSpec error: %+v", err)
	}

	err = uTlsConn.ApplyPreset(&spec)
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	err = uTlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	return httpGetOverConn(uTlsConn, uTlsConn.ConnectionState().NegotiatedProtocol)
}

func httpGetOverConn(conn net.Conn, alpn string) (*http.Response, error) {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "https", Host: requestHostname, Path: requestPath},
		Header: make(http.Header),
		Host:   requestHostname,
	}

	switch alpn {
	case "h2":
		log.Println("HTTP/2 enabled")
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
		log.Println("Using HTTP/1.1")
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

func main() {
	resp, err := HttpGetCustom(requestHostname, requestAddr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Response: %+v\n", resp)
	// read from resp.Body
	body := make([]byte, 65535)
	n, err := resp.Body.Read(body)
	if err != nil && !errors.Is(err, io.EOF) {
		panic(err)
	}

	fmt.Printf("Body: %s\n", body[:n])
}
