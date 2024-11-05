package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pion/dtls/v3/examples/util"
	tls "github.com/refraction-networking/utls"
)

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:6666", "remote address")
	flag.Parse()

	rootCertificate, err := LoadCertificate("certificates/server.pub.pem")
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	dialConn, err := net.Dial("tcp", *remoteAddr)
	if err != nil {
		fmt.Printf("net.Dial() failed: %+v\n", err)
		return
	}

	config := tls.Config{ServerName: "127.0.0.1", Certificates: []tls.Certificate{*rootCertificate}, RootCAs: certPool, ClientSessionCache: tls.NewLRUClientSessionCache(2)}
	tlsConn := tls.Client(dialConn, &config)

	tlsConn.Write([]byte("hi\n"))

	tlsConn.Close()

	dialConn2, err := net.Dial("tcp", *remoteAddr)
	if err != nil {
		fmt.Printf("net.Dial() failed: %+v\n", err)
		return
	}

	tlsConn2 := tls.Client(dialConn2, &config)

	util.Chat(tlsConn2)
}

// LoadCertificate Load/read certificate(s) from file
func LoadCertificate(path string) (*tls.Certificate, error) {
	rawData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errBlockIsNotCertificate
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errNoCertificateFound
	}

	return &certificate, nil
}

var (
	errBlockIsNotCertificate = errors.New("block is not a certificate, unable to load certificates")
	errNoCertificateFound    = errors.New("no certificate found, unable to load certificates")
)
