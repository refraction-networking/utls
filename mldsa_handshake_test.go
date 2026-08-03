//go:build !nomldsa

package tls

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestHandshakeServerMLDSACertificateTLS13(t *testing.T) {
	for _, test := range mldsaHandshakeTests() {
		t.Run(test.name, func(t *testing.T) {
			serverCert, err := X509KeyPair([]byte(test.serverCertPEM), []byte(testingKeyToPrivateKeyPEM(test.serverKeyPEM)))
			if err != nil {
				t.Fatal(err)
			}
			rootCAs := x509.NewCertPool()
			if !rootCAs.AppendCertsFromPEM([]byte(testRootCertPEM)) {
				t.Fatal("failed to append root cert")
			}
			clientConfig := &Config{
				ServerName: "test.golang.example",
				RootCAs:    rootCAs,
				Time:       mldsaTestTime,
				MinVersion: VersionTLS13,
				MaxVersion: VersionTLS13,
			}
			serverConfig := &Config{
				Certificates: []Certificate{serverCert},
				MinVersion:   VersionTLS13,
				MaxVersion:   VersionTLS13,
			}
			client, server := localPipe(t)
			defer client.Close()
			defer server.Close()

			errChan := make(chan error, 1)
			go func() {
				errChan <- Server(server, serverConfig).Handshake()
			}()
			clientConn := Client(client, clientConfig)
			if err := clientConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-errChan; err != nil {
				t.Fatal(err)
			}
			if got := clientConn.ConnectionState().Version; got != VersionTLS13 {
				t.Fatalf("version = %#x, want TLS 1.3", got)
			}
			expectMLDSAPublicKey(t, clientConn.ConnectionState().PeerCertificates[0].PublicKey, test.sigAlg)
		})
	}
}

func TestHandshakeClientMLDSACertificateTLS13(t *testing.T) {
	for _, test := range mldsaHandshakeTests() {
		t.Run(test.name, func(t *testing.T) {
			serverCert, err := X509KeyPair([]byte(test.serverCertPEM), []byte(testingKeyToPrivateKeyPEM(test.serverKeyPEM)))
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := X509KeyPair([]byte(test.clientCertPEM), []byte(testingKeyToPrivateKeyPEM(test.clientKeyPEM)))
			if err != nil {
				t.Fatal(err)
			}
			rootCAs := x509.NewCertPool()
			if !rootCAs.AppendCertsFromPEM([]byte(testRootCertPEM)) {
				t.Fatal("failed to append root cert")
			}
			clientCAs := x509.NewCertPool()
			if !clientCAs.AppendCertsFromPEM([]byte(testClientRootCertPEM)) {
				t.Fatal("failed to append client root cert")
			}
			clientConfig := &Config{
				ServerName:   "test.golang.example",
				RootCAs:      rootCAs,
				Certificates: []Certificate{clientCert},
				Time:         mldsaTestTime,
				MinVersion:   VersionTLS13,
				MaxVersion:   VersionTLS13,
			}
			serverConfig := &Config{
				Certificates: []Certificate{serverCert},
				ClientAuth:   RequireAndVerifyClientCert,
				ClientCAs:    clientCAs,
				Time:         mldsaTestTime,
				MinVersion:   VersionTLS13,
				MaxVersion:   VersionTLS13,
			}
			client, server := localPipe(t)
			defer client.Close()
			defer server.Close()

			serverConn := Server(server, serverConfig)
			errChan := make(chan error, 1)
			go func() {
				errChan <- serverConn.Handshake()
			}()
			clientConn := Client(client, clientConfig)
			if err := clientConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-errChan; err != nil {
				t.Fatal(err)
			}
			state := serverConn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				t.Fatal("server did not receive peer certificate")
			}
			expectMLDSAPublicKey(t, state.PeerCertificates[0].PublicKey, test.sigAlg)
		})
	}
}

func mldsaHandshakeTests() []struct {
	name          string
	sigAlg        SignatureScheme
	serverCertPEM string
	serverKeyPEM  string
	clientCertPEM string
	clientKeyPEM  string
} {
	return []struct {
		name          string
		sigAlg        SignatureScheme
		serverCertPEM string
		serverKeyPEM  string
		clientCertPEM string
		clientKeyPEM  string
	}{
		{"MLDSA44", MLDSA44, testMLDSA44CertPEM, testMLDSA44KeyPEM, testClientMLDSA44CertPEM, testClientMLDSA44KeyPEM},
		{"MLDSA65", MLDSA65, testMLDSA65CertPEM, testMLDSA65KeyPEM, testClientMLDSA65CertPEM, testClientMLDSA65KeyPEM},
		{"MLDSA87", MLDSA87, testMLDSA87CertPEM, testMLDSA87KeyPEM, testClientMLDSA87CertPEM, testClientMLDSA87KeyPEM},
	}
}

func mldsaTestTime() time.Time {
	return time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC)
}
