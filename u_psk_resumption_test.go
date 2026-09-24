package tls

import (
	"net"
	"testing"
)

// pskHandshakeResult holds what one connection of the resumption test showed.
type pskHandshakeResult struct {
	didResume bool
	sentPSK   bool
}

// pskProfiles holds the PSK profiles that this test runs. HelloChrome_150_PSK covers
// the current Chrome ClientHello. HelloChrome_114_Padding_PSK_Shuf covers the two
// features that change how the binders are written: a padding extension, whose length
// comes from the length of the other extensions, and the extension shuffle, which must
// keep pre_shared_key last. The other PSK profiles follow the same path as
// HelloChrome_150_PSK.
var pskProfiles = []ClientHelloID{
	HelloChrome_150_PSK,
	HelloChrome_114_Padding_PSK_Shuf,
}

// TestPSKProfilesResumeSession runs two connections of each PSK profile against a TLS
// 1.3 server. The first connection gets a session ticket. The second connection sends
// the pre_shared_key extension of the profile and resumes the session, which works only
// if utls computes the binders over the ClientHello that goes on the wire.
func TestPSKProfilesResumeSession(t *testing.T) {
	for _, id := range pskProfiles {
		t.Run(id.Str(), func(t *testing.T) {
			serverConfig, clientConfig := pskTestConfigs()

			first := runPSKHandshake(t, clientConfig, serverConfig, id)
			if first.didResume {
				t.Error("the first connection resumed a session, although no ticket existed")
			}
			if first.sentPSK {
				t.Error("the first connection sent a pre_shared_key extension, although no ticket existed")
			}

			second := runPSKHandshake(t, clientConfig, serverConfig, id)
			if !second.sentPSK {
				t.Fatal("the second connection sent no pre_shared_key extension")
			}
			if !second.didResume {
				t.Error("the second connection did not resume the session")
			}
		})
	}
}

// TestProfileWithoutPSKDoesNotResume covers a profile that holds no pre_shared_key
// extension. Such a profile cannot resume, although the session cache holds a ticket.
// This is what makes the resumption of the PSK profiles a property of the extension,
// and not of the session cache.
func TestProfileWithoutPSKDoesNotResume(t *testing.T) {
	serverConfig, clientConfig := pskTestConfigs()

	runPSKHandshake(t, clientConfig, serverConfig, HelloChrome_150_PSK)

	withoutPSK := runPSKHandshake(t, clientConfig, serverConfig, HelloChrome_150)
	if withoutPSK.sentPSK {
		t.Error("the profile without a pre_shared_key extension sent one")
	}
	if withoutPSK.didResume {
		t.Error("the profile without a pre_shared_key extension resumed a session")
	}
}

// pskTestConfigs returns a TLS 1.3 server config, and a client config that keeps
// sessions.
func pskTestConfigs() (serverConfig, clientConfig *Config) {
	serverConfig = testConfig.Clone()
	serverConfig.MinVersion = VersionTLS13
	serverConfig.MaxVersion = VersionTLS13

	clientConfig = testConfig.Clone()
	clientConfig.MinVersion = VersionTLS13
	clientConfig.MaxVersion = VersionTLS13
	clientConfig.ServerName = "example.go.dev"
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(4)
	// A connection that holds no session yet would fail on the empty pre_shared_key
	// extension. OmitEmptyPsk conceals that extension instead.
	clientConfig.OmitEmptyPsk = true

	return serverConfig, clientConfig
}

// runPSKHandshake runs one client connection against a server that this function
// starts. It returns whether the connection resumed a session, and whether the
// ClientHello held a pre_shared_key extension.
func runPSKHandshake(t *testing.T, clientConfig, serverConfig *Config, id ClientHelloID) pskHandshakeResult {
	t.Helper()

	listener := newLocalListener(t)
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			serverErr <- err

			return
		}
		defer serverConn.Close()

		server := Server(serverConn, serverConfig)
		if err := server.Handshake(); err != nil {
			serverErr <- err

			return
		}

		// The write lets the client read, and the read of the client processes the
		// session tickets that the server sent after the handshake.
		_, err = server.Write([]byte{'x'})
		serverErr <- err
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	client := UClient(clientConn, clientConfig, id)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake with %s: %v", id.Str(), err)
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("client read with %s: %v", id.Str(), err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server with %s: %v", id.Str(), err)
	}

	return pskHandshakeResult{
		didResume: client.ConnectionState().DidResume,
		sentPSK:   clientHelloHoldsExtension(t, client.HandshakeState.Hello.Raw, extensionPreSharedKey),
	}
}

// clientHelloHoldsExtension reports whether a ClientHello holds one extension.
func clientHelloHoldsExtension(t *testing.T, raw []byte, want uint16) bool {
	t.Helper()

	for _, extension := range parseJA4ClientHello(t, raw).extensions {
		if extension.id == want {
			return true
		}
	}

	return false
}
