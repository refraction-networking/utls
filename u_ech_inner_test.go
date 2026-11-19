package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// echTestKey returns an ECH key for the given public name and the matching
// ECHConfigList a client offers it with.
func echTestKey(t *testing.T, publicName string) (EncryptedClientHelloKey, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7) // config id
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0001) // HKDF-SHA256
			b.AddUint16(0x0001) // AES-128-GCM
		})
		b.AddUint8(64) // maximum name length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	config := b.BytesOrPanic()
	var list cryptobyte.Builder
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	return EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}, list.BytesOrPanic()
}

// extensionID returns the extension type an extension marshals as.
func extensionID(t *testing.T, ext TLSExtension) uint16 {
	t.Helper()
	buf := make([]byte, ext.Len())
	if _, err := ext.Read(buf); err != nil && err.Error() != "EOF" {
		t.Fatal(err)
	}
	return uint16(buf[0])<<8 | uint16(buf[1])
}

func isTLS13CipherSuite(id uint16) bool { return id >= 0x1301 && id <= 0x1305 }

// innerHelloFromOuter applies BoringSSL's rules for ClientHelloInner to the
// outer hello a connection built: only the GREASE and TLS 1.3 cipher suites;
// the extensions that differ between the two hellos (server_name,
// encrypted_client_hello, supported_versions, and application-layer protocol
// negotiation when the config overrides it) uncompressed in outer order,
// followed by every extension that is the same in both, compressed, in outer
// order; and none of the TLS 1.2-only extensions nor padding.
func innerHelloFromOuter(t *testing.T, client *UConn, alpnFromConfig bool) (cipherSuites, extensions []uint16) {
	t.Helper()
	for _, id := range client.HandshakeState.Hello.CipherSuites {
		if isGREASEUint16(id) || isTLS13CipherSuite(id) {
			cipherSuites = append(cipherSuites, id)
		}
	}
	var compressed []uint16
	for _, ext := range client.Extensions {
		id := extensionID(t, ext)
		switch ext.(type) {
		case *RenegotiationInfoExtension, *ExtendedMasterSecretExtension, *SessionTicketExtension,
			*SupportedPointsExtension, *NPNExtension, *UtlsPaddingExtension, PreSharedKeyExtension:
			continue
		case *SNIExtension, *SupportedVersionsExtension, EncryptedClientHelloExtension:
			extensions = append(extensions, id)
		case *ALPNExtension:
			if alpnFromConfig {
				extensions = append(extensions, id)
			} else {
				compressed = append(compressed, id)
			}
		default:
			compressed = append(compressed, id)
		}
	}
	return cipherSuites, append(extensions, compressed...)
}

// retryGroup returns the first group a spec supports without offering a key
// share for it, which a server preferring it answers with a HelloRetryRequest.
func retryGroup(t *testing.T, spec *ClientHelloSpec) CurveID {
	t.Helper()
	var curves []CurveID
	shared := map[CurveID]bool{}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *SupportedCurvesExtension:
			curves = e.Curves
		case *KeyShareExtension:
			for _, ks := range e.KeyShares {
				shared[ks.Group] = true
			}
		}
	}
	for _, c := range curves {
		if !isGREASEUint16(uint16(c)) && !shared[c] {
			if _, err := keyExchangeForCurveID(c); err == nil {
				return c
			}
		}
	}
	t.Fatal("the spec offers a key share for every group it supports")
	return 0
}

// echHandshakeWithSpec handshakes a spec with real ECH against a server that
// accepts it and returns the ClientHelloInfo the server negotiated with, the
// client, and its connection state.
func echHandshakeWithSpec(t *testing.T, spec *ClientHelloSpec, clientConfig, serverConfig *Config) (*ClientHelloInfo, *UConn, ConnectionState) {
	t.Helper()
	var seen *ClientHelloInfo
	serverConfig.GetConfigForClient = func(info *ClientHelloInfo) (*Config, error) {
		seen = info
		return nil, nil
	}
	c, s := localPipe(t)
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	client := UClient(c, clientConfig, HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Server(s, serverConfig).Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server: %v", err)
	}
	if seen == nil {
		t.Fatal("the server never saw a ClientHello")
	}
	return seen, client, client.ConnectionState()
}

// TestUTLSECHInnerHelloFollowsSpec checks that with real ECH the server, which
// negotiates with the inner ClientHello, sees the spec's hello transformed as
// BoringSSL transforms Chrome's, not a hello built from Go's defaults; with and
// without a HelloRetryRequest.
func TestUTLSECHInnerHelloFollowsSpec(t *testing.T) {
	for _, id := range []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto} {
		for _, retry := range []bool{false, true} {
			name := id.Str()
			if retry {
				name += "/HelloRetryRequest"
			}
			t.Run(name, func(t *testing.T) {
				spec, err := utlsIdToSpec(id)
				if err != nil {
					t.Fatal(err)
				}
				key, configList := echTestKey(t, "public.example")
				clientConfig := testConfigClient.Clone()
				clientConfig.EncryptedClientHelloConfigList = configList
				serverConfig := testConfigServer.Clone()
				serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{key}
				var group CurveID
				if retry {
					group = retryGroup(t, &spec)
					serverConfig.CurvePreferences = []CurveID{group}
				}

				info, client, state := echHandshakeWithSpec(t, &spec, clientConfig, serverConfig)
				if !state.ECHAccepted || state.HelloRetryRequest != retry {
					t.Fatalf("ECHAccepted=%v HelloRetryRequest=%v, want true and %v", state.ECHAccepted, state.HelloRetryRequest, retry)
				}
				if retry && state.CurveID != group {
					t.Fatalf("negotiated group %v, want the retried %v", state.CurveID, group)
				}
				wantSuites, wantExtensions := innerHelloFromOuter(t, client, false)
				if !slices.Equal(info.CipherSuites, wantSuites) {
					t.Errorf("inner cipher suites %v, want %v", info.CipherSuites, wantSuites)
				}
				if !slices.Equal(info.Extensions, wantExtensions) {
					t.Errorf("inner extensions %v, want %v", info.Extensions, wantExtensions)
				}
				if info.ServerName != clientConfig.ServerName {
					t.Errorf("inner server name %q, want %q", info.ServerName, clientConfig.ServerName)
				}
				var wantALPN []string
				for _, ext := range client.Extensions {
					if alpn, ok := ext.(*ALPNExtension); ok {
						wantALPN = alpn.AlpnProtocols
					}
				}
				if !slices.Equal(info.SupportedProtos, wantALPN) {
					t.Errorf("inner ALPN %v, want the spec's %v", info.SupportedProtos, wantALPN)
				}
				for _, v := range info.SupportedVersions {
					if !isGREASEUint16(v) && v < VersionTLS13 {
						t.Errorf("inner offers version %#x; only TLS 1.3 may be offered", v)
					}
				}
			})
		}
	}
}

// TestUTLSECHInnerHelloALPNFromConfig checks that Config.NextProtos, when set,
// replaces the spec's ALPN in the inner hello only, as the outer keeps the
// spec's, so an application can offer one protocol under cover of the other.
func TestUTLSECHInnerHelloALPNFromConfig(t *testing.T) {
	spec, err := utlsIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	key, configList := echTestKey(t, "public.example")
	clientConfig := testConfigClient.Clone()
	clientConfig.EncryptedClientHelloConfigList = configList
	clientConfig.NextProtos = []string{"http/1.1"}
	serverConfig := testConfigServer.Clone()
	serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{key}

	info, client, state := echHandshakeWithSpec(t, &spec, clientConfig, serverConfig)
	if !state.ECHAccepted {
		t.Fatal("ECH was not accepted")
	}
	if !slices.Equal(info.SupportedProtos, clientConfig.NextProtos) {
		t.Errorf("inner ALPN %v, want the config's %v", info.SupportedProtos, clientConfig.NextProtos)
	}
	_, wantExtensions := innerHelloFromOuter(t, client, true)
	if !slices.Equal(info.Extensions, wantExtensions) {
		t.Errorf("inner extensions %v, want %v", info.Extensions, wantExtensions)
	}
}
