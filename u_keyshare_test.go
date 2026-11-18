package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

// keyShareTestSpec returns a TLS 1.3-only ClientHelloSpec offering the given
// key shares and supported groups. It contains every extension type that
// ApplyPreset or the handshake rewrite per connection (SNI, GREASE, supported
// groups, key shares, supported versions), so tests can also check that the
// caller's spec is left untouched.
func keyShareTestSpec(shares []KeyShare, groups []CurveID) *ClientHelloSpec {
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS13,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: append([]CurveID{GREASE_PLACEHOLDER}, groups...)},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
			}},
			&KeyShareExtension{KeyShares: append([]KeyShare{{Group: GREASE_PLACEHOLDER, Data: []byte{0}}}, shares...)},
			&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13}},
			&UtlsGREASEExtension{},
		},
	}
}

// firefoxKeyShares mirrors Firefox's key shares: X25519MLKEM768 and X25519
// sharing one X25519 key, followed by a P-256 share.
func firefoxKeyShares() []KeyShare {
	return append(
		ReuseHybridAndClassicalKeyShares(KeyShare{Group: X25519MLKEM768}, KeyShare{Group: X25519}),
		KeyShare{Group: CurveP256},
	)
}

// keyShareHandshake runs one TLS 1.3 handshake of a HelloCustom client built
// from spec against this package's server, which accepts only serverGroups.
// It returns the group the connection negotiated and the client UConn.
func keyShareHandshake(t *testing.T, spec *ClientHelloSpec, serverGroups []CurveID) (CurveID, *UConn, error) {
	t.Helper()

	serverConfig := testConfig.Clone()
	serverConfig.CurvePreferences = serverGroups
	serverConfig.MinVersion = VersionTLS13
	clientConfig := &Config{
		ServerName:         "example.golang",
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS13,
		MaxVersion:         VersionTLS13,
	}

	c, s := localPipe(t)
	defer c.Close()

	client := UClient(c, clientConfig, HelloCustom)
	if err := client.ApplyPreset(spec); err != nil {
		s.Close()
		return 0, client, fmt.Errorf("ApplyPreset: %w", err)
	}

	const msg = "ping"
	serverErr := make(chan error, 1)
	go func() {
		defer s.Close()
		server := Server(s, serverConfig)
		err := server.Handshake()
		if err == nil {
			_, err = io.WriteString(server, msg)
		}
		if err != nil {
			err = fmt.Errorf("server: %w", err)
		}
		serverErr <- err
	}()

	var curve CurveID
	clientErr := client.Handshake()
	if clientErr == nil {
		curve = client.ConnectionState().testingOnlyCurveID
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(client, buf); err != nil {
			clientErr = fmt.Errorf("read: %w", err)
		} else if string(buf) != msg {
			clientErr = fmt.Errorf("read %q, want %q", buf, msg)
		}
	}
	if clientErr != nil {
		clientErr = fmt.Errorf("client: %w", clientErr)
		c.Close()
	}
	return curve, client, errors.Join(clientErr, <-serverErr)
}

// TestUTLSKeyShareServerSelectsAnyOfferedGroup checks that the client keeps a
// private key for every key share it offers, so the handshake completes
// whichever offered group the server selects.
func TestUTLSKeyShareServerSelectsAnyOfferedGroup(t *testing.T) {
	tests := []struct {
		name   string
		shares []KeyShare
		groups []CurveID
		server []CurveID
	}{
		{"classical/X25519", []KeyShare{{Group: X25519}, {Group: CurveP256}, {Group: CurveP384}},
			[]CurveID{X25519, CurveP256, CurveP384}, []CurveID{X25519}},
		{"classical/P256", []KeyShare{{Group: X25519}, {Group: CurveP256}, {Group: CurveP384}},
			[]CurveID{X25519, CurveP256, CurveP384}, []CurveID{CurveP256}},
		{"classical/P384", []KeyShare{{Group: X25519}, {Group: CurveP256}, {Group: CurveP384}},
			[]CurveID{X25519, CurveP256, CurveP384}, []CurveID{CurveP384}},
		{"firefox/X25519MLKEM768", firefoxKeyShares(),
			[]CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384}, []CurveID{X25519MLKEM768}},
		{"firefox/X25519", firefoxKeyShares(),
			[]CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384}, []CurveID{X25519}},
		{"firefox/P256", firefoxKeyShares(),
			[]CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384}, []CurveID{CurveP256}},
		{"chrome/X25519MLKEM768", []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}},
			[]CurveID{X25519MLKEM768, X25519, CurveP256}, []CurveID{X25519MLKEM768}},
		{"chrome/X25519", []KeyShare{{Group: X25519MLKEM768}, {Group: X25519}},
			[]CurveID{X25519MLKEM768, X25519, CurveP256}, []CurveID{X25519}},
		// The hybrid share must use its own X25519 key even when the first
		// classical share is on another curve.
		{"hybrid+P256/X25519MLKEM768", []KeyShare{{Group: X25519MLKEM768}, {Group: CurveP256}},
			[]CurveID{X25519MLKEM768, CurveP256}, []CurveID{X25519MLKEM768}},
		{"hybrid+P256/P256", []KeyShare{{Group: X25519MLKEM768}, {Group: CurveP256}},
			[]CurveID{X25519MLKEM768, CurveP256}, []CurveID{CurveP256}},
		{"hybrid-only/X25519MLKEM768", []KeyShare{{Group: X25519MLKEM768}},
			[]CurveID{X25519MLKEM768}, []CurveID{X25519MLKEM768}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, _, err := keyShareHandshake(t, keyShareTestSpec(tt.shares, tt.groups), tt.server)
			if err != nil {
				t.Fatalf("handshake failed: %v", err)
			}
			if curve != tt.server[0] {
				t.Fatalf("negotiated %v, want %v", curve, tt.server[0])
			}
		})
	}
}

// TestUTLSKeyShareHelloRetryRequest checks that a HelloRetryRequest for a
// group the client supports but sent no share for still completes when the
// first ClientHello carried several classical shares.
func TestUTLSKeyShareHelloRetryRequest(t *testing.T) {
	shares := []KeyShare{{Group: X25519}, {Group: CurveP384}}
	groups := []CurveID{X25519, CurveP384, CurveP256}
	spec := keyShareTestSpec(shares, groups)

	curve, client, err := keyShareHandshake(t, spec, []CurveID{CurveP256})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !client.ConnectionState().testingOnlyDidHRR {
		t.Fatal("server did not send a HelloRetryRequest")
	}
	if curve != CurveP256 {
		t.Fatalf("negotiated %v, want %v", curve, CurveP256)
	}
}

// TestUTLSKeyShareExplicitDataFailsClearly checks that when the server picks
// a group whose share was given as explicit bytes (so no private key exists),
// the handshake fails with an error naming the cause.
func TestUTLSKeyShareExplicitDataFailsClearly(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		shares []KeyShare
		server CurveID
	}{
		// Another share has a key, but not the one the server selects.
		{"mixed", []KeyShare{{Group: X25519}, {Group: CurveP256, Data: p256.PublicKey().Bytes()}}, CurveP256},
		// No share has a key at all.
		{"all-explicit", []KeyShare{{Group: X25519, Data: x25519.PublicKey().Bytes()}}, X25519},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := keyShareTestSpec(tt.shares, []CurveID{X25519, CurveP256})
			_, _, err := keyShareHandshake(t, spec, []CurveID{tt.server})
			if err == nil {
				t.Fatal("handshake succeeded without the private key for the selected share")
			}
			if !strings.Contains(err.Error(), "no private key") {
				t.Fatalf("error does not name the missing private key: %v", err)
			}
		})
	}
}

func TestUTLSKeySharePrivateKeysConversion(t *testing.T) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &KeySharePrivateKeys{CurveID: X25519, Ecdhe: x, AdditionalEcdhe: []*ecdh.PrivateKey{p}}
	priv := pub.ToPrivate()
	if got := priv.ecdheForGroup(CurveP256); got != p {
		t.Errorf("ecdheForGroup(P256) = %v, want the P-256 key", got)
	}
	if got := priv.ecdheForGroup(X25519); got != x {
		t.Errorf("ecdheForGroup(X25519) = %v, want the X25519 key", got)
	}
	if got := priv.ecdheForGroup(CurveP384); got != nil {
		t.Errorf("ecdheForGroup(P384) = %v, want nil", got)
	}
	if back := priv.ToPublic(); !reflect.DeepEqual(back, pub) {
		t.Errorf("ToPrivate().ToPublic() = %+v, want %+v", back, pub)
	}
}
