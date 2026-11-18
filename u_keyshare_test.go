package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
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

	serverConfig := testConfigServer.Clone()
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
		curve = client.ConnectionState().CurveID
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
// first ClientHello carried several classical shares, and that the retry does
// not leak into the caller's spec.
func TestUTLSKeyShareHelloRetryRequest(t *testing.T) {
	shares := []KeyShare{{Group: X25519}, {Group: CurveP384}}
	groups := []CurveID{X25519, CurveP384, CurveP256}
	spec := keyShareTestSpec(shares, groups)

	curve, client, err := keyShareHandshake(t, spec, []CurveID{CurveP256})
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !client.ConnectionState().HelloRetryRequest {
		t.Fatal("server did not send a HelloRetryRequest")
	}
	if curve != CurveP256 {
		t.Fatalf("negotiated %v, want %v", curve, CurveP256)
	}
	if want := keyShareTestSpec(shares, groups); !reflect.DeepEqual(spec, want) {
		t.Errorf("HelloRetryRequest modified the caller's ClientHelloSpec:\n got %+v\nwant %+v",
			specKeyShares(spec), specKeyShares(want))
	}
}

// TestUTLSApplyPresetSpecReuse checks that one ClientHelloSpec can be applied
// to several connections: each one generates fresh keys and completes, and
// the caller's spec is never modified.
func TestUTLSApplyPresetSpecReuse(t *testing.T) {
	shares := firefoxKeyShares()
	groups := []CurveID{X25519MLKEM768, X25519, CurveP256}
	spec := keyShareTestSpec(shares, groups)

	var sent [][]KeyShare
	for i, server := range [][]CurveID{{X25519}, {X25519}, {CurveP256}, {X25519MLKEM768}} {
		curve, client, err := keyShareHandshake(t, spec, server)
		if err != nil {
			t.Fatalf("handshake %d with the same spec failed: %v", i+1, err)
		}
		if curve != server[0] {
			t.Fatalf("handshake %d negotiated %v, want %v", i+1, curve, server[0])
		}
		sent = append(sent, specKeyShares(&ClientHelloSpec{Extensions: client.Extensions}))
	}

	if want := keyShareTestSpec(shares, groups); !reflect.DeepEqual(spec, want) {
		t.Errorf("ApplyPreset modified the caller's ClientHelloSpec:\n got %+v\nwant %+v",
			specKeyShares(spec), specKeyShares(want))
	}

	// Every connection must send fresh key material.
	for i := 1; i < len(sent); i++ {
		for j, ks := range sent[i] {
			if ks.Group == X25519MLKEM768 || isGREASEUint16(uint16(ks.Group)) {
				continue
			}
			if string(ks.Data) == string(sent[0][j].Data) {
				t.Errorf("connection %d resent connection 1's %v public key", i+1, ks.Group)
			}
		}
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
	mlkemKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	hybrid := append(mlkemKey.EncapsulationKey().Bytes(), x25519.PublicKey().Bytes()...)
	tests := []struct {
		name   string
		shares []KeyShare
		server CurveID
	}{
		// Another share has a key, but not the one the server selects.
		{"mixed", []KeyShare{{Group: X25519}, {Group: CurveP256, Data: p256.PublicKey().Bytes()}}, CurveP256},
		// No share has a key at all.
		{"all-explicit", []KeyShare{{Group: X25519, Data: x25519.PublicKey().Bytes()}}, X25519},
		// A hand-written hybrid share next to a generated X25519 share: no
		// ML-KEM key exists for the share the server selects.
		{"hybrid-explicit", []KeyShare{{Group: X25519MLKEM768, Data: hybrid}, {Group: X25519}}, X25519MLKEM768},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := keyShareTestSpec(tt.shares, []CurveID{X25519MLKEM768, X25519, CurveP256})
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
	pub := &KeySharePrivateKeys{Ecdhe: x, AdditionalEcdhe: []*ecdh.PrivateKey{p}}
	priv := pub.ToPrivate()
	if got := priv.ecdheForCurve(ecdh.P256()); got != p {
		t.Errorf("ecdheForCurve(P256) = %v, want the P-256 key", got)
	}
	if got := priv.ecdheForCurve(ecdh.X25519()); got != x {
		t.Errorf("ecdheForCurve(X25519) = %v, want the X25519 key", got)
	}
	if got := priv.ecdheForCurve(ecdh.P384()); got != nil {
		t.Errorf("ecdheForCurve(P384) = %v, want nil", got)
	}
	if back := priv.ToPublic(); !reflect.DeepEqual(back, pub) {
		t.Errorf("ToPrivate().ToPublic() = %+v, want %+v", back, pub)
	}
}

// TestUTLSApplyPresetPerConnectionStateNotInSpec checks that state uTLS keeps
// inside extensions for one connection (GREASE ECH randomness, padding length,
// cached transport parameter bytes) lives in that connection's copy, so a
// reused spec is neither modified nor replayed byte-for-byte.
func TestUTLSApplyPresetPerConnectionStateNotInSpec(t *testing.T) {
	ech := &GREASEEncryptedClientHelloExtension{}
	padding := &UtlsPaddingExtension{GetPaddingLen: func(int) (int, bool) { return 7, true }}
	tp := &QUICTransportParametersExtension{TransportParameters: TransportParameters{InitialMaxData(1)}}
	spec := keyShareTestSpec([]KeyShare{{Group: X25519}}, []CurveID{X25519})
	spec.Extensions = append(spec.Extensions, ech, tp, padding)

	build := func() *UConn {
		t.Helper()
		uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
		if err := uconn.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatal(err)
		}
		return uconn
	}
	first := build()
	// The caller may change its parameters between connections.
	tp.TransportParameters = TransportParameters{InitialMaxData(2)}
	second := build()

	if len(ech.EncapsulatedKey) != 0 || len(ech.payload) != 0 {
		t.Errorf("GREASE ECH state was written into the caller's spec: enc %x", ech.EncapsulatedKey)
	}
	if padding.PaddingLen != 0 || padding.WillPad {
		t.Errorf("padding state was written into the caller's spec: len %d, pad %v", padding.PaddingLen, padding.WillPad)
	}
	if tp.marshalResult != nil {
		t.Errorf("transport parameter bytes were cached in the caller's spec: %x", tp.marshalResult)
	}

	echOf := func(u *UConn) *GREASEEncryptedClientHelloExtension {
		for _, e := range u.Extensions {
			if g, ok := e.(*GREASEEncryptedClientHelloExtension); ok {
				return g
			}
		}
		t.Fatal("no GREASE ECH extension in uconn.Extensions")
		return nil
	}
	if e1, e2 := echOf(first), echOf(second); bytes.Equal(e1.EncapsulatedKey, e2.EncapsulatedKey) ||
		bytes.Equal(e1.payload, e2.payload) {
		t.Error("two connections from one spec sent the same GREASE ECH enc or payload")
	}
	if want := (TransportParameters{InitialMaxData(2)}).Marshal(); !bytes.Contains(second.HandshakeState.Hello.Raw, want) {
		t.Error("second ClientHello carries the first connection's cached transport parameters")
	}
	for _, u := range []*UConn{first, second} {
		if !bytes.Contains(u.HandshakeState.Hello.Raw, []byte{0x00, 0x15, 0x00, 0x07}) {
			t.Error("ClientHello lacks the 7-byte padding extension")
		}
	}
}

func specKeyShares(spec *ClientHelloSpec) []KeyShare {
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*KeyShareExtension); ok {
			return ks.KeyShares
		}
	}
	return nil
}
