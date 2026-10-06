package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
)

// JA4 is a fingerprint of a TLS ClientHello. It has three parts, joined by underscores.
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
//	a: the transport, the TLS version, whether SNI is present, the number of cipher
//	   suites, the number of extensions, and the first and last character of the first
//	   ALPN protocol.
//	b: the first 12 hex characters of the SHA-256 of the sorted cipher suites, without
//	   GREASE.
//	c: the first 12 hex characters of the SHA-256 of the sorted extensions, without
//	   GREASE, SNI and ALPN, then an underscore, then the signature algorithms in the
//	   order that the ClientHello sends them.
//
// The sort makes JA4 the same for every connection of one profile, although
// ShuffleChromeTLSExtensions gives the extensions a new order for each connection.

// ja4Captures holds the captured JA4 of each profile. Add a line to test another
// profile.
var ja4Captures = []struct {
	id  ClientHelloID
	ja4 string
}{
	{id: HelloChrome_150, ja4: "t13d1516h2_8daaf6152771_806a8c22fdea"},
	{id: HelloChrome_150_PSK, ja4: "t13d1517h2_8daaf6152771_a87ad97598a9"},
	{id: HelloChrome_133, ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd"},
	{id: HelloSafari_26_3, ja4: "t13d2013h2_a09f3c656075_7f0f34a4126d"},
	{id: HelloSafari_26_0, ja4: "t13d2013h2_a09f3c656075_7f0f34a4126d"},
	{id: HelloSafari_18_5, ja4: "t13d2014h2_a09f3c656075_e42f34c56612"},
	{id: HelloSafari_16_0, ja4: "t13d2014h2_a09f3c656075_14788d8d241b"},
}

// TestProfilesJA4 compares the ClientHello of each profile against its captured
// JA4. A change of a cipher suite, an extension, or a signature algorithm changes the
// JA4, so this test fails if a profile changes by accident.
func TestProfilesJA4(t *testing.T) {
	for _, capture := range ja4Captures {
		t.Run(capture.id.Str(), func(t *testing.T) {
			got := ja4(t, buildJA4ClientHello(t, capture.id))
			if got != capture.ja4 {
				t.Errorf("JA4 = %s, want %s", got, capture.ja4)
			}
		})
	}
}

// TestProfilesJA4IsStable checks that the JA4 of a profile is the same on every
// connection. Chrome shuffles its extensions, and a fingerprint that changed with the
// shuffle would identify utls rather than the browser.
func TestProfilesJA4IsStable(t *testing.T) {
	const connections = 16

	for _, capture := range ja4Captures {
		t.Run(capture.id.Str(), func(t *testing.T) {
			for i := 0; i < connections; i++ {
				got := ja4(t, buildJA4ClientHello(t, capture.id))
				if got != capture.ja4 {
					t.Fatalf("connection %d gave JA4 %s, want %s", i, got, capture.ja4)
				}
			}
		})
	}
}

// TestChrome150PSKWithoutSession covers the PSK profile without a session. utls then
// conceals the empty pre_shared_key extension, so the ClientHello holds one extension
// less and the fingerprint becomes the one of Chrome 150 without PSK.
func TestChrome150PSKWithoutSession(t *testing.T) {
	want := ja4Captures[0].ja4 // Chrome 150 without PSK

	if got := ja4(t, buildJA4ClientHelloWithoutSession(t, HelloChrome_150_PSK)); got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
}

// buildJA4ClientHello returns the ClientHello bytes that the given profile produces. A
// profile that holds a pre_shared_key extension gets a session, so that the extension
// goes on the wire with a fixed identity and a fixed binder, which is what a resumed
// connection sends.
func buildJA4ClientHello(t *testing.T, id ClientHelloID) []byte {
	t.Helper()

	config := &Config{ServerName: "example.com"}
	if profileSendsPSK(t, id) {
		config.ClientSessionCache = NewLRUClientSessionCache(1)
	}

	uconn := UClient(&net.TCPConn{}, config, id)
	if config.ClientSessionCache != nil {
		psk := &FakePreSharedKeyExtension{
			Identities: []PskIdentity{{Label: []byte("ja4-test-ticket"), ObfuscatedTicketAge: 0x1234}},
			Binders:    [][]byte{make([]byte, 32)},
		}
		if err := uconn.SetPskExtension(psk); err != nil {
			t.Fatalf("SetPskExtension: %v", err)
		}
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	return uconn.HandshakeState.Hello.Raw
}

// buildJA4ClientHelloWithoutSession returns the ClientHello bytes of a profile that
// carries no session. OmitEmptyPsk lets a PSK profile build a ClientHello although no
// session exists.
func buildJA4ClientHelloWithoutSession(t *testing.T, id ClientHelloID) []byte {
	t.Helper()

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com", OmitEmptyPsk: true}, id)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}

	return uconn.HandshakeState.Hello.Raw
}

// profileSendsPSK reports whether the spec of a profile holds a pre_shared_key
// extension.
func profileSendsPSK(t *testing.T, id ClientHelloID) bool {
	t.Helper()

	spec, err := UTLSIdToSpec(id)
	if err != nil {
		t.Fatalf("UTLSIdToSpec: %v", err)
	}

	for _, extension := range spec.Extensions {
		if _, ok := extension.(PreSharedKeyExtension); ok {
			return true
		}
	}

	return false
}

// ja4 returns the JA4 of a ClientHello.
func ja4(t *testing.T, raw []byte) string {
	t.Helper()

	hello := parseJA4ClientHello(t, raw)

	var cipherSuites []string
	for _, cipherSuite := range hello.cipherSuites {
		if isGREASEUint16(cipherSuite) {
			continue
		}
		cipherSuites = append(cipherSuites, fmt.Sprintf("%04x", cipherSuite))
	}

	var (
		extensions []string
		sigAlgs    []string
		alpn       string
		version    = "12"
		sni        = "i"
		count      int
	)
	for _, extension := range hello.extensions {
		if isGREASEUint16(extension.id) {
			continue
		}
		count++

		switch extension.id {
		case extensionServerName:
			sni = "d"
		case extensionALPN:
			alpn = ja4FirstALPNProtocol(t, extension.body)
		case extensionSignatureAlgorithms:
			for _, sigAlg := range ja4SignatureAlgorithms(t, extension.body) {
				if isGREASEUint16(sigAlg) {
					continue
				}
				sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", sigAlg))
			}
		case extensionSupportedVersions:
			if ja4SendsTLS13(extension.body) {
				version = "13"
			}
		}

		// JA4 counts SNI and ALPN, but it keeps them out of the sorted list.
		if extension.id != extensionServerName && extension.id != extensionALPN {
			extensions = append(extensions, fmt.Sprintf("%04x", extension.id))
		}
	}

	sort.Strings(cipherSuites)
	sort.Strings(extensions)

	alpnCode := "00"
	if alpn != "" {
		alpnCode = string(alpn[0]) + string(alpn[len(alpn)-1])
	}

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		version, sni, len(cipherSuites), count, alpnCode,
		ja4Hash(strings.Join(cipherSuites, ",")),
		ja4Hash(strings.Join(extensions, ",")+"_"+strings.Join(sigAlgs, ",")))
}

// ja4Hash returns the first 12 hex characters of the SHA-256 of s.
func ja4Hash(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])[:12]
}

// ja4SignatureAlgorithms returns the algorithms of a signature_algorithms extension.
func ja4SignatureAlgorithms(t *testing.T, body []byte) []uint16 {
	t.Helper()

	if len(body) < 2 {
		t.Fatal("signature_algorithms extension is shorter than its length field")
	}

	var sigAlgs []uint16
	for i := 2; i+1 < len(body); i += 2 {
		sigAlgs = append(sigAlgs, binary.BigEndian.Uint16(body[i:i+2]))
	}

	return sigAlgs
}

// ja4FirstALPNProtocol returns the first protocol of an ALPN extension.
func ja4FirstALPNProtocol(t *testing.T, body []byte) string {
	t.Helper()

	if len(body) < 3 {
		t.Fatal("ALPN extension is shorter than its length fields")
	}
	length := int(body[2])
	if len(body) < 3+length {
		t.Fatal("ALPN protocol runs past the end of the extension")
	}

	return string(body[3 : 3+length])
}

// ja4SendsTLS13 reports whether a supported_versions extension holds TLS 1.3.
func ja4SendsTLS13(body []byte) bool {
	for i := 1; i+1 < len(body); i += 2 {
		if binary.BigEndian.Uint16(body[i:i+2]) == VersionTLS13 {
			return true
		}
	}

	return false
}

// ja4ClientHello holds the parts of a ClientHello that JA4 needs.
type ja4ClientHello struct {
	cipherSuites []uint16
	extensions   []ja4Extension
}

type ja4Extension struct {
	id   uint16
	body []byte
}

// parseJA4ClientHello reads a ClientHello handshake message. It fails the test on a
// short or malformed message, which can only come from this package.
func parseJA4ClientHello(t *testing.T, raw []byte) ja4ClientHello {
	t.Helper()

	reader := &ja4ByteReader{t: t, data: raw}
	reader.skip(4)      // handshake type and length
	reader.skip(2 + 32) // legacy version and random
	reader.skip(int(reader.uint8()))
	cipherSuites := reader.bytes(int(reader.uint16()))
	reader.skip(int(reader.uint8()))
	extensions := reader.bytes(int(reader.uint16()))

	hello := ja4ClientHello{}
	for i := 0; i+1 < len(cipherSuites); i += 2 {
		hello.cipherSuites = append(hello.cipherSuites, binary.BigEndian.Uint16(cipherSuites[i:i+2]))
	}

	extensionReader := &ja4ByteReader{t: t, data: extensions}
	for len(extensionReader.data) > 0 {
		id := extensionReader.uint16()
		hello.extensions = append(hello.extensions, ja4Extension{
			id:   id,
			body: extensionReader.bytes(int(extensionReader.uint16())),
		})
	}

	return hello
}

// ja4ByteReader reads the fields of a handshake message in order. Every method fails
// the test if the message is too short.
type ja4ByteReader struct {
	t    *testing.T
	data []byte
}

func (r *ja4ByteReader) bytes(n int) []byte {
	r.t.Helper()

	if len(r.data) < n {
		r.t.Fatalf("ClientHello ends after %d bytes, want %d more", len(r.data), n)
	}
	head := r.data[:n]
	r.data = r.data[n:]

	return head
}

func (r *ja4ByteReader) skip(n int) {
	r.t.Helper()
	r.bytes(n)
}

func (r *ja4ByteReader) uint8() uint8 {
	r.t.Helper()

	return r.bytes(1)[0]
}

func (r *ja4ByteReader) uint16() uint16 {
	r.t.Helper()

	return binary.BigEndian.Uint16(r.bytes(2))
}
