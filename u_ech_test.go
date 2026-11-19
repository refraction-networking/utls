package tls_test

import (
	"errors"
	"io"
	"net"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	tls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
)

// boringSSLGREASEECHWireLens are the payload lengths BoringSSL sends in a
// GREASE ECH extension: 32 bytes times a random integer in [4, 7], plus the
// 16-byte AEAD tag, drawn afresh for every connection.
var boringSSLGREASEECHWireLens = []int{144, 176, 208, 240}

// greaseECHBody parses the body of an encrypted_client_hello extension (the
// bytes after the 4-byte extension header) and returns the HPKE suite, the
// encapsulated key length and the payload length as sent.
func greaseECHBody(t *testing.T, body []byte) (suite tls.HPKESymmetricCipherSuite, encLen, payloadLen int) {
	t.Helper()
	s := cryptobyte.String(body)
	var chType, configID uint8
	var enc, payload cryptobyte.String
	if !s.ReadUint8(&chType) || chType != 0 ||
		!s.ReadUint16(&suite.KdfId) || !s.ReadUint16(&suite.AeadId) ||
		!s.ReadUint8(&configID) ||
		!s.ReadUint16LengthPrefixed(&enc) || !s.ReadUint16LengthPrefixed(&payload) ||
		!s.Empty() {
		t.Fatal("malformed GREASE ECH extension")
	}
	return suite, len(enc), len(payload)
}

// greaseECHInHello finds the encrypted_client_hello extension in a marshaled
// ClientHello handshake message and returns what greaseECHBody does.
func greaseECHInHello(t *testing.T, hello []byte) (suite tls.HPKESymmetricCipherSuite, encLen, payloadLen int) {
	t.Helper()
	s := cryptobyte.String(hello)
	var body, sessionID, ciphers, compression, extensions cryptobyte.String
	var handshakeType uint8
	if !s.ReadUint8(&handshakeType) || handshakeType != 1 ||
		!s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.Skip(2+32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&ciphers) ||
		!body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		t.Fatal("malformed ClientHello")
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			t.Fatal("malformed ClientHello extensions")
		}
		if extType == 0xfe0d {
			return greaseECHBody(t, extData)
		}
	}
	t.Fatal("ClientHello carries no encrypted_client_hello extension")
	return
}

// rawGREASEECH serializes a GREASE ECH extension, header included, with the
// given suite, encapsulated key length and on-the-wire payload length.
func rawGREASEECH(kdf, aead uint16, encLen, payloadLen int) []byte {
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // outer
		b.AddUint16(kdf)
		b.AddUint16(aead)
		b.AddUint8(0x2a) // config id
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, encLen)) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, payloadLen)) })
	})
	return b.BytesOrPanic()
}

// checkPayloadLens fails unless the observed payload lengths are exactly the
// wanted ones, each seen at least once.
func checkPayloadLens(t *testing.T, seen map[int]int, want []int) {
	t.Helper()
	for _, n := range want {
		if seen[n] == 0 {
			t.Errorf("payload never %d bytes: %v", n, seen)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("payload lengths %v, want only %v", seen, want)
	}
}

// TestGREASEECHDefaultPayloadLengthVariesLikeBoringSSL checks that a GREASE
// ECH extension given no payload length draws one per connection from the
// four BoringSSL uses, rather than sending a single fixed length.
func TestGREASEECHDefaultPayloadLengthVariesLikeBoringSSL(t *testing.T) {
	seen := map[int]int{}
	for range 400 {
		g := &tls.GREASEEncryptedClientHelloExtension{}
		buf := make([]byte, 1024)
		n, err := g.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		_, _, payloadLen := greaseECHBody(t, buf[4:n])
		seen[payloadLen]++
	}
	checkPayloadLens(t, seen, boringSSLGREASEECHWireLens)
}

// TestGREASEECHWrite checks that a captured GREASE ECH extension is parsed
// into its HPKE suite, its encapsulated key length and its payload length,
// and that the extension then marshals with the same shape.
func TestGREASEECHWrite(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          []byte
		wantSuite    tls.HPKESymmetricCipherSuite
		wantEncLen   int
		wantLens     []uint16 // CandidatePayloadLens, pre-encryption
		wantWireLens []int
	}{
		{
			name:         "aes-128-gcm, 208 bytes",
			raw:          rawECH_HKDFSHA256_AES128GCM,
			wantSuite:    tls.HPKESymmetricCipherSuite{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
			wantEncLen:   32,
			wantLens:     []uint16{192},
			wantWireLens: []int{208},
		},
		{
			name:         "chacha20-poly1305, 239 bytes",
			raw:          rawGREASEECH(dicttls.HKDF_SHA256, dicttls.AEAD_CHACHA20_POLY1305, 32, 239),
			wantSuite:    tls.HPKESymmetricCipherSuite{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
			wantEncLen:   32,
			wantLens:     []uint16{223},
			wantWireLens: []int{239},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gech := &tls.GREASEEncryptedClientHelloExtension{}
			n, err := gech.Write(tc.raw[4:]) // skip the extension type and length
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if n != len(tc.raw[4:]) {
				t.Fatalf("Write consumed %d bytes, want %d", n, len(tc.raw[4:]))
			}

			if !slices.Equal(gech.CandidateCipherSuites, []tls.HPKESymmetricCipherSuite{tc.wantSuite}) {
				t.Fatalf("CandidateCipherSuites %v, want [%v]", gech.CandidateCipherSuites, tc.wantSuite)
			}
			if len(gech.EncapsulatedKey) != tc.wantEncLen {
				t.Fatalf("EncapsulatedKey is %d bytes, want %d", len(gech.EncapsulatedKey), tc.wantEncLen)
			}
			if !slices.Equal(gech.CandidatePayloadLens, tc.wantLens) {
				t.Fatalf("CandidatePayloadLens %v, want %v", gech.CandidatePayloadLens, tc.wantLens)
			}

			buf := make([]byte, 1024)
			n, err = gech.Read(buf)
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("Read: %v", err)
			}
			suite, encLen, payloadLen := greaseECHBody(t, buf[4:n])
			if suite != tc.wantSuite || encLen != tc.wantEncLen {
				t.Fatalf("Read produced suite %v and %d-byte key, want %v and %d", suite, encLen, tc.wantSuite, tc.wantEncLen)
			}
			if !slices.Contains(tc.wantWireLens, payloadLen) {
				t.Fatalf("Read produced a %d-byte payload, want one of %v", payloadLen, tc.wantWireLens)
			}
		})
	}
}

// greaseECHHello builds a ClientHello from a spec carrying the given GREASE
// ECH extension and returns the marshaled handshake message.
func greaseECHHello(t *testing.T, spec *tls.ClientHelloSpec) []byte {
	t.Helper()
	uconn := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "example.com"}, tls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		t.Fatal(err)
	}
	return uconn.HandshakeState.Hello.Raw
}

// greaseECHSpec is a minimal spec carrying the given GREASE ECH extension,
// with RFC 8701 GREASE values in the cipher suites and extensions as BoringSSL
// sends them when grease is set, and without any as NSS sends it.
func greaseECHSpec(ech *tls.GREASEEncryptedClientHelloExtension, grease bool) *tls.ClientHelloSpec {
	spec := &tls.ClientHelloSpec{
		TLSVersMin:         tls.VersionTLS12,
		TLSVersMax:         tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13}},
			ech,
		},
	}
	if grease {
		spec.CipherSuites = append([]uint16{tls.GREASE_PLACEHOLDER}, spec.CipherSuites...)
		spec.Extensions = append([]tls.TLSExtension{&tls.UtlsGREASEExtension{}}, spec.Extensions...)
	}
	return spec
}

// TestFingerprintedGREASEECHReplaysItsStack checks that a ClientHello spec
// fingerprinted from a capture sends the GREASE ECH payload length the way
// the captured stack does on successive connections. BoringSSL draws one of
// four lengths every time and sends RFC 8701 GREASE values; NSS derives a
// single length from the ClientHello and sends no GREASE. So a capture with
// GREASE values is replayed with BoringSSL's draw, and one without keeps its
// length, even when that length is one of BoringSSL's four, as Firefox's
// 240 bytes is.
func TestFingerprintedGREASEECHReplaysItsStack(t *testing.T) {
	for _, tc := range []struct {
		name         string
		grease       bool
		capturedLen  uint16 // pre-encryption, as CandidatePayloadLens holds it
		wantWireLens []int
	}{
		{name: "boringssl capture", grease: true, capturedLen: 192, wantWireLens: boringSSLGREASEECHWireLens},
		{name: "nss capture", grease: false, capturedLen: 224, wantWireLens: []int{240}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello := greaseECHHello(t, greaseECHSpec(&tls.GREASEEncryptedClientHelloExtension{
				CandidatePayloadLens: []uint16{tc.capturedLen},
			}, tc.grease))
			record := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
			spec, err := (&tls.Fingerprinter{}).FingerprintClientHello(record)
			if err != nil {
				t.Fatal(err)
			}

			seen := map[int]int{}
			for range 400 {
				_, _, payloadLen := greaseECHInHello(t, greaseECHHello(t, spec))
				seen[payloadLen]++
			}
			checkPayloadLens(t, seen, tc.wantWireLens)
		})
	}
}

var rawECH_HKDFSHA256_AES128GCM = []byte{
	0xfe, 0x0d, 0x00, 0xfa, 0x00, 0x00, 0x01, 0x00,
	0x01, 0x77, 0x00, 0x20, 0x3d, 0x3e, 0xe0, 0xa6,
	0x1f, 0x46, 0x4f, 0x89, 0x5f, 0x39, 0x4a, 0xfd,
	0x6e, 0xbc, 0x7f, 0x4e, 0xe2, 0x5a, 0xdc, 0x4e,
	0xda, 0x9a, 0x9f, 0x5f, 0x2b, 0xf5, 0x21, 0x0e,
	0xc6, 0x33, 0x64, 0x32, 0x00, 0xd0, 0xae, 0xff,
	0x25, 0xd6, 0x4a, 0x23, 0x3a, 0x13, 0x5b, 0xdc,
	0xe4, 0xaf, 0x6c, 0xb8, 0xaf, 0x66, 0x57, 0xbd,
	0x44, 0x2d, 0xca, 0xb6, 0xbb, 0xaf, 0xda, 0x8a,
	0x6b, 0x12, 0xb2, 0x42, 0xf1, 0x3d, 0xf6, 0x26,
	0xd4, 0x82, 0x30, 0x40, 0xd4, 0x53, 0x06, 0x7c,
	0xf1, 0x10, 0xf3, 0x80, 0x16, 0x95, 0xa7, 0xfb,
	0x08, 0x76, 0x82, 0x85, 0x86, 0xb4, 0x3a, 0x7b,
	0xea, 0xfb, 0xaa, 0xc3, 0xe0, 0x51, 0xcf, 0x42,
	0xf6, 0xa0, 0x15, 0x0e, 0x26, 0x4d, 0x37, 0x35,
	0x95, 0x4d, 0xce, 0xf6, 0xd6, 0x58, 0x78, 0x67,
	0x42, 0xd3, 0xc6, 0xac, 0xb5, 0xe9, 0x3e, 0xb6,
	0x02, 0x87, 0x66, 0xb3, 0xb2, 0x56, 0x99, 0xb2,
	0xdb, 0x8c, 0x3b, 0x04, 0xf1, 0x7c, 0x85, 0x5b,
	0xc3, 0x93, 0x8e, 0xdb, 0x5d, 0x87, 0x66, 0xfb,
	0x66, 0x54, 0xf3, 0xec, 0x25, 0xe5, 0x70, 0x3c,
	0xd5, 0x0e, 0x8e, 0xd5, 0xd2, 0xbb, 0x24, 0x2b,
	0xb5, 0x01, 0xa0, 0x5e, 0xba, 0x45, 0xaf, 0x68,
	0x96, 0x8a, 0x83, 0x90, 0x20, 0x5b, 0x8c, 0x7d,
	0x24, 0x00, 0x2f, 0x08, 0x7f, 0x29, 0x8c, 0x32,
	0x5e, 0x57, 0xb5, 0x64, 0xaa, 0x0b, 0xf4, 0x42,
	0x54, 0xdc, 0xe5, 0xd4, 0x08, 0xf4, 0x4d, 0x27,
	0x5d, 0x90, 0x52, 0x32, 0x22, 0xc8, 0xb6, 0xd8,
	0x80, 0xa6, 0x30, 0xa0, 0x20, 0x98, 0x2c, 0x0b,
	0x3e, 0x55, 0x4a, 0x09, 0xa9, 0x09, 0xa4, 0x99,
	0x89, 0x02, 0x6e, 0xab, 0xe3, 0xa1, 0xe9, 0xb8,
	0x58, 0x20, 0xcc, 0xc8, 0xb0, 0x73,
}
