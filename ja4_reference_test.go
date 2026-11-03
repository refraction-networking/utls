// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

// Reference vectors from the FoxIO JA4 specification (technical_details/JA4.md,
// https://github.com/FoxIO-LLC/ja4, fetched 2026-11-03, sha256 14a9623a...):
// the worked example ("Cipher hash", "Extension hash", "Example", "Raw
// Output"), the "ALPN Extension Value" byte examples and the "TLS and DTLS
// Version" rule. These are external expectations, not round trips.

import (
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type ja4Hello struct {
	legacy   uint16
	ciphers  []uint16
	exts     []uint16 // in wire order; bodies come from bodies or are empty
	bodies   map[uint16][]byte
	sigalgs  []uint16 // body of 0x000d (nil: an empty list)
	versions []uint16 // body of 0x002b (only if 0x002b is in exts)
	alpn     [][]byte // body of 0x0010 (only if 0x0010 is in exts)
}

func (h ja4Hello) bytes(t *testing.T) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(1)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(h.legacy)
		b.AddBytes(make([]byte, 32))
		b.AddUint8(0)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, c := range h.ciphers {
				b.AddUint16(c)
			}
		})
		b.AddUint8(1)
		b.AddUint8(0)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range h.exts {
				b.AddUint16(e)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					switch e {
					case 0x0000:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint8(0)
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("example.com")) })
						})
					case 0x000a:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x001d) })
					case 0x000b:
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
					case 0x000d:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, s := range h.sigalgs {
								b.AddUint16(s)
							}
						})
					case 0x0010:
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, p := range h.alpn {
								b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(p) })
							}
						})
					case 0x002b:
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, v := range h.versions {
								b.AddUint16(v)
							}
						})
					default:
						b.AddBytes(h.bodies[e])
					}
				})
			}
		})
	})
	return b.BytesOrPanic()
}

// The specification's worked example, in original wire order (JA4_ro).
func specExample() ja4Hello {
	return ja4Hello{
		legacy:   0x0303,
		ciphers:  []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		exts:     []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		sigalgs:  []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		versions: []uint16{0x0304, 0x0303},
		alpn:     [][]byte{[]byte("h2"), []byte("http/1.1")},
	}
}

func ja4Of(t *testing.T, h ja4Hello) string {
	t.Helper()
	got, err := JA4(h.bytes(t))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestJA4SpecExample(t *testing.T) {
	h := specExample()
	if got := ja4Of(t, h); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("JA4 %s, spec t13d1516h2_8daaf6152771_e5627efa2ab1", got)
	}
	// GREASE anywhere is ignored (cipher, extension, version, sigalg).
	g := specExample()
	g.ciphers = append([]uint16{0x0a0a}, g.ciphers...)
	g.exts = append([]uint16{0x1a1a}, append(g.exts, 0x2a2a)...)
	g.versions = append([]uint16{0x3a3a}, g.versions...)
	g.sigalgs = append([]uint16{0x4a4a}, g.sigalgs...)
	if got := ja4Of(t, g); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("with GREASE: %s", got)
	}
	// "If there are no signature algorithms ... the string ends without an
	// underscore": spec hash 6d807ffa2a79.
	n := specExample()
	n.sigalgs = nil
	if got := ja4Of(t, n); !strings.HasSuffix(got, "_6d807ffa2a79") {
		t.Fatalf("no signature algorithms: %s", got)
	}
}

func TestJA4ALPNSpecExamples(t *testing.T) {
	for _, tc := range []struct {
		alpn [][]byte
		want string
	}{
		{[][]byte{{0xAB}}, "ab"},
		{[][]byte{{0x20}}, "20"},
		{[][]byte{{0xAB, 0xCD}}, "ad"},
		{[][]byte{{0x20, 0x61}}, "21"},
		{[][]byte{{0x30, 0xAB}}, "3b"},
		{[][]byte{{0x61, 0x20}}, "60"},
		{[][]byte{{0x30, 0x31, 0xAB, 0xCD}}, "3d"},
		{[][]byte{{0x30, 0xAB, 0xCD, 0x31}}, "01"},
		{[][]byte{[]byte("h2")}, "h2"},
		{[][]byte{[]byte("http/1.1"), []byte("h2")}, "h1"}, // first value only
		{[][]byte{[]byte("x")}, "xx"},                      // single character is first and last
		{[][]byte{{}, []byte("h2")}, "00"},                 // empty first value
		{[][]byte{}, "00"},                                 // no values
	} {
		h := specExample()
		h.alpn = tc.alpn
		got := ja4Of(t, h)
		if got[8:10] != tc.want {
			t.Errorf("ALPN %x: %s (field %q), want %q", tc.alpn, got, got[8:10], tc.want)
		}
	}
	// No ALPN extension at all.
	h := specExample()
	h.exts = []uint16{0x001b, 0x0000, 0x0033, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	if got := ja4Of(t, h); got[8:10] != "00" {
		t.Errorf("no ALPN extension: %s", got)
	}
}

func TestJA4VersionSpec(t *testing.T) {
	for _, tc := range []struct {
		name     string
		legacy   uint16
		versions []uint16 // nil: no supported_versions extension
		want     string
	}{
		{"highest in supported_versions", 0x0303, []uint16{0x0303, 0x0304}, "13"},
		{"below legacy_version", 0x0303, []uint16{0x0302}, "11"},
		{"GREASE ignored", 0x0303, []uint16{0x7a7a, 0x0302, 0x0a0a}, "11"},
		{"only GREASE", 0x0303, []uint16{0x0a0a}, "00"},
		{"empty list", 0x0303, []uint16{}, "00"},
		{"unknown version", 0x0303, []uint16{0x7f1c}, "00"},
		{"absent: legacy 1.2", 0x0303, nil, "12"},
		{"absent: legacy 1.0", 0x0301, nil, "10"},
		{"absent: legacy SSL 3.0", 0x0300, nil, "s3"},
	} {
		h := specExample()
		h.legacy = tc.legacy
		if tc.versions == nil {
			h.exts = []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0xff01, 0x000b, 0x000a, 0x0015}
		} else {
			h.versions = tc.versions
		}
		if got := ja4Of(t, h); got[1:3] != tc.want {
			t.Errorf("%s: %s, want version %q", tc.name, got, tc.want)
		}
	}
}

// Malformed lists in the extensions JA3/JA4 read are errors, not silently
// treated as absent.
func TestJA4MalformedExtensions(t *testing.T) {
	for id, body := range map[uint16][]byte{
		0x002b: {0x03, 0x03, 0x04, 0x03},       // odd-length versions
		0x0010: {0x00, 0x04, 0x05, 'h', '2'},   // name overruns the list
		0x000d: {0x00, 0x03, 0x04, 0x03, 0x05}, // odd-length sigalgs
		0x000a: {0x00, 0x02, 0x00, 0x1d, 0xff}, // trailing byte
		0x000b: {0x02, 0x00},                   // overruns
	} {
		// Inject the raw body under an ID the builder does not special-case,
		// then relabel it.
		h := ja4Hello{legacy: 0x0303, ciphers: []uint16{0x1301}, exts: []uint16{0x7777}, bodies: map[uint16][]byte{0x7777: body}}
		raw := h.bytes(t)
		i := strings.Index(string(raw), "\x77\x77")
		raw[i], raw[i+1] = byte(id>>8), byte(id)
		if _, err := JA4(raw); err == nil {
			t.Errorf("extension %#04x body %x accepted", id, body)
		}
		if _, _, err := JA3(raw); err == nil {
			t.Errorf("JA3: extension %#04x body %x accepted", id, body)
		}
	}
}
