// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type helloFields struct {
	vers    uint16
	sidLen  int
	ciphers []uint16
	extIDs  []uint16
	ext     map[uint16][]byte
}

func parseHelloFields(t *testing.T, raw []byte) *helloFields {
	t.Helper()
	body, err := clientHelloBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := &helloFields{ext: map[uint16][]byte{}}
	s := cryptobyte.String(body[4:])
	var rnd, sid, cs, comp, exts cryptobyte.String
	if !s.ReadUint16(&h.vers) || !s.ReadBytes((*[]byte)(&rnd), 32) || !s.ReadUint8LengthPrefixed(&sid) ||
		!s.ReadUint16LengthPrefixed(&cs) || !s.ReadUint8LengthPrefixed(&comp) || !s.ReadUint16LengthPrefixed(&exts) {
		t.Fatal("malformed hello")
	}
	h.sidLen = len(sid)
	for !cs.Empty() {
		var c uint16
		cs.ReadUint16(&c)
		h.ciphers = append(h.ciphers, ungrease(c))
	}
	for !exts.Empty() {
		var id uint16
		var d cryptobyte.String
		exts.ReadUint16(&id)
		exts.ReadUint16LengthPrefixed(&d)
		id = ungrease(id)
		h.extIDs = append(h.extIDs, id)
		if id != GREASE_PLACEHOLDER {
			h.ext[id] = []byte(d)
		}
	}
	return h
}

// u16s returns a uint16 list (after a length prefix of n bytes), ungreased.
func u16s(d []byte, prefix int) []uint16 {
	var out []uint16
	for i := prefix; i+1 < len(d); i += 2 {
		out = append(out, ungrease(uint16(d[i])<<8|uint16(d[i+1])))
	}
	return out
}

func keyShareShape(d []byte) [][2]int {
	var out [][2]int
	s := cryptobyte.String(d)
	var list cryptobyte.String
	s.ReadUint16LengthPrefixed(&list)
	for !list.Empty() {
		var g uint16
		var k cryptobyte.String
		list.ReadUint16(&g)
		list.ReadUint16LengthPrefixed(&k)
		out = append(out, [2]int{int(ungrease(g)), len(k)})
	}
	return out
}

// renderHello returns the first ClientHello record id sends for serverName.
func renderHello(t *testing.T, id ClientHelloID, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	rec := &recConn{Conn: c1}
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1<<16)
		n, _ := c2.Read(b)
		got <- b[:n]
	}()
	uc := UClient(rec, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}, id)
	go uc.Handshake()
	return <-got
}

func TestChrome155MatchesBrowserCapture(t *testing.T) {
	hexData, err := os.ReadFile("testdata/chrome155_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := hex.DecodeString(strings.TrimSpace(string(hexData)))
	if err != nil {
		t.Fatal(err)
	}
	want := parseHelloFields(t, capture)
	ja4Want, _ := JA4(capture)
	for i := 0; i < 5; i++ {
		raw := renderHello(t, HelloChrome_155, "www.example.com")
		got := parseHelloFields(t, raw)
		if got.vers != want.vers || got.sidLen != want.sidLen {
			t.Fatalf("legacy version/session id: %x/%d vs %x/%d", got.vers, got.sidLen, want.vers, want.sidLen)
		}
		if !slices.Equal(got.ciphers, want.ciphers) {
			t.Fatalf("cipher suites differ:\n got %x\nwant %x", got.ciphers, want.ciphers)
		}
		gs, ws := slices.Clone(got.extIDs), slices.Clone(want.extIDs)
		sort.Slice(gs, func(i, j int) bool { return gs[i] < gs[j] })
		sort.Slice(ws, func(i, j int) bool { return ws[i] < ws[j] })
		if !slices.Equal(gs, ws) {
			t.Fatalf("extension sets differ:\n got %v\nwant %v", gs, ws)
		}
		if got.extIDs[0] != GREASE_PLACEHOLDER || got.extIDs[len(got.extIDs)-1] != GREASE_PLACEHOLDER {
			t.Fatal("GREASE extensions not at the ends")
		}
		for id, wb := range want.ext {
			gb := got.ext[id]
			switch id {
			case 0x0033: // key_share: same groups and key lengths, fresh keys
				if !slices.Equal(keyShareShape(gb), keyShareShape(wb)) {
					t.Fatalf("key_share shape %v vs %v", keyShareShape(gb), keyShareShape(wb))
				}
			case 0x000a, 0x000d:
				if !slices.Equal(u16s(gb, 2), u16s(wb, 2)) {
					t.Fatalf("extension %d: %x vs %x", id, u16s(gb, 2), u16s(wb, 2))
				}
			case 0x002b:
				if !slices.Equal(u16s(gb, 1), u16s(wb, 1)) {
					t.Fatalf("supported_versions: %x vs %x", gb, wb)
				}
			case 0xfe0d: // GREASE ECH: same suite, payload length from BoringSSL's family
				if !bytes.Equal(gb[:5], wb[:5]) || gb[6] != wb[6] || gb[7] != 32 {
					t.Fatalf("GREASE ECH header %x vs %x", gb[:8], wb[:8])
				}
				if l := len(gb) - 42; l != 144 && l != 176 && l != 208 && l != 240 {
					t.Fatalf("GREASE ECH payload length %d", l)
				}
			default:
				if !bytes.Equal(gb, wb) {
					t.Fatalf("extension %#04x body differs:\n got %x\nwant %x", id, gb, wb)
				}
			}
		}
		if ja4, _ := JA4(raw); ja4 != ja4Want {
			t.Fatalf("JA4 %s, capture %s", ja4, ja4Want)
		}
	}
}

func loadCapture(t testing.TB, name string) []byte {
	t.Helper()
	h, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestFirefox158MatchesBrowserCapture compares HelloFirefox_158 with real
// Firefox 158.0 captures (testdata/firefox158_clienthello.md). Firefox does not
// permute extensions, so order is compared exactly.
func TestFirefox158MatchesBrowserCapture(t *testing.T) {
	for _, tc := range []struct{ file, sni string }{
		{"firefox158_clienthello.hex", "utls-capture.test"},
		{"firefox158_ip_clienthello.hex", "127.0.0.1"},
	} {
		capture := loadCapture(t, tc.file)
		want := parseHelloFields(t, capture)
		for i := 0; i < 3; i++ {
			raw := renderHello(t, HelloFirefox_158, tc.sni)
			got := parseHelloFields(t, raw)
			if len(raw) != len(capture) {
				t.Errorf("%s: record length %d, capture %d", tc.file, len(raw), len(capture))
			}
			if got.vers != want.vers || got.sidLen != want.sidLen || !slices.Equal(got.ciphers, want.ciphers) {
				t.Fatalf("%s: version/session id/ciphers differ", tc.file)
			}
			if !slices.Equal(got.extIDs, want.extIDs) {
				t.Fatalf("%s: extension order\n got %v\nwant %v", tc.file, got.extIDs, want.extIDs)
			}
			for id, wb := range want.ext {
				gb := got.ext[id]
				switch id {
				case 0x0033:
					if !slices.Equal(keyShareShape(gb), keyShareShape(wb)) {
						t.Fatalf("key_share shape %v vs %v", keyShareShape(gb), keyShareShape(wb))
					}
					// X25519 share reused from the hybrid share, as in the capture.
					if !bytes.Equal(gb[2+4+1216-32:2+4+1216], gb[2+4+1216+4:2+4+1216+4+32]) {
						t.Fatal("X25519 share not reused from X25519MLKEM768")
					}
				case 0xfe0d: // type+suite, enc length and payload length exact
					if len(gb) != len(wb) || !bytes.Equal(gb[:5], wb[:5]) || !bytes.Equal(gb[6:8], wb[6:8]) ||
						!bytes.Equal(gb[40:42], wb[40:42]) {
						t.Fatalf("GREASE ECH shape\n got %x\nwant %x", gb[:8], wb[:8])
					}
				default:
					if !bytes.Equal(gb, wb) {
						t.Fatalf("%s: extension %#04x body\n got %x\nwant %x", tc.file, id, gb, wb)
					}
				}
			}
			ja4g, _ := JA4(raw)
			ja4w, _ := JA4(capture)
			ja3g, _, _ := JA3(raw)
			ja3w, _, _ := JA3(capture)
			if ja4g != ja4w || ja3g != ja3w {
				t.Fatalf("%s: JA4 %s/%s JA3 %s/%s", tc.file, ja4g, ja4w, ja3g, ja3w)
			}
		}
	}
	handshakeStd(t, HelloFirefox_158, clientConfig(t), serverConfig(t), nil).ok(t)
}

func TestParseCaptureRoundTrip(t *testing.T) {
	hexData, _ := os.ReadFile("testdata/chrome155_clienthello.hex")
	capture, _ := hex.DecodeString(strings.TrimSpace(string(hexData)))
	spec, err := ParseClientHello(capture)
	if err != nil {
		t.Fatal(err)
	}
	id := CustomFingerprint("Parsed", "chrome155", func() (*ClientHelloSpec, error) { return spec.Clone(), nil })
	raw := renderHello(t, id, "www.example.com")
	got, want := parseHelloFields(t, raw), parseHelloFields(t, capture)
	if !slices.Equal(got.extIDs, want.extIDs) || !slices.Equal(got.ciphers, want.ciphers) {
		t.Fatalf("parsed spec does not reproduce order:\n got %v\nwant %v", got.extIDs, want.extIDs)
	}
	j1, _ := JA4(raw)
	j2, _ := JA4(capture)
	t1, _, _ := JA3(raw)
	t2, _, _ := JA3(capture)
	if j1 != j2 || t1 != t2 {
		t.Fatalf("JA4 %s/%s JA3 %s/%s", j1, j2, t1, t2)
	}
	// It is a working fingerprint, not just bytes.
	handshakeStd(t, id, clientConfig(t), serverConfig(t), nil).ok(t)
}

func TestEveryPresetRoundTripsThroughParser(t *testing.T) {
	for _, id := range allPresets() {
		if id == HelloGolang {
			continue
		}
		raw := renderHello(t, id, "utls.test")
		spec, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("%s: %v", id.Str(), err)
		}
		pid := CustomFingerprint("Parsed", id.Str(), func() (*ClientHelloSpec, error) { return spec.Clone(), nil })
		raw2 := renderHello(t, pid, "utls.test")
		a, _, _ := JA3(raw)
		b, _, _ := JA3(raw2)
		if a != b {
			t.Fatalf("%s: JA3 changed through the parser:\n%s\n%s", id.Str(), a, b)
		}
		handshakeStd(t, pid, clientConfig(t), serverConfig(t), nil).ok(t)
	}
}

func TestSpecFromJA3(t *testing.T) {
	raw := renderHello(t, HelloAndroid_11_OkHttp, "utls.test")
	ja3, _, err := JA3(raw)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := SpecFromJA3(ja3, JA3SpecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	id := CustomFingerprint("FromJA3", "1", func() (*ClientHelloSpec, error) { return spec.Clone(), nil })
	got, _, _ := JA3(renderHello(t, id, "utls.test"))
	if got != ja3 {
		t.Fatalf("JA3 not reproduced:\n%s\n%s", got, ja3)
	}
	handshakeStd(t, id, clientConfig(t), serverConfig(t), nil).ok(t)
	// A JA3 with an extension whose contents cannot be derived is an error.
	chrome, _, _ := JA3(renderHello(t, HelloChrome_155, "utls.test"))
	if _, err := SpecFromJA3(chrome, JA3SpecOptions{}); err == nil {
		t.Fatal("JA3 with ALPS/trust anchors accepted with invented bodies")
	}
	for _, bad := range []string{"", "771,1-2", "x,1,0,29,0", "771,70000,0,29,0"} {
		if _, err := SpecFromJA3(bad, JA3SpecOptions{}); err == nil {
			t.Errorf("SpecFromJA3(%q) accepted", bad)
		}
	}
}

func FuzzParseClientHello(f *testing.F) {
	hexData, _ := os.ReadFile("testdata/chrome155_clienthello.hex")
	capture, _ := hex.DecodeString(strings.TrimSpace(string(hexData)))
	f.Add(capture)
	f.Add(capture[5:])
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		spec, err := ParseClientHello(b)
		JA3(b)
		JA4(b)
		if err != nil {
			return
		}
		// Anything the parser accepts must be a valid spec that renders.
		if err := spec.Validate(); err != nil {
			t.Fatalf("parser returned an invalid spec: %v", err)
		}
		spec.Clone()
	})
}

var _ = errors.New
