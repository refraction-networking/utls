package tls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"
)

func TestTrustAnchorsExtensionRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  [][]byte
		wire []byte
	}{
		{"empty", nil, []byte{0xca, 0x34, 0, 2, 0, 0}},
		{"single", [][]byte{{0x42}}, []byte{0xca, 0x34, 0, 4, 0, 2, 1, 0x42}},
		{"multiple", [][]byte{{1, 2}, {3}}, []byte{0xca, 0x34, 0, 7, 0, 5, 2, 1, 2, 1, 3}},
		{"maximum ID", [][]byte{bytes.Repeat([]byte{0x81}, 255)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext := &TrustAnchorsExtension{TrustAnchorIDs: tc.ids}
			wire := make([]byte, ext.Len())
			if n, err := ext.Read(wire); n != len(wire) || err != io.EOF {
				t.Fatalf("Read = %d, %v; want %d, EOF", n, err, len(wire))
			}
			if tc.wire != nil && !bytes.Equal(wire, tc.wire) {
				t.Fatalf("wire = %x; want %x", wire, tc.wire)
			}
			parsed, ok := ExtensionFromID(utlsExtensionTrustAnchors).(*TrustAnchorsExtension)
			if !ok {
				t.Fatal("trust_anchors is not registered with the fingerprint parser")
			}
			if n, err := parsed.Write(wire[4:]); n != len(wire)-4 || err != nil {
				t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(wire)-4)
			}
			if len(parsed.TrustAnchorIDs) != len(tc.ids) {
				t.Fatalf("parsed %d IDs; want %d", len(parsed.TrustAnchorIDs), len(tc.ids))
			}
			for i, id := range tc.ids {
				if !bytes.Equal(parsed.TrustAnchorIDs[i], id) {
					t.Fatalf("ID %d = %x; want %x", i, parsed.TrustAnchorIDs[i], id)
				}
			}
			encoded := make([]byte, parsed.Len())
			if _, err := parsed.Read(encoded); err != io.EOF {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, wire) {
				t.Fatalf("roundtrip changed wire: %x != %x", encoded, wire)
			}
		})
	}
}

func TestTrustAnchorsExtensionParseDoesNotAliasInput(t *testing.T) {
	data := []byte{0, 5, 2, 1, 2, 1, 3}
	ext := &TrustAnchorsExtension{}
	if _, err := ext.Write(data); err != nil {
		t.Fatal(err)
	}
	data[3] = 0xff
	if ext.TrustAnchorIDs[0][0] != 1 {
		t.Fatal("parsed ID aliases input")
	}
	ext.TrustAnchorIDs[1][0] = 0xfe
	if data[6] != 3 {
		t.Fatal("input aliases parsed ID")
	}
}

func TestTrustAnchorsExtensionRejectsMalformedData(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{0},             // Truncated list length.
		{0, 1},          // Truncated list.
		{0, 3, 1, 1},    // List length exceeds available data.
		{0, 1, 0},       // Empty ID.
		{0, 2, 2, 1},    // Truncated ID.
		{0, 0, 1},       // Trailing bytes after the list.
		{0, 2, 1, 1, 2}, // Trailing bytes after a nonempty list.
	} {
		t.Run(fmt.Sprintf("%x", data), func(t *testing.T) {
			ext := &TrustAnchorsExtension{TrustAnchorIDs: [][]byte{{0x42}}}
			if n, err := ext.Write(data); n != 0 || err == nil {
				t.Fatalf("Write = %d, %v; want 0, error", n, err)
			}
			if !reflect.DeepEqual(ext.TrustAnchorIDs, [][]byte{{0x42}}) {
				t.Fatal("failed parsing modified existing IDs")
			}
		})
	}
}

func TestTrustAnchorsExtensionEncodingLimits(t *testing.T) {
	ids := make([][]byte, 256)
	for i := range ids[:255] {
		ids[i] = bytes.Repeat([]byte{byte(i)}, 255)
	}
	ids[255] = bytes.Repeat([]byte{0xff}, 252)
	ext := &TrustAnchorsExtension{TrustAnchorIDs: ids}
	wire := make([]byte, ext.Len())
	if _, err := ext.Read(wire); err != io.EOF {
		t.Fatalf("maximum extension_data failed: %v", err)
	}
	if len(wire)-4 != 65535 || wire[2] != 0xff || wire[3] != 0xff {
		t.Fatalf("maximum extension_data length = %d; header = %x", len(wire)-4, wire[:4])
	}
	parsed := &TrustAnchorsExtension{}
	if _, err := parsed.Write(wire[4:]); err != nil {
		t.Fatalf("maximum extension_data parsing failed: %v", err)
	}
	for _, ids := range [][][]byte{
		{nil},
		{{}},
		{make([]byte, 256)},
		append(ids[:255:255], make([]byte, 253)), // One byte over the extension_data limit.
	} {
		ext := &TrustAnchorsExtension{TrustAnchorIDs: ids}
		if n, err := ext.Read(make([]byte, ext.Len())); n != 0 || err == nil {
			t.Fatalf("invalid IDs Read = %d, %v; want 0, error", n, err)
		}
	}
	if n, err := parsed.Write(make([]byte, 65536)); n != 0 || err == nil {
		t.Fatalf("oversize input Write = %d, %v; want 0, error", n, err)
	}
	if n, err := ext.Read(make([]byte, ext.Len()-1)); n != 0 || err != io.ErrShortBuffer {
		t.Fatalf("short buffer Read = %d, %v; want 0, ErrShortBuffer", n, err)
	}
}

func TestTrustAnchorsExtensionJSON(t *testing.T) {
	var extensions TLSExtensionsJSONUnmarshaler
	if err := json.Unmarshal([]byte(`[{"name":"trust_anchors","trust_anchor_ids":["AQI=","/w=="]}]`), &extensions); err != nil {
		t.Fatal(err)
	}
	exts := extensions.Extensions()
	if len(exts) != 1 {
		t.Fatalf("parsed %d extensions; want 1", len(exts))
	}
	ext, ok := exts[0].(*TrustAnchorsExtension)
	if !ok || !reflect.DeepEqual(ext.TrustAnchorIDs, [][]byte{{1, 2}, {0xff}}) {
		t.Fatalf("JSON extension = %#v", exts[0])
	}
	encoded, err := json.Marshal(ext)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip TrustAnchorsExtension
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundtrip.TrustAnchorIDs, ext.TrustAnchorIDs) {
		t.Fatalf("JSON roundtrip changed IDs: got %x, want %x", roundtrip.TrustAnchorIDs, ext.TrustAnchorIDs)
	}
	for _, data := range []string{
		`{"trust_anchor_ids":[""]}`,
		`{"trust_anchor_ids":[null]}`,
		`{"trust_anchor_ids":["invalid base64"]}`,
	} {
		if err := json.Unmarshal([]byte(data), ext); err == nil {
			t.Fatalf("invalid JSON accepted: %s", data)
		}
		if !reflect.DeepEqual(ext.TrustAnchorIDs, [][]byte{{1, 2}, {0xff}}) {
			t.Fatal("failed JSON parsing modified existing IDs")
		}
	}
	if err := json.Unmarshal([]byte(`{"trust_anchor_ids":[]}`), ext); err != nil || len(ext.TrustAnchorIDs) != 0 {
		t.Fatalf("empty JSON list = %#v, %v", ext.TrustAnchorIDs, err)
	}
}
