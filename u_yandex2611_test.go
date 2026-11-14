package tls

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestYandex2611CapturedClientHello(t *testing.T) {
	files, err := filepath.Glob("testdata/yandex2611-*.hex")
	if err != nil || len(files) != 19 {
		t.Fatalf("expected 19 independent headed/headless captures, got %d: %v", len(files), err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := hex.DecodeString(strings.Join(strings.Fields(string(data)), ""))
			if err != nil {
				t.Fatal(err)
			}
			want, _, raw := chrome155ParseWire(t, fixture)
			name := chrome155FixtureServerName(t, raw)
			for _, id := range []ClientHelloID{HelloYandex_26_11, HelloChrome_155} {
				client := chrome155Build(t, id, name, nil)
				got, _, generated := chrome155ParseWire(t, client.HandshakeState.Hello.Raw)
				if !reflect.DeepEqual(want, got) {
					t.Errorf("%s differs from %s: got %+v, want %+v", id.Str(), file, got, want)
				}
				if ticket, ok := generated[35]; !ok || len(ticket) != 0 {
					t.Fatal("fresh handshake requires empty session ticket")
				}
				if _, ok := generated[41]; ok {
					t.Fatal("fresh handshake must not offer PSK")
				}
			}
		})
	}
}

func TestYandex2611DoesNotMutateChrome155(t *testing.T) {
	before := chrome155Build(t, HelloChrome_155, "www.example.com", nil)
	want, _, _ := chrome155ParseWire(t, before.HandshakeState.Hello.Raw)
	yandex := chrome155Build(t, HelloYandex_26_11, "www.example.com", nil)
	anchors := chrome155TrustAnchors(t, yandex.Extensions)
	anchors.TrustAnchorIDs[0][0] ^= 0xff
	after := chrome155Build(t, HelloChrome_155, "www.example.com", nil)
	got, _, _ := chrome155ParseWire(t, after.HandshakeState.Hello.Raw)
	if !reflect.DeepEqual(want, got) {
		t.Fatal("Yandex preset mutation changed Chrome155")
	}
}
