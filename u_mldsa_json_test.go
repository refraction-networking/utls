package tls

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/refraction-networking/utls/dicttls"
)

func TestMLDSASignatureSchemeJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scheme SignatureScheme
	}{
		{"mldsa44", MLDSA44},
		{"mldsa65", MLDSA65},
		{"mldsa87", MLDSA87},
	} {
		if got := dicttls.DictSignatureSchemeNameIndexed[tc.name]; got != uint16(tc.scheme) {
			t.Fatalf("signature scheme %s = %#04x, want %#04x", tc.name, got, tc.scheme)
		}
		if got := dicttls.DictSignatureSchemeValueIndexed[uint16(tc.scheme)]; got != tc.name {
			t.Fatalf("signature scheme %#04x = %s, want %s", tc.scheme, got, tc.name)
		}
	}
	for _, name := range []string{"signature_algorithms", "signature_algorithms_cert"} {
		t.Run(name, func(t *testing.T) {
			data := fmt.Sprintf(`[{"name":%q,"supported_signature_algorithms":["GREASE","mldsa44","mldsa65","mldsa87"]}]`, name)
			var extensions TLSExtensionsJSONUnmarshaler
			if err := json.Unmarshal([]byte(data), &extensions); err != nil {
				t.Fatal(err)
			}
			exts := extensions.Extensions()
			if len(exts) != 1 {
				t.Fatalf("parsed %d extensions, want 1", len(exts))
			}
			var got []SignatureScheme
			switch ext := exts[0].(type) {
			case *SignatureAlgorithmsExtension:
				got = ext.SupportedSignatureAlgorithms
			case *SignatureAlgorithmsCertExtension:
				got = ext.SupportedSignatureAlgorithms
			default:
				t.Fatalf("unexpected extension type %T", ext)
			}
			want := []SignatureScheme{GREASE_PLACEHOLDER, MLDSA44, MLDSA65, MLDSA87}
			if !slices.Equal(got, want) {
				t.Fatalf("signature algorithms = %x, want %x", got, want)
			}
		})
	}
}
