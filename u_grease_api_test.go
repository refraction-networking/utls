package tls_test

import (
	"testing"

	tls "github.com/refraction-networking/utls"
)

// The public helper's five-element array remains source-compatible when the
// internal GREASE seed gains slots for additional ClientHello fields.
var _ func([5]uint16, int) uint16 = tls.GetBoringGREASEValue

func TestBoringGREASEPublicAPI(t *testing.T) {
	seed := [5]uint16{0x0000, 0x0012, 0x0080, 0x00f0, 0xffe1}
	want := [5]uint16{0x0a0a, 0x1a1a, 0x8a8a, 0xfafa, 0xeaea}
	for i, expected := range want {
		if got := tls.GetBoringGREASEValue(seed, i); got != expected {
			t.Fatalf("GREASE index %d = %#04x; want %#04x", i, got, expected)
		}
	}
}
