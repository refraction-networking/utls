package tls

import (
	"bytes"
	"crypto/ecdh"
	"net"
	"testing"
)

func greaseECHKeyFromSpec(t *testing.T, spec *ClientHelloSpec) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := UClient(c1, &Config{ServerName: "example.com"}, HelloCustom)
	if err := u.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	for _, e := range u.Extensions {
		if g, ok := e.(*GREASEEncryptedClientHelloExtension); ok {
			return append([]byte(nil), g.EncapsulatedKey...)
		}
	}
	t.Fatal("no GREASE ECH extension in the ClientHello")
	return nil
}

func assertFreshGREASEECHKeys(t *testing.T, spec *ClientHelloSpec) {
	t.Helper()
	first := greaseECHKeyFromSpec(t, spec)
	second := greaseECHKeyFromSpec(t, spec)
	if bytes.Equal(first, second) {
		t.Fatalf("two connections from one spec sent the same GREASE ECH key %x", first)
	}
	if _, err := ecdh.X25519().NewPublicKey(first); err != nil || len(first) != 32 {
		t.Fatalf("GREASE ECH key is not an X25519 public key: %x", first)
	}
}

// A spec fingerprinted from a captured ClientHello must not replay the
// captured encapsulated key on every connection.
func TestGREASEECHFreshKeyFingerprintedSpec(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := UClient(c1, &Config{ServerName: "example.com"}, HelloChrome_120)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	raw := u.HandshakeState.Hello.Raw
	record := append([]byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	spec, err := (&Fingerprinter{}).FingerprintClientHello(record)
	if err != nil {
		t.Fatal(err)
	}
	assertFreshGREASEECHKeys(t, spec)
}

// A shared spec that was marshalled before use (Len and Read run init) must
// not freeze the GREASE ECH values for every connection built from it.
func TestGREASEECHFreshKeySharedSpec(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_120)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		e.Len()
	}
	assertFreshGREASEECHKeys(t, &spec)
}

// A key set by the caller is kept, also through a clone.
func TestGREASEECHCallerKeyKept(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	spec, err := UTLSIdToSpec(HelloChrome_120)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		if g, ok := e.(*GREASEEncryptedClientHelloExtension); ok {
			g.EncapsulatedKey = key
		}
	}
	if got := greaseECHKeyFromSpec(t, &spec); !bytes.Equal(got, key) {
		t.Fatalf("caller key replaced: %x", got)
	}
}

func TestGREASEEncapsulatedKeyLengths(t *testing.T) {
	curves := map[int]ecdh.Curve{32: ecdh.X25519(), 65: ecdh.P256(), 97: ecdh.P384(), 133: ecdh.P521()}
	for n, curve := range curves {
		key, err := greaseEncapsulatedKey(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != n {
			t.Fatalf("length %d: got %d bytes", n, len(key))
		}
		if _, err := curve.NewPublicKey(key); err != nil {
			t.Fatalf("length %d: not a valid public key: %v", n, err)
		}
	}
	if key, err := greaseEncapsulatedKey(48); err != nil || len(key) != 48 {
		t.Fatalf("unknown length: %d bytes, %v", len(key), err)
	}
}
