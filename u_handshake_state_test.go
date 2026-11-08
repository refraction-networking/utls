package tls

import (
	"testing"
)

// TestUTLSHandshakeDropsKeyShareKeys checks that the key share private keys,
// which a connection needs only until the shared secret is derived, are gone
// from the public handshake state once the handshake completes. An ML-KEM
// decapsulation key is about 8 KiB, so keeping it would cost that much for
// every idle connection. The rest of the handshake state stays readable.
func TestUTLSHandshakeDropsKeyShareKeys(t *testing.T) {
	for _, id := range []ClientHelloID{HelloChrome_Auto, HelloGolang} {
		t.Run(id.Str(), func(t *testing.T) {
			clientConfig := testConfigClient.Clone()
			serverConfig := testConfigServer.Clone()
			c, s := localPipe(t)
			t.Cleanup(func() {
				_ = c.Close()
				_ = s.Close()
			})

			client := UClient(c, clientConfig, id)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			keys := client.HandshakeState.State13.KeyShareKeys
			if keys == nil || (keys.Ecdhe == nil && keys.Mlkem == nil) {
				t.Fatalf("key share keys before the handshake = %+v, want generated keys", keys)
			}

			done := make(chan error, 1)
			go func() { done <- Server(s, serverConfig).Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}

			if keys := client.HandshakeState.State13.KeyShareKeys; keys != nil {
				t.Errorf("key share keys after the handshake = %+v, want none", keys)
			}
			if client.HandshakeState.ServerHello == nil || client.HandshakeState.Hello == nil || client.HandshakeState.MasterSecret == nil {
				t.Error("the rest of the handshake state is no longer readable")
			}
		})
	}
}
