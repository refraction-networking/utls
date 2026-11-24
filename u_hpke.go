package tls

import (
	"crypto/ecdh"
	"crypto/hpke"
)

type HPKERawPublicKey = []byte
type HPKE_KEM_ID = uint16  // RFC 9180
type HPKE_KDF_ID = uint16  // RFC 9180
type HPKE_AEAD_ID = uint16 // RFC 9180

type HPKESymmetricCipherSuite struct {
	KdfId  HPKE_KDF_ID
	AeadId HPKE_AEAD_ID
}

var defaultHpkeKdf = hpke.HKDFSHA256().ID()
var defaultHpkeKem = hpke.DHKEM(ecdh.X25519()).ID()
var defaultHpkeAead = hpke.AES128GCM().ID()

// cipherLen returns the length of a ciphertext corresponding to a message of
// length mLen.
func cipherLen(a uint16, mLen int) int {
	switch a {
	case hpke.AES128GCM().ID(), hpke.AES256GCM().ID(), hpke.ChaCha20Poly1305().ID():
		return mLen + 16
	default:
		panic("hpke: invalid AEAD identifier")
	}
}
