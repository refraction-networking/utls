package tls

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/cloudflare/circl/hpke"
)

// Unstable API: This is a work in progress and may change in the future. Using
// it in your application may cause your application to break when updating to
// a new version of uTLS.

const (
	OuterClientHello byte = 0x00
	InnerClientHello byte = 0x01
)

type EncryptedClientHelloExtension interface {
	// TLSExtension must be implemented by all EncryptedClientHelloExtension implementations.
	TLSExtension

	// MarshalClientHello is called by (*UConn).MarshalClientHello() when an ECH extension
	// is present to allow the ECH extension to take control of the generation of the
	// entire ClientHello message.
	MarshalClientHello(*UConn) error

	mustEmbedUnimplementedECHExtension()
}

type ECHExtension = EncryptedClientHelloExtension // alias

// type guard: GREASEEncryptedClientHelloExtension must implement EncryptedClientHelloExtension
var (
	_ EncryptedClientHelloExtension = (*GREASEEncryptedClientHelloExtension)(nil)

	_ EncryptedClientHelloExtension = (*UnimplementedECHExtension)(nil)
)

type GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites []HPKESymmetricCipherSuite // if empty, will populate with one random value and proceed
	cipherSuite           HPKESymmetricCipherSuite   // randomly picked from CandidateCipherSuites or generated if empty
	CandidateConfigIds    []uint8                    // if empty, will populate with one random value and proceed
	configId              uint8                      // randomly picked from CandidateConfigIds or generated if empty
	EncapsulatedKey       []byte                     // if empty, will generate random bytes
	PayloadLen            uint16                     // if 0, will generate random value. Chrome 120: 128(+16=144), Firefox 120: 223(+16=239)
	payload               []byte                     // payload should be calculated ONCE and stored here, HRR will reuse this

	initOnce sync.Once

	UnimplementedECHExtension
}

type GREASEECHExtension = GREASEEncryptedClientHelloExtension // alias

// init initializes the GREASEEncryptedClientHelloExtension with random values if they are not set.
//
// Based on cloudflare/go's echGenerateGreaseExt()
func (g *GREASEEncryptedClientHelloExtension) init() error {
	var initErr error
	g.initOnce.Do(func() {
		// Set the config_id field to a random byte.
		//
		// Note: must not reuse this extension unless for HRR. It is required
		// to generate new random bytes for config_id for each new ClientHello,
		// but reuse the same config_id for HRR.
		if len(g.CandidateConfigIds) == 0 {
			var b []byte = make([]byte, 1)
			_, err := rand.Read(b[:])
			if err != nil {
				initErr = fmt.Errorf("error generating random byte for config_id: %w", err)
				return
			}
			g.configId = b[0]
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateConfigIds))))
			if err != nil {
				initErr = fmt.Errorf("error generating random index for config_id: %w", err)
				return
			}
			g.configId = g.CandidateConfigIds[rndIndex.Int64()]
		}

		// Set the cipher_suite field to a supported HpkeSymmetricCipherSuite.
		// The selection SHOULD vary to exercise all supported configurations,
		// but MAY be held constant for successive connections to the same server
		// in the same session.
		if len(g.CandidateCipherSuites) == 0 {
			_, kdf, aead := defaultHPKESuite.Params()
			g.cipherSuite = HPKESymmetricCipherSuite{uint16(kdf), uint16(aead)}
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateCipherSuites))))
			if err != nil {
				initErr = fmt.Errorf("error generating random index for cipher_suite: %w", err)
				return
			}
			g.cipherSuite = HPKESymmetricCipherSuite{
				g.CandidateCipherSuites[rndIndex.Int64()].KdfId,
				g.CandidateCipherSuites[rndIndex.Int64()].AeadId,
			}
			// aead = hpke.AEAD(g.cipherSuite.AeadId)
		}

		if len(g.EncapsulatedKey) == 0 {
			// use default random key from cloudflare/go
			kem := hpke.KEM_X25519_HKDF_SHA256

			pk, err := kem.Scheme().UnmarshalBinaryPublicKey(dummyX25519PublicKey)
			if err != nil {
				initErr = fmt.Errorf("tls: grease ech: failed to parse dummy public key: %w", err)
				return
			}
			sender, err := defaultHPKESuite.NewSender(pk, nil)
			if err != nil {
				initErr = fmt.Errorf("tls: grease ech: failed to create sender: %w", err)
				return
			}

			g.EncapsulatedKey, _, err = sender.Setup(rand.Reader)
			if err != nil {
				initErr = fmt.Errorf("tls: grease ech: failed to setup encapsulated key: %w", err)
				return
			}
		}

		if len(g.payload) == 0 {
			if g.PayloadLen == 0 {
				g.PayloadLen = 100
			}

			initErr = g.randomizePayload(g.PayloadLen)
		}
	})

	return initErr
}

func (g *GREASEEncryptedClientHelloExtension) randomizePayload(encodedHelloInnerLen uint16) error {
	if len(g.payload) != 0 {
		return errors.New("tls: grease ech: regenerating payload is forbidden")
	}

	aead := hpke.AEAD(g.cipherSuite.AeadId)
	g.payload = make([]byte, int(aead.CipherLen(uint(encodedHelloInnerLen))))
	_, err := rand.Read(g.payload)
	if err != nil {
		return fmt.Errorf("tls: generating grease ech payload: %w", err)
	}
	return nil
}

// For ECH extensions, writeToUConn simply points the ech field in UConn to the extension.
func (g *GREASEEncryptedClientHelloExtension) writeToUConn(uconn *UConn) error {
	// uconn.ech = g // don't do this, so we don't intercept the MarshalClientHello() call
	return nil
}

func (g *GREASEEncryptedClientHelloExtension) Len() int {
	g.init()
	return 2 + 2 + 1 /* ClientHello Type */ + 4 /* CipherSuite */ + 1 /* Config ID */ + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
}

func (g *GREASEEncryptedClientHelloExtension) Read(b []byte) (int, error) {
	if len(b) < g.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(utlsExtensionECH >> 8)
	b[1] = byte(utlsExtensionECH & 0xFF)
	b[2] = byte((g.Len() - 4) >> 8)
	b[3] = byte((g.Len() - 4) & 0xFF)
	b[4] = OuterClientHello
	b[5] = byte(g.cipherSuite.KdfId >> 8)
	b[6] = byte(g.cipherSuite.KdfId & 0xFF)
	b[7] = byte(g.cipherSuite.AeadId >> 8)
	b[8] = byte(g.cipherSuite.AeadId & 0xFF)
	b[9] = g.configId
	b[10] = byte(len(g.EncapsulatedKey) >> 8)
	b[11] = byte(len(g.EncapsulatedKey) & 0xFF)
	copy(b[12:], g.EncapsulatedKey)
	b[12+len(g.EncapsulatedKey)] = byte(len(g.payload) >> 8)
	b[12+len(g.EncapsulatedKey)+1] = byte(len(g.payload) & 0xFF)
	copy(b[12+len(g.EncapsulatedKey)+2:], g.payload)

	return g.Len(), io.EOF
}

func (g *GREASEEncryptedClientHelloExtension) MarshalClientHello(uconn *UConn) error {
	return errors.New("tls: grease ech: MarshalClientHello() is not implemented, use (*UConn).MarshalClientHello() instead")
}

type UnimplementedECHExtension struct{}

func (*UnimplementedECHExtension) writeToUConn(_ *UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

func (*UnimplementedECHExtension) Len() int {
	return 0
}

func (*UnimplementedECHExtension) Read(_ []byte) (int, error) {
	return 0, errors.New("tls: unimplemented ECHExtension")
}

func (*UnimplementedECHExtension) MarshalClientHello(*UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

func (*UnimplementedECHExtension) mustEmbedUnimplementedECHExtension() {
	panic("mustEmbedUnimplementedECHExtension() is not implemented")
}
