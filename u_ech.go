package tls

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/cryptobyte"
)

// Unstable API: This is a work in progress and may change in the future. Using
// it in your application may cause your application to break when updating to
// a new version of uTLS.

type ECHConfigContents struct {
	KeyConfig         HPKEKeyConfig
	MaximumNameLength uint8
	PublicName        []byte
	Extensions        []TLSExtension // ignored for now
	rawExtensions     []byte
}

func UnmarshalECHConfigContents(contents []byte) (ECHConfigContents, error) {
	var (
		contentCryptobyte = cryptobyte.String(contents)
		config            ECHConfigContents
	)

	// Parse KeyConfig
	var t cryptobyte.String
	if !contentCryptobyte.ReadUint8(&config.KeyConfig.ConfigId) ||
		!contentCryptobyte.ReadUint16(&config.KeyConfig.KemId) ||
		!contentCryptobyte.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.KeyConfig.rawPublicKey, len(t)) ||
		!contentCryptobyte.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 {
		return config, errors.New("error parsing KeyConfig")
	}

	// Parse all CipherSuites in KeyConfig
	config.KeyConfig.CipherSuites = nil
	for !t.Empty() {
		var kdfId, aeadId uint16
		if !t.ReadUint16(&kdfId) || !t.ReadUint16(&aeadId) {
			// This indicates an internal bug.
			panic("internal error while parsing contents.cipher_suites")
		}
		config.KeyConfig.CipherSuites = append(config.KeyConfig.CipherSuites, HPKESymmetricCipherSuite{kdfId, aeadId})
	}

	if !contentCryptobyte.ReadUint8(&config.MaximumNameLength) ||
		!contentCryptobyte.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&config.PublicName, len(t)) ||
		!contentCryptobyte.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&config.rawExtensions, len(t)) ||
		!contentCryptobyte.Empty() {
		return config, errors.New("error parsing ECHConfigContents")
	}
	return config, nil
}

func (echcc *ECHConfigContents) ParsePublicKey() error {
	var err error
	kem := hpke.KEM(echcc.KeyConfig.KemId)
	if !kem.IsValid() {
		return errors.New("invalid KEM")
	}
	echcc.KeyConfig.PublicKey, err = kem.Scheme().UnmarshalBinaryPublicKey(echcc.KeyConfig.rawPublicKey)
	if err != nil {
		return fmt.Errorf("error parsing public key: %s", err)
	}
	return nil
}

type ECHConfig struct {
	Version  uint16
	Length   uint16
	Contents ECHConfigContents

	raw []byte
}

// UnmarshalECHConfigs parses a sequence of ECH configurations.
//
// Ported from cloudflare/go
func UnmarshalECHConfigs(raw []byte) ([]ECHConfig, error) {
	var (
		err         error
		config      ECHConfig
		t, contents cryptobyte.String
	)
	configs := make([]ECHConfig, 0)
	s := cryptobyte.String(raw)
	if !s.ReadUint16LengthPrefixed(&t) || !s.Empty() {
		return configs, errors.New("error parsing configs")
	}
	raw = raw[2:]
ConfigsLoop:
	for !t.Empty() {
		l := len(t)
		if !t.ReadUint16(&config.Version) ||
			!t.ReadUint16LengthPrefixed(&contents) {
			return nil, errors.New("error parsing config")
		}
		n := l - len(t)
		config.raw = raw[:n]
		raw = raw[n:]

		if config.Version != utlsExtensionECH {
			continue ConfigsLoop
		}

		/**** cloudflare/go original ****/
		// if !readConfigContents(&contents, &config) {
		// 	return nil, errors.New("error parsing config contents")
		// }

		config.Contents, err = UnmarshalECHConfigContents(contents)
		if err != nil {
			return nil, fmt.Errorf("error parsing config contents: %s", err)
		}

		/**** cloudflare/go original ****/
		// kem := hpke.KEM(config.kemId)
		// if !kem.IsValid() {
		// 	continue ConfigsLoop
		// }
		// config.pk, err = kem.Scheme().UnmarshalBinaryPublicKey(config.rawPublicKey)
		// if err != nil {
		// 	return nil, fmt.Errorf("error parsing public key: %s", err)
		// }

		config.Contents.ParsePublicKey() // parse the bytes into a public key

		configs = append(configs, config)
	}
	return configs, nil
}

type EncryptedClientHelloExtension interface {
	// TLSExtension must be implemented by all EncryptedClientHelloExtension implementations.
	TLSExtension

	EnableOuter() // EnableOuter enables the outer extension content to be output by Read(). It lasts only one Read() call.
}

type GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites []HPKESymmetricCipherSuite // if empty, will populate with one random value and proceed
	cipherSuite           HPKESymmetricCipherSuite   // randomly picked from CandidateCipherSuites or generated if empty
	CandidateConfigIds    []uint8                    // if empty, will populate with one random value and proceed
	configId              uint8                      // randomly picked from CandidateConfigIds or generated if empty
	EncapsulatedKey       []byte                     // if empty, will generate random bytes
	payload               []byte                     // payload should be calculated ONCE and stored here, HRR will reuse this

	outer bool // if true, Read() will output the outer extension content, otherwise the inner (empty)
}

// init initializes the GREASEEncryptedClientHelloExtension with random values if they are not set.
//
// Based on cloudflare/go's echGenerateGreaseExt()
func (g *GREASEEncryptedClientHelloExtension) init() error {
	// Set the config_id field to a random byte.
	//
	// Note: must not reuse this extension unless for HRR. It is required
	// to generate new random bytes for config_id for each new ClientHello,
	// but reuse the same config_id for HRR.
	if len(g.CandidateConfigIds) == 0 {
		var b []byte = make([]byte, 1)
		_, err := rand.Read(b[:])
		if err != nil {
			return fmt.Errorf("error generating random byte for config_id: %w", err)
		}
		g.configId = b[0]
	} else {
		// randomly pick one from the list
		rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateConfigIds))))
		if err != nil {
			return fmt.Errorf("error generating random index for config_id: %w", err)
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
			return fmt.Errorf("error generating random index for cipher_suite: %w", err)
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
			return fmt.Errorf("tls: grease ech: failed to parse dummy public key: %w", err)
		}
		sender, err := defaultHPKESuite.NewSender(pk, nil)
		if err != nil {
			return fmt.Errorf("tls: grease ech: failed to create sender: %w", err)
		}

		g.EncapsulatedKey, _, err = sender.Setup(rand.Reader)
		if err != nil {
			return fmt.Errorf("tls: grease ech: failed to setup encapsulated key: %w", err)
		}
	}

	return nil
}

func (g *GREASEEncryptedClientHelloExtension) generatePayload(encodedHelloInnerLen uint) error {
	aead := hpke.AEAD(g.cipherSuite.AeadId)
	g.payload = make([]byte, int(aead.CipherLen(encodedHelloInnerLen)))
	_, err := rand.Read(g.payload)
	if err != nil {
		return fmt.Errorf("tls: generating grease ech payload: %w", err)
	}
	return nil
}

func (g *GREASEEncryptedClientHelloExtension) EnableOuter() {
	g.outer = true
}

func (g *GREASEEncryptedClientHelloExtension) Read(data []byte) (int, error) {
	defer func() {
		g.outer = false // always set back to false after a Read() no matter what
	}()

	if g.outer {
		// From draft-ietf-tls-esni-17, section 5:
		//
		//  case outer:
		//	 	HpkeSymmetricCipherSuite cipher_suite;
		// 		uint8 config_id;
		// 		opaque enc<0..2^16-1>;
		// 		opaque payload<1..2^16-1>;
		//

	} else {
		// From draft-ietf-tls-esni-17, section 5:
		//
		//  case inner:
		//	 	Empty;
		//
		return 0, nil
	}

	return 0, nil
}
