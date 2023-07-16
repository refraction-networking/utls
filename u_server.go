package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"
)

// ServerSessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
type ServerSessionState struct {
	Vers         uint16
	CipherSuite  uint16
	CreatedAt    uint64
	MasterSecret []byte // opaque master_secret<1..2^16-1>;
	// struct { opaque certificate<1..2^24-1> } Certificate;
	Certificates [][]byte // Certificate certificate_list<0..2^24-1>;

	// usedOldKey is true if the ticket from which this session came from
	// was encrypted with an older key and thus should be refreshed.
	UsedOldKey bool
}

// ForgeServerSessionState allows the creation of a Session (and SessionTicket)
// from a (presumably shared) secret value allowing a client to to
// "re-establish" a non-existent previous connection. With these values a
// ClientSessionState can be created to "resume" a session based on the secret
// value known to both the client and the server.
//
// Warning: you should probably not use this function, unless you are absolutely
// sure this is the functionality you are looking for.
func ForgeServerSessionState(masterSecret []byte, serverConfig *Config, chID ClientHelloID) (*ServerSessionState, error) {
	chSpec, err := utlsIdToSpec(chID)
	if err != nil {
		return nil, err
	}

	clientVersions := []uint16{}
	minVers, maxVers, err := getTLSVers(chSpec.TLSVersMin, chSpec.TLSVersMax, chSpec.Extensions)
	if err != nil {
		return nil, err
	}
	clientVersions = makeSupportedVersions(minVers, maxVers)

	vers, ok := serverConfig.mutualVersion(roleServer, clientVersions)
	if !ok {
		return nil, fmt.Errorf("unable to select mutual version")
	} else if vers < VersionTLS12 {
		return nil, fmt.Errorf("selected mutual version too old")
	}

	clientCipherSuites := make([]uint16, len(chSpec.CipherSuites))
	copy(clientCipherSuites, chSpec.CipherSuites)

	chosenCiphersuite, err := pickCipherSuite(clientCipherSuites, vers, serverConfig)
	if err != nil {
		return nil, err
	}

	sessionState := &ServerSessionState{
		Vers:         vers,
		CipherSuite:  chosenCiphersuite,
		CreatedAt:    uint64(time.Now().UnixMicro()),
		MasterSecret: masterSecret, // TODO
		Certificates: nil,
		// We are fabricating this session state for the key so it can't be old.
		UsedOldKey: false,
	}

	return sessionState, nil
}

func filterClientCiphers(c []*cipherSuite) []*cipherSuite {

	return []*cipherSuite{}
}

// func filterClientCipher(c *cipherSuite) bool {
// 	if c.flags&suiteECDHE != 0 {
// 		if !hs.ecdheOk {
// 			return false
// 		}
// 		if c.flags&suiteECSign != 0 {
// 			if !hs.ecSignOk {
// 				return false
// 			}
// 		} else if !hs.rsaSignOk {
// 			return false
// 		}
// 	} else if !hs.rsaDecryptOk {
// 		return false
// 	}
// 	return true
// }

// Marshal serializes the sessionState object to bytes.
func (ss *ServerSessionState) Marshal() ([]byte, error) {
	pss := ss.toPrivate()
	if pss == nil {
		return nil, nil
	}
	return pss.marshal()
}

func (ss *ServerSessionState) toPrivate() *sessionState {
	if ss == nil {
		return nil
	}
	return &sessionState{
		vers:         ss.Vers,
		cipherSuite:  ss.CipherSuite,
		createdAt:    ss.CreatedAt,
		masterSecret: ss.MasterSecret,
		certificates: ss.Certificates,
		usedOldKey:   ss.UsedOldKey,
	}
}

// MakeEncryptedTicket creates an encrypted session ticket that a client can
// then use to "re-establish" a non-existent previous connection. The value
// provided as keyBytes should be added to the servers ticketKeys using something
// like SetSessionKeys.
func (ss *ServerSessionState) MakeEncryptedTicket(keyBytes [32]byte, config *Config) ([]byte, error) {
	if config == nil {
		config = &Config{}
	}
	key := config.ticketKeyFromBytes(keyBytes)
	state, err := ss.Marshal()
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(state)+sha256.Size)
	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(config.rand(), iv); err != nil {
		return nil, err
	}

	copy(keyName, key.keyName[:])
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+aes.BlockSize:], state)

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

func pickCipherSuite(clientCipherSuites []uint16, vers uint16, config *Config) (uint16, error) {
	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(clientCipherSuites) {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}

	configCipherSuites := config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}

	var cipherSuiteOk = func(*cipherSuite) bool {
		return true
	}
	suite := selectCipherSuite(preferenceList, clientCipherSuites, cipherSuiteOk)
	if suite == nil {
		return 0, errors.New("tls: no cipher suite supported by both client and server")
	}
	cipherSuite := suite.id

	for _, id := range clientCipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection. See RFC 7507.
			if vers < config.maxSupportedVersion(roleServer) {
				return 0, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return cipherSuite, nil
}
