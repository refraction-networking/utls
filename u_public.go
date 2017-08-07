// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/cipher"
	"crypto/x509"
	"hash"
)

type ClientHandshakeState struct {
	C            *Conn
	ServerHello  *ServerHelloMsg
	Hello        *ClientHelloMsg
	Suite        *CipherSuite
	FinishedHash FinishedHash
	MasterSecret []byte
	Session      *ClientSessionState
}

// getPrivatePtr() methods make shallow copies

func (chs *ClientHandshakeState) getPrivatePtr() *clientHandshakeState {
	if chs == nil {
		return nil
	} else {
		return &clientHandshakeState{
			c:            chs.C,
			serverHello:  chs.ServerHello.getPrivatePtr(),
			hello:        chs.Hello.getPrivatePtr(),
			suite:        chs.Suite.getPrivatePtr(),
			finishedHash: *chs.FinishedHash.getPrivatePtr(),
			masterSecret: chs.MasterSecret,
			session:      chs.Session,
		}
	}
}

func (chs *clientHandshakeState) getPublicPtr() *ClientHandshakeState {
	if chs == nil {
		return nil
	} else {
		return &ClientHandshakeState{
			C:            chs.c,
			ServerHello:  chs.serverHello.getPublicPtr(),
			Hello:        chs.hello.getPublicPtr(),
			Suite:        chs.suite.getPublicPtr(),
			FinishedHash: *chs.finishedHash.getPublicPtr(),
			MasterSecret: chs.masterSecret,
			Session:      chs.session,
		}
	}
}

type BensStruct serverHelloMsg

type ServerHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	NextProtoNeg                 bool
	NextProtos                   []string
	OcspStapling                 bool
	Scts                         [][]byte
	TicketSupported              bool
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocol                 string
}

func (shm *ServerHelloMsg) getPrivatePtr() *serverHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &serverHelloMsg{
			raw:                          shm.Raw,
			vers:                         shm.Vers,
			random:                       shm.Random,
			sessionId:                    shm.SessionId,
			cipherSuite:                  shm.CipherSuite,
			compressionMethod:            shm.CompressionMethod,
			nextProtoNeg:                 shm.NextProtoNeg,
			nextProtos:                   shm.NextProtos,
			ocspStapling:                 shm.OcspStapling,
			scts:                         shm.Scts,
			ticketSupported:              shm.TicketSupported,
			secureRenegotiation:          shm.SecureRenegotiation,
			secureRenegotiationSupported: shm.SecureRenegotiationSupported,
			alpnProtocol:                 shm.AlpnProtocol,
		}
	}
}

func (shm *serverHelloMsg) getPublicPtr() *ServerHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &ServerHelloMsg{
			Raw:                          shm.raw,
			Vers:                         shm.vers,
			Random:                       shm.random,
			SessionId:                    shm.sessionId,
			CipherSuite:                  shm.cipherSuite,
			CompressionMethod:            shm.compressionMethod,
			NextProtoNeg:                 shm.nextProtoNeg,
			NextProtos:                   shm.nextProtos,
			OcspStapling:                 shm.ocspStapling,
			Scts:                         shm.scts,
			TicketSupported:              shm.ticketSupported,
			SecureRenegotiation:          shm.secureRenegotiation,
			SecureRenegotiationSupported: shm.secureRenegotiationSupported,
			AlpnProtocol:                 shm.alpnProtocol,
		}
	}
}

type ClientHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuites                 []uint16
	CompressionMethods           []uint8
	NextProtoNeg                 bool
	ServerName                   string
	OcspStapling                 bool
	Scts                         bool
	SupportedCurves              []CurveID
	SupportedPoints              []uint8
	TicketSupported              bool
	SessionTicket                []uint8
	SignatureAndHashes           []SignatureAndHash
	SecureRenegotiation          []byte
	SecureRenegotiationSupported bool
	AlpnProtocols                []string
}

func (chm *ClientHelloMsg) getPrivatePtr() *clientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &clientHelloMsg{
			raw:                          chm.Raw,
			vers:                         chm.Vers,
			random:                       chm.Random,
			sessionId:                    chm.SessionId,
			cipherSuites:                 chm.CipherSuites,
			compressionMethods:           chm.CompressionMethods,
			nextProtoNeg:                 chm.NextProtoNeg,
			serverName:                   chm.ServerName,
			ocspStapling:                 chm.OcspStapling,
			scts:                         chm.Scts,
			supportedCurves:              chm.SupportedCurves,
			supportedPoints:              chm.SupportedPoints,
			ticketSupported:              chm.TicketSupported,
			sessionTicket:                chm.SessionTicket,
			signatureAndHashes:           sigAndHashGetMakePrivate(chm.SignatureAndHashes),
			secureRenegotiation:          chm.SecureRenegotiation,
			secureRenegotiationSupported: chm.SecureRenegotiationSupported,
			alpnProtocols:                chm.AlpnProtocols,
		}
	}
}

func (chm *clientHelloMsg) getPublicPtr() *ClientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &ClientHelloMsg{
			Raw:                          chm.raw,
			Vers:                         chm.vers,
			Random:                       chm.random,
			SessionId:                    chm.sessionId,
			CipherSuites:                 chm.cipherSuites,
			CompressionMethods:           chm.compressionMethods,
			NextProtoNeg:                 chm.nextProtoNeg,
			ServerName:                   chm.serverName,
			OcspStapling:                 chm.ocspStapling,
			Scts:                         chm.scts,
			SupportedCurves:              chm.supportedCurves,
			SupportedPoints:              chm.supportedPoints,
			TicketSupported:              chm.ticketSupported,
			SessionTicket:                chm.sessionTicket,
			SignatureAndHashes:           sigAndHashMakePublic(chm.signatureAndHashes),
			SecureRenegotiation:          chm.secureRenegotiation,
			SecureRenegotiationSupported: chm.secureRenegotiationSupported,
			AlpnProtocols:                chm.alpnProtocols,
		}
	}
}

// SignatureAndHash mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See
// RFC 5246, section A.4.1.
type SignatureAndHash struct {
	Hash, Signature uint8
}

func sigAndHashGetMakePrivate(sahSlice []SignatureAndHash) []signatureAndHash {
	res := []signatureAndHash{}
	for _, sah := range sahSlice {
		res = append(res, signatureAndHash{hash: sah.Hash,
			signature: sah.Signature})
	}
	return res
}

func sigAndHashMakePublic(sahSlice []signatureAndHash) []SignatureAndHash {
	res := []SignatureAndHash{}
	for _, sah := range sahSlice {
		res = append(res, SignatureAndHash{Hash: sah.hash,
			Signature: sah.signature})
	}
	return res
}

// A CipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type CipherSuite struct {
	Id uint16
	// the lengths, in bytes, of the key material needed for each component.
	KeyLen int
	MacLen int
	IvLen  int
	Ka     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	Flags  int
	Cipher func(key, iv []byte, isRead bool) interface{}
	Mac    func(version uint16, macKey []byte) macFunction
	Aead   func(key, fixedNonce []byte) cipher.AEAD
}

func (cs *CipherSuite) getPrivatePtr() *cipherSuite {
	if cs == nil {
		return nil
	} else {
		return &cipherSuite{
			id:     cs.Id,
			keyLen: cs.KeyLen,
			macLen: cs.MacLen,
			ivLen:  cs.IvLen,
			ka:     cs.Ka,
			flags:  cs.Flags,
			cipher: cs.Cipher,
			mac:    cs.Mac,
			aead:   cs.Aead,
		}
	}
}

func (cs *cipherSuite) getPublicPtr() *CipherSuite {
	if cs == nil {
		return nil
	} else {
		return &CipherSuite{
			Id:     cs.id,
			KeyLen: cs.keyLen,
			MacLen: cs.macLen,
			IvLen:  cs.ivLen,
			Ka:     cs.ka,
			Flags:  cs.flags,
			Cipher: cs.cipher,
			Mac:    cs.mac,
			Aead:   cs.aead,
		}
	}
}

// A FinishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type FinishedHash struct {
	Client hash.Hash
	Server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	ClientMD5 hash.Hash
	ServerMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	Buffer []byte

	Version uint16
	Prf     func(result, secret, label, seed []byte)
}

func (fh *FinishedHash) getPrivatePtr() *finishedHash {
	if fh == nil {
		return nil
	} else {
		return &finishedHash{
			client:    fh.Client,
			server:    fh.Server,
			clientMD5: fh.ClientMD5,
			serverMD5: fh.ServerMD5,
			buffer:    fh.Buffer,
			version:   fh.Version,
			prf:       fh.Prf,
		}
	}
}

func (fh *finishedHash) getPublicPtr() *FinishedHash {
	if fh == nil {
		return nil
	} else {
		return &FinishedHash{
			Client:    fh.client,
			Server:    fh.server,
			ClientMD5: fh.clientMD5,
			ServerMD5: fh.serverMD5,
			Buffer:    fh.buffer,
			Version:   fh.version,
			Prf:       fh.prf}
	}
}

// ClientSessionState is public, but all its fields are private. Let's add setters, getters and constructor

// ClientSessionState contains the state needed by clients to resume TLS sessions.
func MakeClientSessionState(
	SessionTicket []uint8,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	ServerCertificates []*x509.Certificate,
	VerifiedChains [][]*x509.Certificate) *ClientSessionState {
	css := ClientSessionState{sessionTicket: SessionTicket,
		vers:               Vers,
		cipherSuite:        CipherSuite,
		masterSecret:       MasterSecret,
		serverCertificates: ServerCertificates,
		verifiedChains:     VerifiedChains}
	return &css
}

// Encrypted ticket used for session resumption with server
func (css *ClientSessionState) SessionTicket() []uint8 {
	return css.sessionTicket
}

// SSL/TLS version negotiated for the session
func (css *ClientSessionState) Vers() uint16 {
	return css.vers
}

// Ciphersuite negotiated for the session
func (css *ClientSessionState) CipherSuite() uint16 {
	return css.cipherSuite
}

// MasterSecret generated by client on a full handshake
func (css *ClientSessionState) MasterSecret() []byte {
	return css.masterSecret
}

// Certificate chain presented by the server
func (css *ClientSessionState) ServerCertificates() []*x509.Certificate {
	return css.serverCertificates
}

// Certificate chains we built for verification
func (css *ClientSessionState) VerifiedChains() [][]*x509.Certificate {
	return css.verifiedChains
}

func (css *ClientSessionState) SetSessionTicket(SessionTicket []uint8) {
	css.sessionTicket = SessionTicket
}
func (css *ClientSessionState) SetVers(Vers uint16) {
	css.vers = Vers
}
func (css *ClientSessionState) SetCipherSuite(CipherSuite uint16) {
	css.cipherSuite = CipherSuite
}
func (css *ClientSessionState) SetMasterSecret(MasterSecret []byte) {
	css.masterSecret = MasterSecret
}
func (css *ClientSessionState) SetServerCertificates(ServerCertificates []*x509.Certificate) {
	css.serverCertificates = ServerCertificates
}
func (css *ClientSessionState) SetVerifiedChains(VerifiedChains [][]*x509.Certificate) {
	css.verifiedChains = VerifiedChains
}
