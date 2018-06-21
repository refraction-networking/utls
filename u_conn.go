// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
)

type UConn struct {
	*Conn

	Extensions    []TLSExtension
	clientHelloID ClientHelloID

	HandshakeState ClientHandshakeState

	HandshakeStateBuilt bool

	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	greaseSeed [ssl_grease_last_index]uint16
}

// UClient returns a new uTLS client, with behavior depending on clientHelloID.
// Config CAN be nil, but make sure to eventually specify ServerName.
func UClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) *UConn {
	if config == nil {
		config = &Config{}
	}
	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := ClientHandshakeState{C: &tlsConn, Hello: &ClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, clientHelloID: clientHelloID, HandshakeState: handshakeState}
	return &uconn
}

// BuildHandshakeState() overwrites most fields, therefore, it is advised to manually call this function,
// if you need to inspect/change contents after parroting/making default Golang ClientHello.
// Otherwise, there is no need to call this function explicitly.
func (uconn *UConn) BuildHandshakeState() error {
	if uconn.clientHelloID == HelloGolang {
		// use default Golang ClientHello.
		hello, err := makeClientHello(uconn.config)
		if uconn.HandshakeState.Session != nil {
			// session is lost at makeClientHello(), let's reapply
			uconn.SetSessionState(uconn.HandshakeState.Session)
		}
		if err != nil {
			return err
		}
		uconn.HandshakeState.Hello = hello.getPublicPtr()
	} else {
		var err error
		err = uconn.applyPresetByID(uconn.clientHelloID)
		if err != nil {
			return err
		}
		err = uconn.ApplyConfig()
		if err != nil {
			return err
		}
		err = uconn.MarshalClientHello()
		if err != nil {
			return err
		}
	}
	uconn.HandshakeStateBuilt = true
	return nil
}

// If you want session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionState(session *ClientSessionState) error {
	uconn.HandshakeState.Session = session
	var sessionTicket []uint8
	if session != nil {
		sessionTicket = session.sessionTicket
	}
	uconn.HandshakeState.Hello.TicketSupported = true
	uconn.HandshakeState.Hello.SessionTicket = sessionTicket
	for _, ext := range uconn.Extensions {
		st, ok := ext.(*SessionTicketExtension)
		if !ok {
			continue
		}
		st.Session = session
		if session != nil {
			if len(session.SessionTicket()) > 0 {
				if uconn.GetSessionID != nil {
					sid := uconn.GetSessionID(session.SessionTicket())
					uconn.HandshakeState.Hello.SessionId = sid[:]
					return nil
				}
			}
			var sessionID [32]byte
			_, err := io.ReadFull(uconn.config.rand(), uconn.HandshakeState.Hello.SessionId)
			if err != nil {
				return err
			}
			uconn.HandshakeState.Hello.SessionId = sessionID[:]
		}
		return nil
	}
	return errors.New("SessionTicketExtension is not part of current spec and won't be sent")
}

// If you want session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionCache(cache ClientSessionCache) {
	uconn.config.ClientSessionCache = cache
	uconn.HandshakeState.Hello.TicketSupported = true
}

// r has to be 32 bytes long
func (uconn *UConn) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("Incorrect client random length! Expected: 32, got: " + strconv.Itoa(len(r)))
	} else {
		uconn.HandshakeState.Hello.Random = make([]byte, 32)
		copy(uconn.HandshakeState.Hello.Random, r)
		return nil
	}
}

func (uconn *UConn) SetSNI(sni string) {
	hname := hostnameInSNI(sni)
	uconn.config.ServerName = hname
	for _, ext := range uconn.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
}

// Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (c *UConn) Handshake() error {
	// This code was copied almost as is from tls/conn.go
	// c.handshakeErr and c.handshakeComplete are protected by
	// c.handshakeMutex. In order to perform a handshake, we need to lock
	// c.in also and c.handshakeMutex must be locked after c.in.
	//
	// However, if a Read() operation is hanging then it'll be holding the
	// lock on c.in and so taking it here would cause all operations that
	// need to check whether a handshake is pending (such as Write) to
	// block.
	//
	// Thus we first take c.handshakeMutex to check whether a handshake is
	// needed.
	//
	// If so then, previously, this code would unlock handshakeMutex and
	// then lock c.in and handshakeMutex in the correct order to run the
	// handshake. The problem was that it was possible for a Read to
	// complete the handshake once handshakeMutex was unlocked and then
	// keep c.in while waiting for network data. Thus a concurrent
	// operation could be blocked on c.in.
	//
	// Thus handshakeCond is used to signal that a goroutine is committed
	// to running the handshake and other goroutines can wait on it if they
	// need. handshakeCond is protected by handshakeMutex.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.isClient {
		if !c.HandshakeStateBuilt {
			err := c.BuildHandshakeState()
			if err != nil {
				return err
			}
		}

		privateState := c.HandshakeState.getPrivatePtr()
		c.handshakeErr = c.clientHandshakeWithState(privateState)
		c.HandshakeState = *privateState.getPublicPtr()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.handshakeComplete {
		panic("handshake should have had a result.")
	}

	return c.handshakeErr
}

// Copy-pasted from tls.Conn in its entirety. But c.Handshake() is now utls' one, not tls.
// Write writes data to the connection.
func (c *UConn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, errClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	// SSL 3.0 and TLS 1.0 are susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// http://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// http://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.vers <= VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

// c.out.Mutex <= L; c.handshakeMutex <= L.
func (c *Conn) clientHandshakeWithState(hs *clientHandshakeState) error {
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	// UTLS: don't make new ClientHello, use hs.hello

	// UTLS: preserve the check from makeClientHello [start]
	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
		return errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}
	//  UTLS: preserve the check from makeClientHello [end]

	if c.handshakes > 0 {
		hs.hello.secureRenegotiation = c.clientFinished[:]
	}

	var session *ClientSessionState
	var cacheKey string
	sessionCache := c.config.ClientSessionCache

	if c.config.SessionTicketsDisabled {
		sessionCache = nil
	}

	if sessionCache != nil {
		hs.hello.ticketSupported = true
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if sessionCache != nil && c.handshakes == 0 && hs.session == nil { // [UTLS] hs.session == nil
		// Try to resume a previously negotiated TLS session, if
		// available.
		cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
		candidateSession, ok := sessionCache.Get(cacheKey)
		if ok {
			// Check that the ciphersuite/version used for the
			// previous session are still valid.
			cipherSuiteOk := false
			for _, id := range hs.hello.cipherSuites {
				if id == candidateSession.cipherSuite {
					cipherSuiteOk = true
					break
				}
			}

			versOk := candidateSession.vers >= c.config.minVersion() &&
				candidateSession.vers <= c.config.maxVersion()
			if versOk && cipherSuiteOk {
				session = candidateSession
			}
		}
	}

	if session != nil {
		if hs.hello.sessionTicket == nil { // [UTLS] check
			hs.hello.sessionTicket = session.sessionTicket
		}
		// A random session ID is used to detect when the
		// server accepted the ticket and is resuming a session
		// (see RFC 5077).

		if hs.hello.sessionId == nil { // [UTLS] check
			hs.hello.sessionId = make([]byte, 16)
			if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
	}

	if err := hs.handshake(); err != nil {
		return err
	}

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one
	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

func (uconn *UConn) ApplyConfig() error {
	for _, ext := range uconn.Extensions {
		err := ext.writeToUConn(uconn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uconn *UConn) MarshalClientHello() error {
	hello := uconn.HandshakeState.Hello
	headerLength := 2 + 32 + 1 + len(hello.SessionId) +
		2 + len(hello.CipherSuites)*2 +
		1 + len(hello.CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension
	for _, ext := range uconn.Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			// If not padding - just add length of extension to total length
			extensionsLen += ext.Len()
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("Multiple padding extensions!")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uconn.Extensions) > 0 {
		helloLen += 2 + extensionsLen // 2 bytes for extensions' length
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4) // 1 byte for tls record type, 3 for length
	// We use buffered Writer to avoid checking write errors after every Write(): whenever first error happens
	// Write() will become noop, and error will be accessible via Flush(), which is called once in the end

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)} // poor man's uint24
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello.Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello.Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello.CipherSuites)<<1))
	for _, suite := range hello.CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.CompressionMethods)

	if len(uconn.Extensions) > 0 {
		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uconn.Extensions {
			bufferedWriter.ReadFrom(ext)
		}
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("utls: unexpected ClientHello length. Expected: " + strconv.Itoa(4+helloLen) +
			". Got: " + strconv.Itoa(helloBuffer.Len()))
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	hello.Raw = helloBuffer.Bytes()
	return nil
}

// get current state of cipher and encrypt zeros to get keystream
func (uconn *UConn) GetOutKeystream(length int) ([]byte, error) {
	zeros := make([]byte, length)

	if outCipher, ok := uconn.out.cipher.(cipher.AEAD); ok {
		// AEAD.Seal() does not mutate internal state, other ciphers might
		return outCipher.Seal(nil, uconn.out.seq[:], zeros, nil), nil
	}
	return nil, errors.New("Could not convert OutCipher to cipher.AEAD")
}
