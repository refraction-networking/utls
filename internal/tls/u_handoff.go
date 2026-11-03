// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// ErrHandedOff is returned by Read and Write after HandOff.
var ErrHandedOff = errors.New("utls: record layer was handed off")

// RecordLayerState is the complete TLS 1.3 record-layer state of a client
// connection at the moment of HandOff. Read is server-to-client, Write is
// client-to-server. It contains secrets: treat it like a private key.
type RecordLayerState struct {
	Version     uint16 // always VersionTLS13
	CipherSuite uint16

	// Current application traffic secrets (RFC 8446 7.1), needed to follow
	// KeyUpdate, and the record keys and IVs derived from them (7.3).
	ReadTrafficSecret, WriteTrafficSecret []byte
	ReadKey, ReadIV, WriteKey, WriteIV    []byte

	// Sequence numbers of the next record to decrypt / encrypt.
	ReadSeq, WriteSeq uint64

	// Plaintext is application data already decrypted but not yet returned
	// by Read; it precedes everything in RawInput.
	Plaintext []byte
	// RawInput is bytes received from Conn but not yet decrypted. It starts
	// at a record boundary and may end in the middle of a record.
	RawInput []byte

	// Conn is the underlying transport, now owned by the caller. (Closing the
	// TLS connection still closes it, without sending close_notify.)
	Conn net.Conn
}

// HandOff detaches the record layer of a completed TLS 1.3 connection so the
// caller can continue it elsewhere: kernel TLS (load the keys and sequence
// numbers), a splice/Vision-style switch to raw copying (drain Plaintext and
// RawInput first), or a custom record layer. After HandOff, Read and Write
// return ErrHandedOff and Close sends no close_notify, so the TLS stack never
// again touches the transport with stale state. It must not be called while
// a Read or Write is in progress (it waits for them).
//
// It fails, leaving the connection usable, for TLS 1.2 (whose keys are not
// retained), QUIC, an incomplete handshake, a broken connection, or when a
// post-handshake message is partially buffered.
func (u *UConn) HandOff() (*RecordLayerState, error) {
	c := u.Conn
	if c.quic != nil {
		return nil, errors.New("utls: HandOff does not apply to QUIC")
	}
	if !c.isHandshakeComplete.Load() {
		return nil, errors.New("utls: HandOff before the handshake completed")
	}
	c.in.Lock()
	defer c.in.Unlock()
	c.out.Lock()
	defer c.out.Unlock()
	if c.in.err != nil || c.out.err != nil {
		return nil, errors.New("utls: HandOff on a closed or failed connection")
	}
	if c.vers != VersionTLS13 {
		return nil, errors.New("utls: HandOff requires TLS 1.3")
	}
	if c.hand.Len() > 0 {
		return nil, errors.New("utls: HandOff with a partially received post-handshake message")
	}
	if c.closeNotifySent {
		return nil, errors.New("utls: HandOff after CloseWrite")
	}
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil || c.in.trafficSecret == nil || c.out.trafficSecret == nil {
		return nil, errors.New("utls: HandOff: no TLS 1.3 traffic secrets")
	}
	st := &RecordLayerState{
		Version:            VersionTLS13,
		CipherSuite:        c.cipherSuite,
		ReadTrafficSecret:  bytes.Clone(c.in.trafficSecret),
		WriteTrafficSecret: bytes.Clone(c.out.trafficSecret),
		ReadSeq:            binary.BigEndian.Uint64(c.in.seq[:]),
		WriteSeq:           binary.BigEndian.Uint64(c.out.seq[:]),
		Conn:               c.conn,
	}
	st.ReadKey, st.ReadIV = suite.trafficKey(st.ReadTrafficSecret)
	st.WriteKey, st.WriteIV = suite.trafficKey(st.WriteTrafficSecret)
	// c.input aliases c.rawInput's storage: copy both before poisoning.
	st.Plaintext, _ = io.ReadAll(&c.input)
	st.RawInput = bytes.Clone(c.rawInput.Bytes())
	c.rawInput.Reset()

	c.in.setErrorLocked(ErrHandedOff)
	c.out.setErrorLocked(ErrHandedOff)
	c.closeNotifySent = true // Close must not write an alert with stale state
	return st, nil
}
