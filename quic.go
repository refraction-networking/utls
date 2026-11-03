// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"

	itls "github.com/refraction-networking/utls/v2/internal/tls"
)

// QUICConn is a QUIC client TLS connection with a uTLS ClientHello. It is the
// counterpart of *crypto/tls.QUICConn and speaks only standard crypto/tls
// types (QUICConfig, QUICEvent, QUICEncryptionLevel, SessionState,
// ConnectionState), so a QUIC implementation drives it exactly as it drives
// tls.QUICClient: Start, then loop on NextEvent / HandleData.
//
// The built-in presets are TCP fingerprints; a browser's QUIC ClientHello
// differs (for example, it lists only TLS 1.3). For QUIC fidelity, apply a
// QUIC spec with ApplyPreset that contains a QUICTransportParametersExtension
// slot; without one the transport parameters are appended at the end of the
// extensions, before padding.
type QUICConn struct {
	q       *itls.QUICConn
	u       *itls.UConn
	id      ClientHelloID
	initErr error // config or fingerprint error, reported by Start

	mu sync.Mutex
	// sessions from the latest QUICResumeSession / QUICStoreSession events,
	// so edits the application makes to the std copies (EarlyData, Extra)
	// reach the handshake.
	resume *sessionPair
	stored map[*tls.SessionState]*itls.SessionState
}

type sessionPair struct {
	std *tls.SessionState
	in  *itls.SessionState
}

// QUICClient returns a uTLS QUIC client connection with fingerprint id. config
// and config.TLSConfig must not be nil; config.TLSConfig.MinVersion must allow
// TLS 1.3 (QUIC requires it). Errors from id or the config are reported by
// Start.
func QUICClient(config *tls.QUICConfig, id ClientHelloID) *QUICConn {
	spec, golang, err := id.resolve()
	var tcfg *tls.Config
	ecfg := false
	if config != nil {
		tcfg = config.TLSConfig
		ecfg = config.EnableSessionEvents
	}
	if config == nil || tcfg == nil {
		err = errors.New("utls: QUICClient requires a QUICConfig with a TLSConfig")
		tcfg = &tls.Config{InsecureSkipVerify: true}
	} else if cerr := configError(tcfg); cerr != nil {
		err = cerr
	}
	q, u := itls.NewUQUICConn(&itls.QUICConfig{TLSConfig: fromStdConfig(tcfg), EnableSessionEvents: ecfg}, spec, golang, err)
	return &QUICConn{q: q, u: u, id: id, initErr: err, stored: map[*tls.SessionState]*itls.SessionState{}}
}

// ApplyPreset sets the ClientHelloSpec (for HelloCustom or to override the
// preset). It must be called before Start.
func (q *QUICConn) ApplyPreset(spec *ClientHelloSpec) error {
	if spec == nil {
		return errors.New("utls: nil ClientHelloSpec")
	}
	return q.u.SetSpec(spec)
}

// SetClientHelloHook installs a ClientHello hook; see
// (*UConn).SetClientHelloHook. It must be called before Start.
func (q *QUICConn) SetClientHelloHook(h func(*ClientHelloContext) error) error {
	return q.u.SetClientHelloHook(h)
}

// SetSession makes the handshake offer cs; see (*UConn).SetSession.
func (q *QUICConn) SetSession(cs *tls.ClientSessionState) error {
	if cs == nil {
		return errors.New("utls: nil session")
	}
	ics, err := stdToInternalSession(cs)
	if err != nil {
		return err
	}
	return q.u.SetSession(ics)
}

// Start starts the client handshake; see tls.QUICConn.Start. A config or
// fingerprint error is returned here; other handshake errors (including
// ErrNoSpec for HelloCustom without ApplyPreset) surface as with crypto/tls,
// from HandleData or a QUICErrorEvent.
func (q *QUICConn) Start(ctx context.Context) error {
	if q.initErr != nil {
		return q.initErr
	}
	return itls.StdError(q.q.Start(ctx))
}

// NextEvent returns the next event; see tls.QUICConn.NextEvent. Event data is
// valid until the next call to NextEvent.
func (q *QUICConn) NextEvent() tls.QUICEvent {
	q.syncResume()
	e := q.q.NextEvent()
	out := tls.QUICEvent{
		Kind:  tls.QUICEventKind(e.Kind),
		Level: tls.QUICEncryptionLevel(e.Level),
		Data:  e.Data,
		Suite: e.Suite,
	}
	if e.Err != nil {
		out.Err = itls.StdError(e.Err)
	}
	if e.SessionState != nil {
		if std := stdSessionState(e.SessionState); std != nil {
			out.SessionState = std
			q.mu.Lock()
			switch e.Kind {
			case itls.QUICResumeSession:
				q.resume = &sessionPair{std, e.SessionState}
			case itls.QUICStoreSession:
				q.stored[std] = e.SessionState
			}
			q.mu.Unlock()
		}
	}
	return out
}

// syncResume copies the application's edits of the last QUICResumeSession
// session back before the handshake resumes.
func (q *QUICConn) syncResume() {
	q.mu.Lock()
	p := q.resume
	q.resume = nil
	q.mu.Unlock()
	if p != nil {
		p.in.EarlyData = p.std.EarlyData
		p.in.Extra = cloneExtra(p.std.Extra)
	}
}

// HandleData handles handshake bytes received from the peer; see
// tls.QUICConn.HandleData.
func (q *QUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	q.syncResume()
	return itls.StdError(q.q.HandleData(itls.QUICEncryptionLevel(level), data))
}

// SetTransportParameters sets the transport parameters to send; see
// tls.QUICConn.SetTransportParameters.
func (q *QUICConn) SetTransportParameters(params []byte) {
	q.q.SetTransportParameters(params)
}

// StoreSession stores a session from a QUICStoreSession event in the
// ClientSessionCache, including edits to its Extra and EarlyData fields; see
// tls.QUICConn.StoreSession.
func (q *QUICConn) StoreSession(session *tls.SessionState) error {
	if session == nil {
		return errors.New("utls: nil session")
	}
	q.mu.Lock()
	in := q.stored[session]
	delete(q.stored, session)
	q.mu.Unlock()
	if in == nil {
		b, err := session.Bytes()
		if err != nil {
			return err
		}
		if in, err = itls.ParseSessionState(b); err != nil {
			return err
		}
	}
	in.EarlyData = session.EarlyData
	in.Extra = cloneExtra(session.Extra)
	return itls.StdError(q.q.StoreSession(in))
}

// SendSessionTicket is not available on a client connection.
func (q *QUICConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("utls: SendSessionTicket called on a client connection")
}

// ConnectionState returns the standard connection state.
func (q *QUICConn) ConnectionState() tls.ConnectionState {
	return toStdConnectionState(q.q.ConnectionState())
}

// Close closes the connection and stops any in-progress handshake.
func (q *QUICConn) Close() error { return q.q.Close() }

// ClientHelloID returns the fingerprint the connection was created with.
func (q *QUICConn) ClientHelloID() ClientHelloID { return q.id }

// ClientHelloRaw returns the last ClientHello sent.
func (q *QUICConn) ClientHelloRaw() []byte { return q.u.ClientHelloRaw() }

func stdSessionState(s *itls.SessionState) *tls.SessionState {
	b, err := s.Bytes()
	if err != nil {
		return nil
	}
	std, err := tls.ParseSessionState(b)
	if err != nil {
		return nil
	}
	return std
}

func cloneExtra(x [][]byte) [][]byte {
	if x == nil {
		return nil
	}
	out := make([][]byte, len(x))
	for i, b := range x {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
