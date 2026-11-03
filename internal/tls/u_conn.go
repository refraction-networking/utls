// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/refraction-networking/utls/internal/tls13"
)

// UConn is a crypto/tls client *Conn whose ClientHello is rendered from a
// ClientHelloSpec. It is created by the module's root package.
type UConn struct {
	*Conn

	mu sync.Mutex // guards the fields below that are read after the handshake

	spec    *ClientHelloSpec // owned copy; nil only with golang
	golang  bool             // explicit stock crypto/tls ClientHello
	specErr error            // error from resolving the fingerprint, reported at handshake

	clientHelloHook func(*ClientHelloContext) error
	injected        *ClientSessionState

	started  bool   // the handshake has begun; configuration is frozen
	snapshot []byte // last ClientHello rendered for the wire (immutable copy)
	build    *helloBuild
	renderer *helloRenderer
	hello    *clientHelloMsg
	keys     map[CurveID]*keySharePrivateKeys

	serverHelloRaw []byte
	serverKeyShare keyShare

	// negotiated
	alpsNegotiated        bool
	peerALPS              []byte
	peerRecordSizeLimit   int
	recordLimitNegotiated bool
}

// NewUConn wraps conn as a uTLS client. spec is cloned. If golang is true the
// stock crypto/tls ClientHello is sent and spec must be nil. A nil spec without
// golang (and specErr) makes the handshake fail with specErr or ErrNoSpec.
func NewUConn(conn net.Conn, config *Config, spec *ClientHelloSpec, golang bool, specErr error) *UConn {
	u := &UConn{
		Conn:    Client(conn, config),
		spec:    spec.Clone(),
		golang:  golang,
		specErr: specErr,
	}
	u.Conn.uconn = u
	return u
}

// NewUQUICConn is NewUConn for a QUIC client connection.
func NewUQUICConn(config *QUICConfig, spec *ClientHelloSpec, golang bool, specErr error) (*QUICConn, *UConn) {
	q := QUICClient(config)
	u := &UConn{Conn: q.conn, spec: spec.Clone(), golang: golang, specErr: specErr}
	q.conn.uconn = u
	return q, u
}

// SetSpec replaces the spec before the handshake (it is cloned).
func (u *UConn) SetSpec(s *ClientHelloSpec) error {
	u.mu.Lock()
	started := u.started
	u.mu.Unlock()
	if started {
		return errors.New("utls: cannot change the ClientHelloSpec after the handshake started")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	u.spec, u.golang, u.specErr = s.Clone(), false, nil
	return nil
}

// SetClientHelloHook installs the authentication hook (see ClientHelloContext).
func (u *UConn) SetClientHelloHook(h func(*ClientHelloContext) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.started {
		return errors.New("utls: SetClientHelloHook must be called before the handshake")
	}
	u.clientHelloHook = h
	return nil
}

// SetSession makes the first handshake offer cs (a TLS 1.2 ticket or a TLS 1.3
// PSK) regardless of the session cache. It is the out-of-band resumption
// interface (forged/obfuscated tickets): the session is trusted as given; its
// certificates, if any, are not re-verified.
func (u *UConn) SetSession(cs *ClientSessionState) error {
	if cs == nil || cs.session == nil {
		return errors.New("utls: nil session")
	}
	u.mu.Lock()
	started := u.started
	u.mu.Unlock()
	if started {
		return errors.New("utls: SetSession must be called before the handshake")
	}
	u.injected = cs
	return nil
}

// HandshakeContext runs the handshake.
func (u *UConn) HandshakeContext(ctx context.Context) error { return u.Conn.HandshakeContext(ctx) }

// EphemeralKey returns the classical ECDH private key offered for group (for a
// hybrid group, its X25519/ECDH half), or nil.
func (u *UConn) EphemeralKey(group CurveID) *ecdh.PrivateKey {
	u.mu.Lock()
	defer u.mu.Unlock()
	if k := u.keys[group]; k != nil {
		return k.ecdhe
	}
	return nil
}

// ServerKeyShareGroup and ServerKeyShareData expose the key share the server
// selected (TLS 1.3), available from certificate verification onwards.
func (u *UConn) ServerKeyShareGroup() CurveID {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.serverKeyShare.group
}

func (u *UConn) ServerKeyShareData() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.serverKeyShare.data)
}

// ServerHelloRaw returns the last ServerHello handshake message received.
func (u *UConn) ServerHelloRaw() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.serverHelloRaw)
}

// ClientHelloRaw returns an immutable copy of the last ClientHello rendered for
// the wire (after a HelloRetryRequest, the retried one; with ECH, the outer
// one); nil before the first ClientHello. For HelloGolang it is the first
// ClientHello. Safe to call concurrently with the handshake.
func (u *UConn) ClientHelloRaw() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.snapshot)
}

func (u *UConn) setSnapshot(raw []byte) {
	u.mu.Lock()
	u.snapshot = slices.Clone(raw)
	u.mu.Unlock()
}

// NegotiatedApplicationSettings returns the server's ALPS settings and whether
// ALPS was negotiated.
func (u *UConn) NegotiatedApplicationSettings() ([]byte, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.peerALPS), u.alpsNegotiated
}

// PeerRecordSizeLimit returns the server's record_size_limit, or 0.
func (u *UConn) PeerRecordSizeLimit() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.peerRecordSizeLimit
}

// ClientHelloContext is passed to the ClientHello hook. It runs once, on the
// first ClientHello, after any session has been loaded and binders computed,
// immediately before the hello is sent.
//
// Raw is the complete ClientHello handshake message exactly as it will be
// sent, except that pre_shared_key binders (if any) are zero in Raw and
// computed after the hook returns (see PSK). Random and SessionID alias Raw; the hook may overwrite their
// contents in place (not their length). Modifying any other byte of Raw is an
// error. The same Random and SessionID are used for a ClientHello retried after
// HelloRetryRequest, as RFC 8446 requires.
type ClientHelloContext struct {
	Raw       []byte
	Random    []byte
	SessionID []byte
	// PSK reports that the hello offers a pre_shared_key. Its binders are
	// computed after the hook returns (they cover Random and SessionID), so
	// in Raw they are zeroed and differ from the bytes sent: an authenticator
	// over the whole of Raw cannot be verified by the peer. Schemes that MAC
	// the full ClientHello (REALITY-style) must not offer resumption.
	PSK bool

	keys map[CurveID]*keySharePrivateKeys
}

// EphemeralKey returns the classical ECDH private key offered for group (for a
// hybrid group, its X25519 half), or nil.
func (c *ClientHelloContext) EphemeralKey(group CurveID) *ecdh.PrivateKey {
	if k := c.keys[group]; k != nil {
		return k.ecdhe
	}
	return nil
}

// prepareHello is the build stage, called from makeClientHello.
func (u *UConn) prepareHello(c *Conn, hello *clientHelloMsg, stock *keySharePrivateKeys) (*keySharePrivateKeys, error) {
	u.mu.Lock()
	u.started = true
	u.mu.Unlock()
	if u.golang {
		if hello.encryptedClientHello != nil && u.clientHelloHook != nil {
			return nil, ErrHookWithECH
		}
		// Expose crypto/tls's own key shares (the X25519 fallback share of a
		// hybrid reuses the hybrid's X25519 key).
		keys := map[CurveID]*keySharePrivateKeys{}
		if stock != nil && len(hello.keyShares) > 0 {
			keys[hello.keyShares[0].group] = stock
			for _, ks := range hello.keyShares[1:] {
				keys[ks.group] = &keySharePrivateKeys{ecdhe: stock.ecdhe}
			}
		}
		u.mu.Lock()
		u.hello, u.keys = hello, keys
		u.mu.Unlock()
		return nil, nil
	}
	if u.specErr != nil {
		return nil, u.specErr
	}
	if u.spec == nil {
		return nil, ErrNoSpec
	}
	if hello.encryptedClientHello != nil && u.clientHelloHook != nil {
		return nil, ErrHookWithECH
	}
	b := &helloBuild{c: c, config: c.config, hello: hello, spec: u.spec}
	keys, primary, err := b.build()
	if err != nil {
		return nil, err
	}
	r, err := newHelloRenderer(u.spec, b, c.config.rand())
	if err != nil {
		return nil, err
	}
	r.owner, r.owned = u, hello
	hello.uRender = r
	if _, err := hello.marshal(); err != nil { // surface encoding errors before any I/O
		return nil, err
	}
	u.mu.Lock()
	u.build, u.renderer, u.hello, u.keys = b, r, hello, keys
	u.mu.Unlock()
	return primary, nil
}

// uLoadSession is the session stage, called from clientHandshake in place of
// loadSession.
func (c *Conn) uLoadSession(hello *clientHelloMsg) (*SessionState, *tls13.EarlySecret, []byte, error) {
	u := c.uconn
	if u == nil {
		return c.loadSession(hello)
	}
	var session *SessionState
	var earlySecret *tls13.EarlySecret
	var binderKey []byte
	var err error
	if u.injected != nil && c.handshakes == 0 {
		session, earlySecret, binderKey, err = c.loadInjectedSession(hello, u.injected.session)
	} else {
		session, earlySecret, binderKey, err = c.loadSession(hello)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if u.golang {
		if u.clientHelloHook != nil && c.handshakes == 0 {
			if err := u.runHook(hello, session, binderKey); err != nil {
				return nil, nil, nil, err
			}
		}
		if raw, err := hello.marshal(); err == nil {
			u.setSnapshot(raw)
		}
		return session, earlySecret, binderKey, nil
	}
	b := u.build
	// loadSession enables tickets and PSK modes on its own; the spec decides.
	echInner := isECHInner(hello)
	hello.ticketSupported = b.hasTicket && !c.config.SessionTicketsDisabled && !echInner
	hello.pskModes = slices.Clone(b.pskModes)
	if session != nil {
		drop := false
		if session.version == VersionTLS13 && len(b.pskModes) == 0 {
			drop = true // no psk_key_exchange_modes in the fingerprint: cannot offer a PSK
		}
		if session.version != VersionTLS13 && !hello.ticketSupported && !echInner {
			drop = true // no session_ticket in the fingerprint
		}
		if drop {
			hello.pskIdentities, hello.pskBinders, hello.sessionTicket = nil, nil, nil
			session, earlySecret, binderKey = nil, nil, nil
		}
	}
	if u.clientHelloHook != nil && c.handshakes == 0 {
		if err := u.runHook(hello, session, binderKey); err != nil {
			return nil, nil, nil, err
		}
	}
	return session, earlySecret, binderKey, nil
}

// runHook gives the hook the final ClientHello and enforces that only Random
// and SessionID changed, recomputing PSK binders over the new bytes.
func (u *UConn) runHook(hello *clientHelloMsg, session *SessionState, binderKey []byte) error {
	raw, err := hello.marshal()
	if err != nil {
		return err
	}
	sidLen := int(raw[38])
	orig := raw
	nb := bindersLength(hello)
	if nb > 0 {
		// Binders are recomputed after the hook, so they cannot be covered by
		// anything the hook computes: present them zeroed.
		clear(raw[len(raw)-nb+2:])
	}
	ctx := &ClientHelloContext{Raw: raw, Random: raw[6:38], SessionID: raw[39 : 39+sidLen], PSK: nb > 0, keys: u.keys}
	if err := u.clientHelloHook(ctx); err != nil {
		return err
	}
	if len(ctx.Raw) != len(orig) || &ctx.Raw[0] != &orig[0] || len(ctx.Random) != 32 || len(ctx.SessionID) != sidLen ||
		&ctx.Random[0] != &orig[6] || (sidLen > 0 && &ctx.SessionID[0] != &orig[39]) {
		return errors.New("utls: ClientHello hook must modify Random/SessionID in place, not replace the slices")
	}
	hello.random = slices.Clone(orig[6:38])
	hello.sessionId = slices.Clone(orig[39 : 39+sidLen])
	if len(hello.pskIdentities) > 0 {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		if suite == nil {
			return errors.New("utls: internal error: PSK without a TLS 1.3 suite")
		}
		if err := computeAndUpdatePSK(hello, binderKey, suite.hash.New(), suite.finishedHash); err != nil {
			return err
		}
	}
	re, err := hello.marshal()
	if err != nil {
		return err
	}
	n := len(re) - bindersLength(hello)
	if len(re) != len(orig) || !bytes.Equal(re[:n], orig[:n]) {
		return errors.New("utls: ClientHello hook modified bytes other than Random and SessionID")
	}
	return nil
}

func bindersLength(m *clientHelloMsg) int {
	if len(m.pskBinders) == 0 {
		return 0
	}
	n := 2
	for _, b := range m.pskBinders {
		n += 1 + len(b)
	}
	return n
}

// loadInjectedSession is loadSession for a session supplied by SetSession: no
// cache lookup and no certificate re-verification (the caller vouches for it).
func (c *Conn) loadInjectedSession(hello *clientHelloMsg, session *SessionState) (*SessionState, *tls13.EarlySecret, []byte, error) {
	if c.config.SessionTicketsDisabled {
		return nil, nil, nil, errors.New("utls: SetSession used with Config.SessionTicketsDisabled")
	}
	if c.config.ClientSessionCache == nil {
		// crypto/tls clears the cache entry on failure; give it somewhere to go.
		c.config.ClientSessionCache = nopSessionCache{}
	}
	if !slices.Contains(hello.supportedVersions, session.version) {
		return nil, nil, nil, fmt.Errorf("utls: injected session version %#04x is not offered", session.version)
	}
	echInner := isECHInner(hello)
	if session.version != VersionTLS13 {
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return nil, nil, nil, fmt.Errorf("utls: injected session cipher suite %#04x is not offered", session.cipherSuite)
		}
		if echInner {
			return nil, nil, nil, errors.New("utls: a TLS 1.2 session cannot be resumed with ECH")
		}
		hello.sessionTicket = slices.Clone(session.ticket)
		return session, nil, nil, nil
	}
	suite := cipherSuiteTLS13ByID(session.cipherSuite)
	if suite == nil {
		return nil, nil, nil, fmt.Errorf("utls: injected session has unknown TLS 1.3 suite %#04x", session.cipherSuite)
	}
	ok := false
	for _, id := range hello.cipherSuites {
		if s := cipherSuiteTLS13ByID(id); s != nil && s.hash == suite.hash {
			ok = true
		}
	}
	if !ok {
		return nil, nil, nil, errors.New("utls: no offered TLS 1.3 suite matches the injected session's hash")
	}
	if len(session.ticket) == 0 {
		return nil, nil, nil, errors.New("utls: injected TLS 1.3 session has no ticket (PSK identity)")
	}
	ticketAge := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))
	hello.pskIdentities = []pskIdentity{{
		label:               slices.Clone(session.ticket),
		obfuscatedTicketAge: uint32(ticketAge/time.Millisecond) + session.ageAdd,
	}}
	hello.pskBinders = [][]byte{make([]byte, suite.hash.Size())}
	earlySecret := tls13.NewEarlySecret(suite.hash.New, session.secret)
	binderKey := earlySecret.ResumptionBinderKey()
	if err := computeAndUpdatePSK(hello, binderKey, suite.hash.New(), suite.finishedHash); err != nil {
		return nil, nil, nil, err
	}
	return session, earlySecret, binderKey, nil
}

type nopSessionCache struct{}

func (nopSessionCache) Get(string) (*ClientSessionState, bool) { return nil, false }
func (nopSessionCache) Put(string, *ClientSessionState)        {}

// NewSessionState builds a resumable session for SetSession: a TLS 1.2 session
// (secret = master secret, ticket = session ticket) or a TLS 1.3 session
// (secret = resumption PSK, ticket = PSK identity).
func NewSessionState(version, cipherSuite uint16, secret, ticket []byte, extMasterSecret bool, createdAt time.Time, ageAdd uint32, lifetime time.Duration) (*ClientSessionState, error) {
	switch version {
	case VersionTLS12, VersionTLS11, VersionTLS10:
		if cipherSuiteByID(cipherSuite) == nil {
			return nil, fmt.Errorf("utls: unknown TLS 1.2 cipher suite %#04x", cipherSuite)
		}
		if len(secret) != masterSecretLength {
			return nil, errors.New("utls: TLS 1.2 master secret must be 48 bytes")
		}
	case VersionTLS13:
		s := cipherSuiteTLS13ByID(cipherSuite)
		if s == nil {
			return nil, fmt.Errorf("utls: unknown TLS 1.3 cipher suite %#04x", cipherSuite)
		}
		if len(secret) != s.hash.Size() {
			return nil, errors.New("utls: TLS 1.3 PSK length must equal the suite hash size")
		}
	default:
		return nil, fmt.Errorf("utls: unsupported version %#04x", version)
	}
	if len(ticket) == 0 || len(ticket) > 0xffff {
		return nil, errors.New("utls: invalid ticket length")
	}
	if lifetime <= 0 {
		lifetime = 7 * 24 * time.Hour
	}
	st := &SessionState{
		version:         version,
		isClient:        true,
		cipherSuite:     cipherSuite,
		createdAt:       uint64(createdAt.Unix()),
		secret:          slices.Clone(secret),
		extMasterSecret: extMasterSecret,
		ageAdd:          ageAdd,
		useBy:           uint64(createdAt.Add(lifetime).Unix()),
		ticket:          slices.Clone(ticket),
	}
	return &ClientSessionState{session: st}, nil
}

// keyShareKeyForGroup returns the private key generated for group, so the
// handshake completes whichever offered group the server selects.
func (u *UConn) keyShareKeyForGroup(group CurveID) *keySharePrivateKeys {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.keys[group]
}

func (u *UConn) setServerHello(raw []byte, share keyShare) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.serverHelloRaw = slices.Clone(raw)
	if share.group != 0 {
		u.serverKeyShare = keyShare{share.group, slices.Clone(share.data)}
	}
}

// uMaxOfferedVersion is the highest version actually offered, for the RFC 8446
// downgrade-canary check (the spec may offer less than the Config allows).
func (c *Conn) uMaxOfferedVersion(configMax uint16) uint16 {
	u := c.uconn
	if u == nil || u.golang || u.hello == nil || len(u.hello.supportedVersions) == 0 {
		return configMax
	}
	return min(configMax, slices.Max(u.hello.supportedVersions))
}
