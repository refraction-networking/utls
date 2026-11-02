// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/ecdh"
	"errors"
	"net"
)

// UConn is a crypto/tls *Conn whose ClientHello is rendered from a
// ClientHelloSpec. It is created by the module's root package, never by
// downstream directly. The root package wraps it in the public utls.UConn.
type UConn struct {
	*Conn

	spec *ClientHelloSpec

	// clientHelloHook, if set, runs after the ClientHello bytes are rendered
	// but before they are sent, and may mutate them in place (e.g. to write an
	// authenticator into session_id). See ClientHelloContext.
	clientHelloHook func(*ClientHelloContext) error

	// built guards against rebuilding.
	built bool

	// ephemeralKeys holds the private half of every generated key share,
	// keyed by group, so the handshake completes whichever group the server
	// picks and so a hook/verifier can derive shared secrets (e.g. REALITY).
	ephemeralKeys map[CurveID]*keySharePrivateKeys

	// Populated during the handshake for post-hoc verification (REALITY/JLS):
	serverHelloRaw     []byte
	serverKeyShare     keyShare
	peerCertificatesCB func() []byte
}

// NewUConn wraps an existing net.Conn as a uTLS client using spec.
func NewUConn(conn net.Conn, config *Config, spec *ClientHelloSpec) *UConn {
	u := &UConn{
		Conn:          Client(conn, config),
		spec:          spec,
		ephemeralKeys: map[CurveID]*keySharePrivateKeys{},
	}
	u.Conn.uconn = u
	return u
}

// SetClientHelloHook installs a hook invoked on the rendered ClientHello.
func (u *UConn) SetClientHelloHook(h func(*ClientHelloContext) error) { u.clientHelloHook = h }

// SetSpec sets the ClientHelloSpec to render. It must be called before the
// handshake. Used by the public ApplyPreset flow (HelloCustom).
func (u *UConn) SetSpec(s *ClientHelloSpec) { u.spec = s }

// Spec returns the attached ClientHelloSpec, or nil.
func (u *UConn) Spec() *ClientHelloSpec { return u.spec }

// RenderClientHelloForTest renders the spec's ClientHello with the given random
// and session_id and returns the raw bytes, without performing a handshake. It
// exists so the public package and its tests can inspect rendered bytes.
func (u *UConn) RenderClientHelloForTest(random, sessionID []byte) ([]byte, error) {
	hello := &clientHelloMsg{random: random, sessionId: sessionID}
	if u.Conn != nil && u.Conn.config != nil {
		hello.serverName = hostnameInSNI(u.Conn.config.ServerName)
	}
	if _, err := u.buildClientHello(hello); err != nil {
		return nil, err
	}
	return hello.original, nil
}

// Handshake runs the TLS handshake, sending the spec-defined ClientHello.
func (u *UConn) Handshake() error { return u.HandshakeContext(context.Background()) }

// HandshakeContext runs the handshake with the given context.
func (u *UConn) HandshakeContext(ctx context.Context) error {
	return u.Conn.HandshakeContext(ctx)
}

// EphemeralKey returns the ECDHE private key offered for group, or nil. For a
// hybrid group it returns the classical (ECDHE) half, which is what REALITY and
// similar schemes use.
func (u *UConn) EphemeralKey(group CurveID) *ecdh.PrivateKey {
	if k := u.ephemeralKeys[group]; k != nil {
		return k.ecdhe
	}
	return nil
}

// ServerKeyShareGroup and ServerKeyShareData expose the server's selected
// key_share once the handshake has processed the ServerHello, for schemes that
// derive a shared secret from the server's ephemeral public key.
func (u *UConn) ServerKeyShareGroup() CurveID { return u.serverKeyShare.group }
func (u *UConn) ServerKeyShareData() []byte   { return u.serverKeyShare.data }

// ServerHelloRaw returns the raw ServerHello bytes once received.
func (u *UConn) ServerHelloRaw() []byte { return u.serverHelloRaw }

// ClientHelloContext is passed to a ClientHello hook. Random and SessionID are
// sub-slices of Raw, so writing through them edits the bytes that go on the
// wire. The hook may also overwrite arbitrary bytes of Raw directly.
type ClientHelloContext struct {
	// Raw is the full ClientHello handshake message (4-byte header + body).
	Raw []byte
	// Random aliases the 32-byte client_random inside Raw.
	Random []byte
	// SessionID aliases the legacy_session_id inside Raw (often 32 bytes).
	SessionID []byte

	keys map[CurveID]*keySharePrivateKeys
}

// EphemeralKey returns the ECDHE private key for group (classical half of a
// hybrid), or nil.
func (c *ClientHelloContext) EphemeralKey(group CurveID) *ecdh.PrivateKey {
	if k := c.keys[group]; k != nil {
		return k.ecdhe
	}
	return nil
}

// buildClientHello is the body of the makeClientHello [uTLS] hook. It takes the
// clientHelloMsg crypto/tls just built, rewrites it from the spec, renders the
// wire bytes into hello.original, runs the hook, and returns the key material
// crypto/tls should use.
func (u *UConn) buildClientHello(hello *clientHelloMsg) (*keySharePrivateKeys, error) {
	if u.spec == nil {
		return nil, errNoSpec
	}
	if u.built {
		return nil, errHelloAlreadySet
	}

	r := newHelloRenderer(u, hello, u.spec)

	// Logical cipher suites and compression, ungreased, for the state machine.
	hello.cipherSuites = hello.cipherSuites[:0]
	for _, cs := range u.spec.CipherSuites {
		if !isGREASEUint16(cs) && cs != GREASEPlaceholder {
			hello.cipherSuites = append(hello.cipherSuites, cs)
		}
	}
	hello.compressionMethods = u.spec.CompressionMethods

	// Let each extension populate the logical hello (versions, groups, sig
	// algs, ALPN, SNI, key shares, ...).
	for _, ext := range u.spec.Extensions {
		if err := ext.writeToHello(r); err != nil {
			return nil, err
		}
	}

	// Derive the max offered version for legacy_version.
	hello.vers = maxSupportedVersion(hello.supportedVersions)

	// Render the exact wire bytes.
	raw, err := r.render()
	if err != nil {
		return nil, err
	}
	hello.original = raw

	// Expose generated key material.
	u.ephemeralKeys = r.extraKeyShareKeys

	// Run the ClientHello hook, letting the caller rewrite Random/SessionID.
	if u.clientHelloHook != nil {
		sidLen := int(raw[38])
		hc := &ClientHelloContext{
			Raw:       raw,
			Random:    raw[6:38],
			SessionID: raw[39 : 39+sidLen],
			keys:      r.extraKeyShareKeys,
		}
		if err := u.clientHelloHook(hc); err != nil {
			return nil, err
		}
		// The hook edits Raw in place; keep logical random/session_id in sync.
		hello.random = raw[6:38]
		hello.sessionId = raw[39 : 39+sidLen]
	}

	u.built = true
	return r.keyShareKeys, nil
}

func maxSupportedVersion(vers []uint16) uint16 {
	max := uint16(0)
	for _, v := range vers {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		max = VersionTLS12
	}
	return max
}

// keyShareKeyForGroup returns the stored private keys for the group the server
// selected, used by the establishHandshakeKeys [uTLS] hook so a fallback key
// share can complete the handshake.
func (u *UConn) keyShareKeyForGroup(group CurveID) *keySharePrivateKeys {
	return u.ephemeralKeys[group]
}

var errUConnHandshake = errors.New("utls: handshake error")
