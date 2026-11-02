// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"errors"
	"net"
	"time"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// UConn is a TLS client connection whose ClientHello is rendered from a
// fingerprint. It satisfies net.Conn and the implicit interface net/http uses
// to discover TLS state (ConnectionState + HandshakeContext), so it drops into
// http.Transport.DialTLSContext and x/net/http2 without a wrapper.
type UConn struct {
	u      *itls.UConn
	config *tls.Config
}

// ClientHelloContext is passed to a ClientHello hook. Random and SessionID
// alias bytes inside Raw, so writing through them changes what goes on the
// wire. EphemeralKey exposes the private half of an offered key share (the
// classical half of a hybrid), which authenticated-transport schemes such as
// REALITY and ShadowTLS use to derive a secret bound to this exact hello.
type ClientHelloContext = itls.ClientHelloContext

// UClient wraps conn as a uTLS client that will send the ClientHello described
// by id. For HelloCustom, call ApplyPreset with your own spec before the
// handshake. config may be nil.
func UClient(conn net.Conn, config *tls.Config, id ClientHelloID) *UConn {
	if config == nil {
		config = &tls.Config{}
	}
	var spec *ClientHelloSpec
	if id.specFactory != nil {
		if s, err := id.specFactory(); err == nil {
			spec = s
		}
	}
	uc := newInternalUConn(conn, config, spec)
	return &UConn{u: uc, config: config}
}

func newInternalUConn(conn net.Conn, config *tls.Config, spec *ClientHelloSpec) *itls.UConn {
	// newUConn is unexported in internal/tls; NewUConn is its exported form.
	return itls.NewUConn(conn, fromStdConfig(config), spec)
}

// ApplyPreset sets (or replaces) the ClientHelloSpec before the handshake.
func (c *UConn) ApplyPreset(spec *ClientHelloSpec) error {
	if spec == nil {
		return errors.New("utls: nil ClientHelloSpec")
	}
	c.u.SetSpec(spec)
	return nil
}

// SetClientHelloHook installs a hook run on the rendered ClientHello just
// before it is sent. The hook may rewrite Random/SessionID in place.
func (c *UConn) SetClientHelloHook(h func(*ClientHelloContext) error) { c.u.SetClientHelloHook(h) }

// Handshake performs the TLS handshake.
func (c *UConn) Handshake() error { return c.u.HandshakeContext(context.Background()) }

// HandshakeContext performs the TLS handshake with a context.
func (c *UConn) HandshakeContext(ctx context.Context) error { return c.u.HandshakeContext(ctx) }

// ConnectionState returns the standard crypto/tls.ConnectionState.
func (c *UConn) ConnectionState() ConnectionState { return toStdConnectionState(c.u.ConnectionState()) }

// EphemeralKey returns the offered ECDHE private key for group, or nil.
func (c *UConn) EphemeralKey(group CurveID) *ecdh.PrivateKey {
	return c.u.EphemeralKey(itls.CurveID(group))
}

// ServerKeyShareGroup and ServerKeyShareData expose the key share the server
// selected, available once the ServerHello has been processed.
func (c *UConn) ServerKeyShareGroup() CurveID { return CurveID(c.u.ServerKeyShareGroup()) }
func (c *UConn) ServerKeyShareData() []byte   { return c.u.ServerKeyShareData() }

// ServerHelloRaw returns the raw ServerHello bytes once received.
func (c *UConn) ServerHelloRaw() []byte { return c.u.ServerHelloRaw() }

// NetConn returns the underlying connection.
func (c *UConn) NetConn() net.Conn { return c.u.NetConn() }

// net.Conn passthrough.
func (c *UConn) Read(b []byte) (int, error)         { return c.u.Read(b) }
func (c *UConn) Write(b []byte) (int, error)        { return c.u.Write(b) }
func (c *UConn) Close() error                       { return c.u.Close() }
func (c *UConn) CloseWrite() error                  { return c.u.CloseWrite() }
func (c *UConn) LocalAddr() net.Addr                { return c.u.LocalAddr() }
func (c *UConn) RemoteAddr() net.Addr               { return c.u.RemoteAddr() }
func (c *UConn) SetDeadline(t time.Time) error      { return c.u.SetDeadline(t) }
func (c *UConn) SetReadDeadline(t time.Time) error  { return c.u.SetReadDeadline(t) }
func (c *UConn) SetWriteDeadline(t time.Time) error { return c.u.SetWriteDeadline(t) }

var _ net.Conn = (*UConn)(nil)

// Dial connects to addr and performs a uTLS handshake using fingerprint id.
func Dial(network, addr string, config *tls.Config, id ClientHelloID) (*UConn, error) {
	return DialContext(context.Background(), network, addr, config, id)
}

// DialContext is Dial with a context governing both the TCP dial and the
// handshake.
func DialContext(ctx context.Context, network, addr string, config *tls.Config, id ClientHelloID) (*UConn, error) {
	config = fillServerName(config, addr)
	raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uc := UClient(raw, config, id)
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return uc, nil
}

// fillServerName returns a config whose ServerName defaults to addr's host when
// unset (and not an IP), matching the standard tls.Dial convenience.
func fillServerName(config *tls.Config, addr string) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	}
	if config.ServerName != "" {
		return config
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return config
	}
	c := config.Clone()
	c.ServerName = host
	return c
}
