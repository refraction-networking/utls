// Copyright 2026 The uTLS Authors. All rights reserved.
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
// fingerprint. It implements net.Conn and the interface net/http uses to
// discover TLS state (ConnectionState + HandshakeContext).
//
// Lifecycle: configure (ApplyPreset, SetClientHelloHook, SetSession) before
// the handshake; after it starts, configuration methods return an error.
// Methods are safe to call concurrently with Read/Write after the handshake.
type UConn struct {
	u  *itls.UConn
	id ClientHelloID
}

// ClientHelloContext is passed to a ClientHello hook; see
// (*UConn).SetClientHelloHook.
type ClientHelloContext = itls.ClientHelloContext

// ErrNoSpec is returned by the handshake when the fingerprint has no spec
// (HelloCustom without ApplyPreset, or the zero ClientHelloID). uTLS never
// silently sends the Go fingerprint instead; use HelloGolang for that.
var ErrNoSpec = itls.ErrNoSpec

// ErrHookWithECH is returned when a ClientHello hook is combined with Encrypted
// Client Hello (the hook would see bytes that never go on the wire).
var ErrHookWithECH = itls.ErrHookWithECH

// UClient wraps conn as a uTLS client with fingerprint id. config may be nil
// (but crypto/tls rules still require ServerName or InsecureSkipVerify).
// config is copied; later changes to it do not affect the connection.
//
// An unusable id (zero value, or a spec factory that fails) is reported by the
// handshake, before anything is written to conn. HelloCustom requires
// ApplyPreset before the handshake. HelloGolang sends the stock crypto/tls
// ClientHello.
func UClient(conn net.Conn, config *tls.Config, id ClientHelloID) *UConn {
	spec, golang, err := id.resolve()
	if cerr := configError(config); cerr != nil {
		err = cerr
	}
	return &UConn{u: itls.NewUConn(conn, fromStdConfig(config), spec, golang, err), id: id}
}

// ClientHelloID returns the fingerprint the connection was created with.
func (c *UConn) ClientHelloID() ClientHelloID { return c.id }

// ApplyPreset sets the ClientHelloSpec to send (it is copied and validated).
// It must be called before the handshake.
func (c *UConn) ApplyPreset(spec *ClientHelloSpec) error {
	if spec == nil {
		return errors.New("utls: nil ClientHelloSpec")
	}
	return c.u.SetSpec(spec)
}

// SetClientHelloHook installs a hook that runs once, on the final first
// ClientHello, just before it is sent (after any session is loaded and PSK
// binders computed). The hook may overwrite ctx.Random and ctx.SessionID in
// place, e.g. to embed an authenticator computed over ctx.Raw with
// ctx.EphemeralKey; binders are then recomputed. Changing any other byte is an
// error. A hook error aborts the handshake before the hello is sent. A hook
// cannot be combined with ECH (ErrHookWithECH). It works with every
// fingerprint, including HelloGolang. It returns an error once the handshake
// has started.
func (c *UConn) SetClientHelloHook(h func(*ClientHelloContext) error) error {
	return c.u.SetClientHelloHook(h)
}

// FragmentOptions controls how the first ClientHello is written (TLS record
// and/or TCP-write splitting, e.g. inside the SNI host name). See
// (*UConn).SetFragmentation.
type FragmentOptions = itls.FragmentOptions

// SetFragmentation splits the first ClientHello across TLS records and/or
// separate writes as o describes. The handshake transcript is unchanged. It
// must be called before the handshake; invalid options are rejected here.
func (c *UConn) SetFragmentation(o FragmentOptions) error { return c.u.SetFragmentation(o) }

// SetSession makes the first handshake offer cs (from any crypto/tls
// ClientSessionCache, or built with NewClientSession) regardless of the
// Config's session cache. The session is trusted as given: its certificates
// are not re-verified, so use it only with sessions you obtained or forged
// yourself. It must be called before the handshake.
func (c *UConn) SetSession(cs *tls.ClientSessionState) error {
	if cs == nil {
		return errors.New("utls: nil session")
	}
	ics, err := stdToInternalSession(cs)
	if err != nil {
		return err
	}
	return c.u.SetSession(ics)
}

// SetSessionParams makes the first handshake offer a session described by raw
// parameters (an out-of-band or forged ticket / PSK, as Psiphon's obfuscated
// session tickets). Such sessions carry no certificates, so they cannot be
// represented as a *tls.ClientSessionState; this is the native path. It must
// be called before the handshake.
func (c *UConn) SetSessionParams(p ClientSessionParams) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	ics, err := itls.NewSessionState(p.Version, p.CipherSuite, p.Secret, p.Ticket, p.ExtendedMasterSecret, p.CreatedAt, p.AgeAdd, p.Lifetime)
	if err != nil {
		return err
	}
	return c.u.SetSession(ics)
}

// ErrExporterUnavailable is returned by ExportKeyingMaterial on a returned
// ConnectionState before the handshake completes (crypto/tls itself has no
// exporter then).
var ErrExporterUnavailable = itls.ErrExporterUnavailable

// Handshake runs the TLS handshake.
func (c *UConn) Handshake() error { return itls.StdError(c.u.HandshakeContext(context.Background())) }

// HandshakeContext runs the handshake. ctx is also what
// tls.CertificateRequestInfo.Context returns inside GetClientCertificate.
func (c *UConn) HandshakeContext(ctx context.Context) error {
	return itls.StdError(c.u.HandshakeContext(ctx))
}

// ConnectionState returns the standard crypto/tls.ConnectionState, including a
// working ExportKeyingMaterial.
func (c *UConn) ConnectionState() ConnectionState { return toStdConnectionState(c.u.ConnectionState()) }

// ExportKeyingMaterial returns keying material per RFC 5705 / RFC 8446 7.5,
// with the same restrictions as crypto/tls.
func (c *UConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	cs := c.u.ConnectionState()
	return cs.ExportKeyingMaterial(label, context, length)
}

// EphemeralKey returns the classical ECDH private key offered for group (for
// X25519MLKEM768, its X25519 half), or nil.
func (c *UConn) EphemeralKey(group CurveID) *ecdh.PrivateKey { return c.u.EphemeralKey(group) }

// ServerKeyShareGroup and ServerKeyShareData return the key share the server
// selected (TLS 1.3); available from certificate verification onwards.
func (c *UConn) ServerKeyShareGroup() CurveID { return c.u.ServerKeyShareGroup() }

// ServerKeyShareData: see ServerKeyShareGroup.
func (c *UConn) ServerKeyShareData() []byte { return c.u.ServerKeyShareData() }

// ServerHelloRaw returns the last ServerHello handshake message received.
func (c *UConn) ServerHelloRaw() []byte { return c.u.ServerHelloRaw() }

// ClientHelloRaw returns the last ClientHello handshake message sent (the
// retried one after HelloRetryRequest; the outer one with ECH).
func (c *UConn) ClientHelloRaw() []byte { return c.u.ClientHelloRaw() }

// NegotiatedApplicationSettings returns the server's ALPS settings and whether
// ALPS was negotiated.
func (c *UConn) NegotiatedApplicationSettings() ([]byte, bool) {
	return c.u.NegotiatedApplicationSettings()
}

// RecordLayerState is the TLS 1.3 record-layer state returned by HandOff.
type RecordLayerState = itls.RecordLayerState

// ErrHandedOff is returned by Read and Write after HandOff.
var ErrHandedOff = itls.ErrHandedOff

// HandOff detaches the record layer of a completed TLS 1.3 connection (keys,
// IVs, traffic secrets, sequence numbers, buffered plaintext and undecrypted
// input, and the transport) for kernel TLS, Vision-style raw splicing or a
// custom record layer. Afterwards Read and Write return ErrHandedOff and Close
// sends no close_notify. See RecordLayerState for the contract.
func (c *UConn) HandOff() (*RecordLayerState, error) { return c.u.HandOff() }

// NetConn returns the underlying connection. Writing to it bypasses TLS.
func (c *UConn) NetConn() net.Conn { return c.u.NetConn() }

// Read, Write, Close and the other net.Conn methods behave as crypto/tls.Conn.
func (c *UConn) Read(b []byte) (int, error) {
	n, err := c.u.Read(b)
	return n, itls.StdError(err)
}
func (c *UConn) Write(b []byte) (int, error) {
	n, err := c.u.Write(b)
	return n, itls.StdError(err)
}
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

// DialContext is Dial with a context governing the dial and the handshake.
func DialContext(ctx context.Context, network, addr string, config *tls.Config, id ClientHelloID) (*UConn, error) {
	return (&Dialer{Config: config, ClientHelloID: id}).dialUConn(ctx, network, addr)
}

// Dialer dials uTLS connections over a custom transport (a proxy, a
// fragmenting conn, ...). The zero value dials TCP with HelloChrome_Auto.
type Dialer struct {
	// NetDialer dials the underlying connection; nil uses a zero net.Dialer.
	NetDialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	Config        *tls.Config
	ClientHelloID ClientHelloID
	// ClientHelloHook, if set, is installed on every connection.
	ClientHelloHook func(*ClientHelloContext) error
}

// DialContext dials and completes the handshake before returning.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialUConn(ctx, network, addr)
}

func (d *Dialer) dialUConn(ctx context.Context, network, addr string) (*UConn, error) {
	nd := d.NetDialer
	if nd == nil {
		nd = &net.Dialer{}
	}
	id := d.ClientHelloID
	if id.isZero() {
		id = HelloChrome_Auto
	}
	config := fillServerName(d.Config, addr)
	raw, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uc := UClient(raw, config, id)
	if d.ClientHelloHook != nil {
		if err := uc.SetClientHelloHook(d.ClientHelloHook); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return uc, nil
}

// fillServerName defaults ServerName to addr's host, as tls.Dial does.
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
