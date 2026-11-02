// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// Transport is an http.RoundTripper that makes HTTPS requests with a uTLS
// fingerprint, choosing HTTP/2 or HTTP/1.1 from the ALPN the server negotiates.
//
// Nearly every downstream project re-implemented this (and some forked net/http
// for it) because the standard http.Transport will not speak HTTP/2 over a
// connection it did not create itself. Transport does the dispatch for you and
// needs no forked net/http: it returns a uTLS connection whose ConnectionState
// is the standard type, then hands an h2 connection to x/net/http2 or an h1
// connection to net/http.
//
// This reference implementation opens one connection per request (no pooling),
// which is simple and correct; wrap it if you need pooling.
type Transport struct {
	// ClientHelloID selects the fingerprint. Defaults to HelloChrome_Auto.
	ClientHelloID ClientHelloID
	// Config is the base TLS config (ServerName is filled per request).
	Config *tls.Config
	// Dialer dials the underlying TCP connection. Defaults to a zero net.Dialer.
	Dialer *net.Dialer
	// ClientHelloHook, if set, is installed on every connection.
	ClientHelloHook func(*ClientHelloContext) error
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("utls: Transport only supports https")
	}
	host := req.URL.Hostname()
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(host, "443")
	}

	id := t.ClientHelloID
	if !id.IsSet() && id.Client != "Custom" {
		id = HelloChrome_Auto
	}

	cfg := t.Config.Clone()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}

	dialer := t.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	raw, err := dialer.DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	uc := UClient(raw, cfg, id)
	if t.ClientHelloHook != nil {
		uc.SetClientHelloHook(t.ClientHelloHook)
	}
	if err := uc.HandshakeContext(req.Context()); err != nil {
		raw.Close()
		return nil, err
	}

	switch uc.ConnectionState().NegotiatedProtocol {
	case "h2":
		h2 := &http2.Transport{}
		cc, err := h2.NewClientConn(uc)
		if err != nil {
			uc.Close()
			return nil, err
		}
		return cc.RoundTrip(req)
	default:
		// HTTP/1.1 over the established connection, one shot.
		ht := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uc, nil
			},
			DisableKeepAlives: true,
		}
		return ht.RoundTrip(req)
	}
}

var _ http.RoundTripper = (*Transport)(nil)
