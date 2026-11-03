// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// Transport is an http.RoundTripper that makes HTTPS requests with a uTLS
// fingerprint, speaking HTTP/2 or HTTP/1.1 according to the ALPN protocol the
// server selects. It is safe for concurrent use and pools connections:
// HTTP/2 connections in an x/net/http2 Transport, HTTP/1.1 connections in a
// net/http Transport. Plain http:// requests use net/http without TLS.
//
// Routing: the first request to a host dials one uTLS connection and caches
// the negotiated protocol for that host; the connection is handed to the
// matching pool. If a later pooled dial negotiates a different protocol the
// dial fails (nothing has been sent), the cache is updated and the request is
// routed again. responses carry resp.TLS from the uTLS connection.
type Transport struct {
	// ClientHelloID selects the fingerprint (default HelloChrome_Auto).
	ClientHelloID ClientHelloID
	// TLSConfig is the base TLS configuration; ServerName defaults to the
	// request host. NextProtos, if set, overrides the fingerprint's ALPN list
	// and must contain only "h2" and/or "http/1.1".
	TLSConfig *tls.Config
	// ClientHelloHook, if set, is installed on every connection.
	ClientHelloHook func(*ClientHelloContext) error
	// DialContext dials the underlying TCP connection (e.g. through a custom
	// proxy). Nil uses a net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Proxy returns the proxy for a request (http://, https:// via CONNECT, or
	// socks5://), as net/http.Transport.Proxy; nil means no proxy.
	Proxy func(*http.Request) (*url.URL, error)
	// IdleConnTimeout closes idle connections after this long (default 90s).
	IdleConnTimeout time.Duration
	// MaxIdleConnsPerHost for HTTP/1.1 (default 2, as net/http).
	MaxIdleConnsPerHost int
	// ResponseHeaderTimeout, if non-zero, bounds the wait for response headers.
	ResponseHeaderTimeout time.Duration

	once  sync.Once
	h1    *http.Transport
	h2    *http2.Transport
	mu    sync.Mutex
	proto map[string]string       // host:port -> "h2" | "http/1.1"
	ready map[string][]pendingConn // probed connections waiting for their pool
}

type pendingConn struct {
	c  *UConn
	at time.Time
}

const pendingTTL = 30 * time.Second

var errWrongProto = errors.New("utls: connection negotiated a different protocol")

func (t *Transport) init() {
	t.once.Do(func() {
		t.proto = map[string]string{}
		t.ready = map[string][]pendingConn{}
		idle := t.IdleConnTimeout
		if idle == 0 {
			idle = 90 * time.Second
		}
		t.h1 = &http.Transport{
			Proxy:                 nil, // proxying is done in dialTLS / dialPlain
			DialContext:           t.dialPlainForH1,
			DialTLSContext:        func(ctx context.Context, network, addr string) (net.Conn, error) { return t.dialFor(ctx, addr, "http/1.1") },
			ForceAttemptHTTP2:     false,
			IdleConnTimeout:       idle,
			MaxIdleConnsPerHost:   t.MaxIdleConnsPerHost,
			ResponseHeaderTimeout: t.ResponseHeaderTimeout,
		}
		t.h2 = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return t.dialFor(ctx, addr, "h2")
			},
			IdleConnTimeout: idle,
			ReadIdleTimeout: idle,
		}
	})
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.init()
	switch req.URL.Scheme {
	case "http":
		return t.h1.RoundTrip(req)
	case "https":
	default:
		return nil, fmt.Errorf("utls: unsupported URL scheme %q", req.URL.Scheme)
	}
	addr := canonicalAddr(req.URL)
	for attempt := 0; attempt < 3; attempt++ {
		p, err := t.protocolFor(req.Context(), req, addr)
		if err != nil {
			return nil, err
		}
		var resp *http.Response
		if p == "h2" {
			resp, err = t.h2.RoundTrip(req)
		} else {
			resp, err = t.h1.RoundTrip(req)
		}
		if errors.Is(err, errWrongProto) {
			continue // the dial failed before the request was written: safe to re-route
		}
		return resp, err
	}
	return nil, errors.New("utls: server keeps changing its negotiated protocol")
}

// protocolFor returns the cached protocol for addr, probing it if unknown.
func (t *Transport) protocolFor(ctx context.Context, req *http.Request, addr string) (string, error) {
	t.mu.Lock()
	p, ok := t.proto[addr]
	t.mu.Unlock()
	if ok {
		return p, nil
	}
	c, err := t.dialTLS(ctx, req, addr)
	if err != nil {
		return "", err
	}
	p = negotiated(c)
	t.mu.Lock()
	t.proto[addr] = p
	t.ready[addr] = append(t.ready[addr], pendingConn{c, time.Now()})
	t.mu.Unlock()
	return p, nil
}

func negotiated(c *UConn) string {
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		return "h2"
	}
	return "http/1.1"
}

// dialFor is the pools' dial function: it hands out a probed connection or
// dials a new one, and fails (without sending anything) if the negotiated
// protocol does not match the pool.
func (t *Transport) dialFor(ctx context.Context, addr, want string) (net.Conn, error) {
	t.mu.Lock()
	var c *UConn
	q := t.ready[addr]
	for len(q) > 0 {
		pc := q[0]
		q = q[1:]
		if time.Since(pc.at) < pendingTTL && negotiated(pc.c) == want {
			c = pc.c
			break
		}
		pc.c.Close()
	}
	t.ready[addr] = q
	t.mu.Unlock()
	if c != nil {
		return c, nil
	}
	req, _ := ctx.Value(requestKey{}).(*http.Request)
	c, err := t.dialTLS(ctx, req, addr)
	if err != nil {
		return nil, err
	}
	if got := negotiated(c); got != want {
		t.mu.Lock()
		t.proto[addr] = got
		t.ready[addr] = append(t.ready[addr], pendingConn{c, time.Now()})
		t.mu.Unlock()
		return nil, errWrongProto
	}
	return c, nil
}

type requestKey struct{}

// dialTLS dials addr (through the proxy if any) and completes a uTLS handshake.
func (t *Transport) dialTLS(ctx context.Context, req *http.Request, addr string) (*UConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	raw, err := t.dialRaw(ctx, req, addr)
	if err != nil {
		return nil, err
	}
	cfg := t.TLSConfig.Clone()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	for _, p := range cfg.NextProtos {
		if p != "h2" && p != "http/1.1" {
			raw.Close()
			return nil, fmt.Errorf("utls: Transport only speaks h2 and http/1.1, not ALPN %q", p)
		}
	}
	id := t.ClientHelloID
	if id.isZero() {
		id = HelloChrome_Auto
	}
	uc := UClient(raw, cfg, id)
	if t.ClientHelloHook != nil {
		if err := uc.SetClientHelloHook(t.ClientHelloHook); err != nil {
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

func (t *Transport) dialPlainForH1(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.dialRaw(ctx, nil, addr)
}

func (t *Transport) baseDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.DialContext != nil {
		return t.DialContext(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}
func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// dialRaw dials addr directly or through the configured proxy.
func (t *Transport) dialRaw(ctx context.Context, req *http.Request, addr string) (net.Conn, error) {
	var pu *url.URL
	if t.Proxy != nil {
		r := req
		if r == nil {
			r = &http.Request{URL: &url.URL{Scheme: "https", Host: addr}}
		}
		var err error
		if pu, err = t.Proxy(r); err != nil {
			return nil, err
		}
	}
	if pu == nil {
		return t.baseDial(ctx, "tcp", addr)
	}
	switch pu.Scheme {
	case "socks5", "socks5h":
		d, err := proxy.FromURL(pu, dialerFunc(t.baseDial))
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return d.Dial("tcp", addr)
	case "http", "https":
		return t.dialConnect(ctx, pu, addr)
	}
	return nil, fmt.Errorf("utls: unsupported proxy scheme %q", pu.Scheme)
}

// dialConnect opens an HTTP CONNECT tunnel to addr through proxy pu.
func (t *Transport) dialConnect(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	paddr := canonicalAddr(pu)
	c, err := t.baseDial(ctx, "tcp", paddr)
	if err != nil {
		return nil, err
	}
	if pu.Scheme == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: pu.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	creq := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u := pu.User; u != nil {
		pw, _ := u.Password()
		creq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if err := creq.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, creq)
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("utls: proxy CONNECT to %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		c.Close()
		return nil, errors.New("utls: proxy sent data before the TLS handshake")
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// CloseIdleConnections closes idle pooled connections and probed connections
// not yet used.
func (t *Transport) CloseIdleConnections() {
	t.init()
	t.h1.CloseIdleConnections()
	t.h2.CloseIdleConnections()
	t.mu.Lock()
	ready := t.ready
	t.ready = map[string][]pendingConn{}
	t.mu.Unlock()
	for _, q := range ready {
		for _, pc := range q {
			pc.c.Close()
		}
	}
}

func canonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

var _ http.RoundTripper = (*Transport)(nil)
