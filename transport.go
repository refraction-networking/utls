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
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Transport is an http.RoundTripper that makes HTTPS requests with a uTLS
// fingerprint. It is safe for concurrent use; as with net/http.Transport, its
// fields must not be changed after the first request.
//
// It delegates everything but the TLS handshake to net/http: for each proxy
// route (the result of Proxy for the request) it keeps a net/http.Transport
// whose DialTLSContext opens the route (direct, HTTP/HTTPS CONNECT or SOCKS5)
// and performs the uTLS handshake. net/http (Go 1.27.3+) speaks HTTP/2 natively
// over any connection whose ConnectionState reports "h2", so h1/h2 selection,
// connection pooling, request retries and body rewinding (GetBody), timeouts,
// cancellation and resp.TLS are all standard net/http behavior. Connections
// are never shared between proxy routes (or proxy credentials).
//
// Plain http:// requests use a standard net/http.Transport with the same
// Proxy (standard forward-proxy semantics).
type Transport struct {
	// ClientHelloID selects the fingerprint (default HelloChrome_Auto).
	ClientHelloID ClientHelloID
	// TLSConfig is the base TLS configuration; ServerName defaults to the
	// request host. NextProtos, if set, overrides the fingerprint's ALPN list
	// and may contain only "h2" and "http/1.1".
	TLSConfig *tls.Config
	// ClientHelloHook, if set, is installed on every connection.
	ClientHelloHook func(*ClientHelloContext) error
	// Fragmentation, if set, is applied to every connection's first
	// ClientHello (see FragmentOptions).
	Fragmentation *FragmentOptions
	// DialContext dials TCP connections (to the server or the proxy). Nil uses
	// a net.Dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Proxy selects a proxy per request (http://, https://, socks5://,
	// socks5h://), as net/http.Transport.Proxy; nil means direct.
	Proxy func(*http.Request) (*url.URL, error)
	// Connection pool and timeout settings, as in net/http.Transport.
	IdleConnTimeout       time.Duration // default 90s
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	ResponseHeaderTimeout time.Duration
	TLSHandshakeTimeout   time.Duration // default 10s; bounds proxy setup + uTLS handshake
	// MaxProxyRoutes bounds how many proxy routes (distinct Proxy results,
	// including credentials) keep a connection pool; default 64. The least
	// recently used route without in-flight requests is evicted beyond it, and
	// any route idle for IdleConnTimeout is dropped. Eviction closes the
	// route's idle connections and lets in-flight requests finish (their
	// connections are then closed instead of pooled).
	MaxProxyRoutes int

	once   sync.Once
	mu     sync.Mutex
	routes map[string]*routeEntry // proxy route ("" = direct) -> pool
	plain  *http.Transport
}

// routeEntry is one proxy route's pool. refs counts requests whose response
// is not finished; a route is never evicted while refs > 0.
type routeEntry struct {
	rt       *http.Transport
	refs     int
	lastUsed time.Time
}

func (t *Transport) init() {
	t.once.Do(func() {
		t.routes = map[string]*routeEntry{}
		t.plain = t.newStd(nil)
		t.plain.Proxy = t.Proxy
		t.plain.DialContext = t.baseDial
	})
}

func (t *Transport) newStd(dialTLS func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	idle := t.IdleConnTimeout
	if idle == 0 {
		idle = 90 * time.Second
	}
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	return &http.Transport{
		DialTLSContext:        dialTLS,
		ForceAttemptHTTP2:     true,
		Protocols:             p,
		IdleConnTimeout:       idle,
		MaxIdleConns:          t.MaxIdleConns,
		MaxIdleConnsPerHost:   t.MaxIdleConnsPerHost,
		MaxConnsPerHost:       t.MaxConnsPerHost,
		ResponseHeaderTimeout: t.ResponseHeaderTimeout,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.init()
	switch req.URL.Scheme {
	case "http":
		return t.plain.RoundTrip(req)
	case "https":
	default:
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("utls: unsupported URL scheme %q", req.URL.Scheme)
	}
	var pu *url.URL
	if t.Proxy != nil {
		var err error
		if pu, err = t.Proxy(req); err != nil {
			if req.Body != nil {
				req.Body.Close()
			}
			return nil, err
		}
	}
	e := t.acquire(pu)
	resp, err := e.rt.RoundTrip(req)
	if err != nil {
		t.release(e)
		return nil, err
	}
	resp.Body = &routeBody{ReadCloser: resp.Body, done: func() { t.release(e) }}
	return resp, nil
}

// routeBody releases its route when the response body is finished (EOF, read
// error or Close), whichever happens first.
type routeBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *routeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.done)
	}
	return n, err
}

func (b *routeBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}

func (t *Transport) idleTimeout() time.Duration {
	if t.IdleConnTimeout > 0 {
		return t.IdleConnTimeout
	}
	return 90 * time.Second
}

// acquire returns the route for pu with a reference held, creating it on
// first use and evicting stale or excess unreferenced routes.
func (t *Transport) acquire(pu *url.URL) *routeEntry {
	key := ""
	if pu != nil {
		key = pu.String()
	}
	now := time.Now()
	var closeNow []*http.Transport
	t.mu.Lock()
	e := t.routes[key]
	if e == nil {
		var proxyURL *url.URL
		if pu != nil {
			c := *pu
			proxyURL = &c
		}
		e = &routeEntry{rt: t.newStd(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.dialTLS(ctx, proxyURL, addr)
		})}
		t.routes[key] = e
	}
	e.refs++
	e.lastUsed = now
	// Expire idle routes, then enforce the bound (LRU among unreferenced).
	for k, r := range t.routes {
		if r.refs == 0 && now.Sub(r.lastUsed) > t.idleTimeout() {
			closeNow = append(closeNow, t.evictLocked(k, r))
		}
	}
	closeNow = append(closeNow, t.evictExcessLocked()...)
	t.mu.Unlock()
	for _, rt := range closeNow {
		rt.CloseIdleConnections()
	}
	return e
}

// evictLocked removes an unreferenced route from the cache (dropping its
// proxy URL and credentials) and returns its transport for
// CloseIdleConnections. That also sets net/http's closeIdle flag, so a
// connection whose response finished concurrently is closed rather than
// pooled.
func (t *Transport) evictLocked(key string, e *routeEntry) *http.Transport {
	delete(t.routes, key)
	return e.rt
}

// evictExcessLocked evicts least recently used unreferenced routes until at
// most MaxProxyRoutes remain (or only routes with in-flight requests do).
func (t *Transport) evictExcessLocked() []*http.Transport {
	max := t.MaxProxyRoutes
	if max <= 0 {
		max = 64
	}
	var out []*http.Transport
	for len(t.routes) > max {
		var lk string
		var lr *routeEntry
		for k, r := range t.routes {
			if r.refs == 0 && (lr == nil || r.lastUsed.Before(lr.lastUsed)) {
				lk, lr = k, r
			}
		}
		if lr == nil {
			break // all in flight; shrink again as they finish
		}
		out = append(out, t.evictLocked(lk, lr))
	}
	return out
}

func (t *Transport) release(e *routeEntry) {
	t.mu.Lock()
	e.refs--
	e.lastUsed = time.Now()
	closeNow := t.evictExcessLocked()
	t.mu.Unlock()
	for _, rt := range closeNow {
		rt.CloseIdleConnections()
	}
}

// dialTLS opens the route to addr and completes a uTLS handshake.
func (t *Transport) dialTLS(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	timeout := t.TLSHandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, _, err := net.SplitHostPort(addr)
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
			return nil, fmt.Errorf("utls: Transport speaks only h2 and http/1.1, not ALPN %q", p)
		}
	}
	raw, err := t.dialRoute(ctx, pu, addr)
	if err != nil {
		return nil, err
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
	if t.Fragmentation != nil {
		if err := uc.SetFragmentation(*t.Fragmentation); err != nil {
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

// dialRoute dials addr directly or through proxy pu.
func (t *Transport) dialRoute(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
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
	c, err := t.baseDial(ctx, "tcp", canonicalAddr(pu))
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
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Unix(1, 0)) })
	if err := creq.Write(c); err != nil {
		stop()
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, creq)
	if err != nil {
		stop()
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if !stop() {
		c.Close()
		return nil, ctx.Err()
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("utls: proxy CONNECT to %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		c.Close()
		return nil, errors.New("utls: proxy sent data before the TLS handshake")
	}
	return c, nil
}

// CloseIdleConnections closes idle connections on every route and drops
// every route without in-flight requests (and with it the proxy URL and its
// credentials). Routes still serving requests keep them; their connections
// close when idle.
func (t *Transport) CloseIdleConnections() {
	t.init()
	t.plain.CloseIdleConnections()
	var rts []*http.Transport
	t.mu.Lock()
	for k, e := range t.routes {
		if e.refs == 0 {
			rts = append(rts, t.evictLocked(k, e))
		} else {
			rts = append(rts, e.rt)
		}
	}
	t.mu.Unlock()
	for _, rt := range rts {
		rt.CloseIdleConnections()
	}
}

// routeCount reports the number of cached routes (for tests).
func (t *Transport) routeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.routes)
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
