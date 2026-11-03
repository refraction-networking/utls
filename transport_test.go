// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testHTTPServer struct {
	*httptest.Server
	conns   atomic.Int32
	greased atomic.Int32
	roots   *x509.CertPool
	addr    string
}

func newHTTPServer(t *testing.T, h2 bool, h http.Handler) *testHTTPServer {
	s := &testHTTPServer{}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, c := range ch.CipherSuites {
			if isGREASE(c) {
				s.greased.Add(1)
				break
			}
		}
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.Server = srv
	s.roots = x509.NewCertPool()
	s.roots.AddCert(srv.Certificate())
	s.addr = srv.Listener.Addr().String()
	return s
}

func (s *testHTTPServer) transport() *Transport {
	return &Transport{TLSConfig: &tls.Config{RootCAs: s.roots, ServerName: "example.com"}}
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	fmt.Fprintf(w, "%s %d %s", r.Proto, len(b), b)
}

// oneShotBody is a non-replayable body that fails if read twice.
type oneShotBody struct {
	r      io.Reader
	closed atomic.Bool
}

func (b *oneShotBody) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, errors.New("read after close")
	}
	return b.r.Read(p)
}
func (b *oneShotBody) Close() error { b.closed.Store(true); return nil }

func TestTransportH2PoolingConcurrent(t *testing.T) {
	s := newHTTPServer(t, true, http.HandlerFunc(echoHandler))
	tr := s.transport()
	defer tr.CloseIdleConnections()
	// Warm up: concurrent FIRST requests each dial (as with crypto/tls, the
	// protocol is unknown until a handshake completes); afterwards all
	// requests multiplex on the pooled HTTP/2 connection.
	resp, err := tr.RoundTrip(httptestRequest("GET", s.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := &oneShotBody{r: strings.NewReader(fmt.Sprintf("body-%d", i))}
			req, _ := http.NewRequest("POST", s.URL+"/", body)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" ||
				string(b) != fmt.Sprintf("HTTP/2.0 %d body-%d", len(fmt.Sprintf("body-%d", i)), i) {
				errs <- fmt.Errorf("bad response %q proto %d", b, resp.ProtoMajor)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := s.conns.Load(); n != 1 {
		t.Fatalf("h2 not pooled: %d connections for 33 requests", n)
	}
	if s.greased.Load() == 0 {
		t.Fatal("server did not see the uTLS fingerprint")
	}
}

func TestTransportH1Pooling(t *testing.T) {
	s := newHTTPServer(t, false, http.HandlerFunc(echoHandler))
	tr := s.transport()
	for i := 0; i < 10; i++ {
		resp, err := tr.RoundTrip(httptestRequest("POST", s.URL+"/", "x"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 1 || string(b) != "HTTP/1.1 1 x" || resp.TLS == nil {
			t.Fatalf("bad response %q", b)
		}
	}
	if n := s.conns.Load(); n != 1 {
		t.Fatalf("h1 keep-alive not pooled: %d connections", n)
	}
	tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(httptestRequest("GET", s.URL+"/", ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n := s.conns.Load(); n != 2 {
		t.Fatalf("CloseIdleConnections did not close: %d", n)
	}
}

func httptestRequest(method, u, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, r)
	return req
}

func TestTransportCancelAndTimeout(t *testing.T) {
	s := newHTTPServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	tr := s.transport()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &oneShotBody{r: strings.NewReader("x")}
	req, _ := http.NewRequestWithContext(ctx, "POST", s.URL, body)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("canceled request succeeded")
	}
	if !body.closed.Load() {
		t.Fatal("body not closed for a canceled request")
	}
	tr.ResponseHeaderTimeout = 200 * time.Millisecond
	tr2 := s.transport()
	tr2.ResponseHeaderTimeout = 200 * time.Millisecond
	start := time.Now()
	_, err := tr2.RoundTrip(httptestRequest("GET", s.URL, ""))
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("h2 ResponseHeaderTimeout not applied: %v after %v", err, time.Since(start))
	}
}

// connectProxy is a counting HTTP CONNECT / forward proxy.
type connectProxy struct {
	addr     string
	connects atomic.Int32
	forwards atomic.Int32
	auth     atomic.Value
}

func newConnectProxy(t *testing.T) *connectProxy {
	p := &connectProxy{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	p.auth.Store(req.Header.Get("Proxy-Authorization"))
	if req.Method == http.MethodConnect {
		p.connects.Add(1)
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
		go func() { io.Copy(up, br); up.Close() }()
		io.Copy(c, up)
		c.Close()
		return
	}
	p.forwards.Add(1) // forward-proxy form: absolute URI
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		c.Close()
		return
	}
	resp.Write(c)
	c.Close()
}

func TestTransportProxyRouteIsolation(t *testing.T) {
	s := newHTTPServer(t, true, http.HandlerFunc(echoHandler))
	pa, pb := newConnectProxy(t), newConnectProxy(t)
	tr := s.transport()
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		if r.Header.Get("X-Route") == "a" {
			return &url.URL{Scheme: "http", Host: pa.addr, User: url.UserPassword("alice", "pw")}, nil
		}
		return &url.URL{Scheme: "http", Host: pb.addr}, nil
	}
	for i := 0; i < 6; i++ {
		req := httptestRequest("GET", s.URL, "")
		route := "a"
		if i%2 == 1 {
			route = "b"
		}
		req.Header.Set("X-Route", route)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if pa.connects.Load() != 1 || pb.connects.Load() != 1 {
		t.Fatalf("routes shared or not pooled: a=%d b=%d tunnels", pa.connects.Load(), pb.connects.Load())
	}
	if !strings.HasPrefix(pa.auth.Load().(string), "Basic ") {
		t.Fatal("proxy credentials not sent")
	}
	// Plain http uses standard forward-proxy semantics.
	plain := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer plain.Close()
	tr = &Transport{Proxy: func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: pa.addr}, nil }}
	resp, err := tr.RoundTrip(httptestRequest("GET", plain.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if pa.forwards.Load() != 1 {
		t.Fatal("plain http was not forwarded via the proxy")
	}
}

// socks5 is a minimal no-auth SOCKS5 CONNECT server.
func newSOCKS5(t *testing.T) (string, *atomic.Int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				io.ReadFull(c, buf[:buf[1]])
				c.Write([]byte{5, 0})
				io.ReadFull(c, buf[:4])
				var host string
				switch buf[3] {
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					io.ReadFull(c, buf[:1])
					l := int(buf[0])
					io.ReadFull(c, buf[:l])
					host = string(buf[:l])
				}
				io.ReadFull(c, buf[:2])
				port := binary.BigEndian.Uint16(buf[:2])
				up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
				if err != nil {
					return
				}
				n.Add(1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), &n
}

func TestTransportSOCKS5(t *testing.T) {
	s := newHTTPServer(t, true, http.HandlerFunc(echoHandler))
	addr, n := newSOCKS5(t)
	tr := s.transport()
	tr.Proxy = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "socks5", Host: addr}, nil }
	resp, err := tr.RoundTrip(httptestRequest("GET", s.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n.Load() != 1 || resp.ProtoMajor != 2 {
		t.Fatalf("socks tunnels=%d proto=%d", n.Load(), resp.ProtoMajor)
	}
}

func TestTransportRejectsUnknownALPN(t *testing.T) {
	s := newHTTPServer(t, true, http.HandlerFunc(echoHandler))
	tr := s.transport()
	tr.TLSConfig.NextProtos = []string{"spdy/3"}
	if _, err := tr.RoundTrip(httptestRequest("GET", s.URL, "")); err == nil {
		t.Fatal("unknown ALPN accepted")
	}
}
