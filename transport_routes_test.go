// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingSOCKS5 is a SOCKS5 proxy (username/password accepted) that tracks
// open tunnels per username.
type countingSOCKS5 struct {
	addr string
	mu   sync.Mutex
	open map[string]int
}

func (p *countingSOCKS5) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, v := range p.open {
		n += v
	}
	return n
}

func (p *countingSOCKS5) users() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for u, v := range p.open {
		if v > 0 {
			out = append(out, u)
		}
	}
	return out
}

func newCountingSOCKS5(t *testing.T) *countingSOCKS5 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &countingSOCKS5{addr: ln.Addr().String(), open: map[string]int{}}
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
				c.Write([]byte{5, 2}) // username/password
				io.ReadFull(c, buf[:2])
				ul := int(buf[1])
				io.ReadFull(c, buf[:ul])
				user := string(buf[:ul])
				io.ReadFull(c, buf[:1])
				io.ReadFull(c, buf[:buf[0]])
				c.Write([]byte{1, 0})
				io.ReadFull(c, buf[:4])
				io.ReadFull(c, buf[:4]) // IPv4 only (tests dial 127.0.0.1)
				host := net.IP(buf[:4]).String()
				io.ReadFull(c, buf[:2])
				up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(buf[:2]))))
				if err != nil {
					return
				}
				p.mu.Lock()
				p.open[user]++
				p.mu.Unlock()
				defer func() { p.mu.Lock(); p.open[user]--; p.mu.Unlock() }()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
				up.Close()
			}(c)
		}
	}()
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func rotatingProxy(addr string) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		user := r.Header.Get("X-Route")
		return &url.URL{Scheme: "socks5", Host: addr, User: url.UserPassword(user, "secret-"+user)}, nil
	}
}

func get(t *testing.T, tr *Transport, u, route string) string {
	t.Helper()
	req := httptestRequest("GET", u, "")
	req.Header.Set("X-Route", route)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("route %s: %v", route, err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Rotating credentials: many distinct routes stay bounded, evicted routes'
// connections are closed, and CloseIdleConnections drops every idle route.
func TestTransportRouteCacheBounded(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			s := newHTTPServer(t, h2, http.HandlerFunc(echoHandler))
			p := newCountingSOCKS5(t)
			tr := s.transport()
			tr.MaxProxyRoutes = 4
			tr.Proxy = rotatingProxy(p.addr)
			for i := 0; i < 40; i++ {
				get(t, tr, s.URL, fmt.Sprint("user", i))
				if n := tr.routeCount(); n > 4 {
					t.Fatalf("after %d routes, %d cached (max 4)", i+1, n)
				}
			}
			// Only the 4 most recent routes keep a (pooled) tunnel open.
			waitFor(t, "evicted tunnels to close", func() bool { return p.total() <= 4 })
			for _, u := range p.users() {
				var n int
				fmt.Sscanf(u, "user%d", &n)
				if n < 36 {
					t.Fatalf("tunnel of evicted route %s still open", u)
				}
			}
			tr.CloseIdleConnections()
			if n := tr.routeCount(); n != 0 {
				t.Fatalf("CloseIdleConnections kept %d idle routes", n)
			}
			waitFor(t, "all tunnels to close", func() bool { return p.total() == 0 })
		})
	}
}

// A request in flight on a route keeps working while the cache churns past
// its bound and while CloseIdleConnections runs; the route is released (and
// its tunnel closed) only after the response finishes.
func TestTransportRouteEvictionSparesInFlight(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint("h2=", h2), func(t *testing.T) {
			release := make(chan struct{})
			var started atomic.Bool
			s := newHTTPServer(t, h2, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					w.Write([]byte("first-half;"))
					w.(http.Flusher).Flush()
					started.Store(true)
					<-release
					w.Write([]byte("second-half"))
					return
				}
				echoHandler(w, r)
			}))
			p := newCountingSOCKS5(t)
			tr := s.transport()
			tr.MaxProxyRoutes = 2
			tr.Proxy = rotatingProxy(p.addr)

			type result struct {
				body string
				err  error
			}
			done := make(chan result, 1)
			go func() {
				req := httptestRequest("GET", s.URL+"/slow", "")
				req.Header.Set("X-Route", "active")
				resp, err := tr.RoundTrip(req)
				if err != nil {
					done <- result{err: err}
					return
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				done <- result{string(b), err}
			}()
			waitFor(t, "the slow request to start", started.Load)

			for i := 0; i < 10; i++ { // churn: evicts everything evictable
				get(t, tr, s.URL, fmt.Sprint("churn", i))
			}
			tr.CloseIdleConnections()
			if n := tr.routeCount(); n != 1 {
				t.Fatalf("%d routes cached; want only the in-flight one", n)
			}
			if !strings.Contains(strings.Join(p.users(), ","), "active") {
				t.Fatal("the in-flight route's tunnel was closed")
			}
			close(release)
			r := <-done
			if r.err != nil || r.body != "first-half;second-half" {
				t.Fatalf("in-flight request: %q %v", r.body, r.err)
			}
			// Now finished: further churn evicts it and closes its tunnel.
			for i := 0; i < 3; i++ {
				get(t, tr, s.URL, fmt.Sprint("after", i))
			}
			waitFor(t, "the finished route's tunnel to close", func() bool {
				return !strings.Contains(strings.Join(p.users(), ","), "active")
			})
		})
	}
}

// Idle routes expire after IdleConnTimeout even without churn past the bound.
func TestTransportRouteIdleExpiry(t *testing.T) {
	s := newHTTPServer(t, false, http.HandlerFunc(echoHandler))
	p := newCountingSOCKS5(t)
	tr := s.transport()
	tr.IdleConnTimeout = 50 * time.Millisecond
	tr.Proxy = rotatingProxy(p.addr)
	get(t, tr, s.URL, "old")
	time.Sleep(100 * time.Millisecond)
	get(t, tr, s.URL, "new")
	if n := tr.routeCount(); n != 1 {
		t.Fatalf("%d routes; the idle one should have expired", n)
	}
}
