package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
	"golang.org/x/net/proxy"
)

// uhttpLogger is the type of the optional logger. The log.Default
// logger in the standard library matches this interface.
type uhttpLogger interface {
	Printf(fmt string, v ...interface{})
	Print(v ...interface{})
}

// uhttpSilentLogger is the silent logger.
type uhttpSilentLogger struct{}

// Printf implements uhttpLogger.Printf.
func (ul *uhttpSilentLogger) Printf(fmt string, v ...interface{}) {}

// Print implements uhttpLogger.Print.
func (ul *uhttpSilentLogger) Print(v ...interface{}) {}

// uhttpLog is the default logger.
var uhttpLog uhttpLogger = &uhttpSilentLogger{}

// init checks whether the user wants verbose logs.
func init() {
	if os.Getenv("UHTTP_VERBOSE") == "1" {
		uhttpLog = log.Default()
	}
}

// UHTTPTransport uses UTLS instead of TLS. This struct
// mimicks an http.Transport and matches the http.RoundTripper
// standard library interface.
//
// As documented in https://github.com/refraction-networking/utls/issues/16,
// the standard library http.RoundTripper cannot use connections
// from UTLS because httpTransport enables http2 only when it's possible
// to cast the net.Conn to a *tls.Conn.
//
// This transport attempts to solve this issue by inspecting
// the ALPN negotiated protocol and routing:
//
// - "h2" to a default constructed http2.Transport;
//
// - "http/1.1" to a default constructed http.Transport.
//
// Moreover, cleartext HTTP requests go to a default
// constructed http.Transport.
//
// The zero initialized UHTTPTransport is valid and can be
// used immediately. We will allocate internal variables when
// we need them. As http.Transport, UHTTPTransport may have
// idle connections, for which CloseIdleConnections can be used.
//
// You SHOULD NOT modify the public fields of this data
// structure while it's being used, because that MAY
// quite possibly lead to data races. Otherwise, it is
// safe to call the methods of this struct from several
// concurrent goroutines.
type UHTTPTransport struct {
	// TODO(bassosimone): what useful fields of an ordinary
	// http.Transport should we also implement?

	// DialContext is the optional dialer to dial connections
	// just like the namesake field of http.Transport. If this
	// dialer is set, we'll use it for dialing all conns.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// Proxy is like the namesake field in http.Transport. If
	// not initialized, or if it returns a nil URL, then there
	// will be no proxying of connections. We support the
	// same types of proxies as the stdlib for HTTP but we
	// only support socks5 proxies for HTTPS/H2.
	Proxy func(*http.Request) (*url.URL, error)

	// TLSClientConfig contains optional UTLS configuration for
	// this transport. We will default-construct a config
	// instance if this field is not set. Otherwise,
	// every dial attempt will use a Clone() of this field.
	TLSClientConfig *Config

	// TLSHandshakeTimeout is the optional maximum timeout we are
	// willing to wait for the TLS handshake. If not set, we'll
	// use a default TLS-handshake timeout of ten seconds.
	TLSHandshakeTimeout time.Duration

	// UTLSClientHelloID is the optional UTLS ClientHelloID
	// that you would like to use with this transport. If
	// nil, we will use utls.HelloFirefox_Auto.
	UTLSClientHelloID *ClientHelloID

	// cleartext is a transport for HTTP only. We will initialize
	// this field on the first RoundTrip invocation.
	cleartext uhttpCloseableTransport

	// onlyDial is the transport used for dialing new
	// connections. It will populate connCache and
	// hostCache. We will initialize this field during
	// the first invocation of RoundTrip.
	onlyDial uhttpCloseableTransport

	// https is a transport used only for the "http/1.1"
	// ALPN. This transport does not perform any dial and
	// only manages its cached persistent connections. We'll
	// initialize it during the first RoundTrip call.
	https uhttpCloseableTransport

	// h2 is like https but for the "h2" ALPN.
	h2 uhttpCloseableTransport

	// connCache maps a specific dialing address to an open
	// connection. We will store open connections created by the
	// dialOnly in this field. The https and h2 transports
	// will get their new connections from this field. We will
	// initialize this field during the first RoundTrip call.
	connCache map[string][]net.Conn

	// hostCache maps a specific URL.Host[:port] to the proper
	// HTTP transport. We will remember which URL.Host[:port] wants
	// HTTP/1.1 and which one wants H2. We will initialize
	// this field during the first RoundTrip call.
	hostCache map[string]http.RoundTripper

	// mu allows for synchronized access of internals.
	mu sync.Mutex
}

// _ ensures that UHTTPTransport matches the http.RoundTripper interface.
var _ http.RoundTripper = &UHTTPTransport{
	Proxy: http.ProxyFromEnvironment,
}

// UHTTPDefaultTransport is the default UHTTPTransport.
var UHTTPDefaultTransport http.RoundTripper = &UHTTPTransport{}

// errUHTTPNoCachedConn indicates that there are no cached connections.
var errUHTTPNoCachedConn = errors.New("no cached conn")

// errUHTTPUseH2 indicates that we should be using h2.
var errUHTTPUseH2 = errors.New("utls: use h2")

// errUHTTPUseHTTPS indicates that we should be using http/1.1 over TLS.
var errUHTTPUseHTTPS = errors.New("utls: use https")

// uhttpProxyURLKey is the type key to bind a proxy URL to a context.
type uhttpProxyURLKey struct{}

// uhttpWithProxyURL returns a copy of the current context
// that keeps track of the current proxy URL. If there
// is no proxy URL, this function returns the original context.
func uhttpWithProxyURL(ctx context.Context, proxyURL *url.URL) context.Context {
	if proxyURL == nil {
		return ctx
	}
	return context.WithValue(ctx, uhttpProxyURLKey{}, proxyURL)
}

// uhttpContextWithProxyURL returns the proxy URL that
// we saved in the context so we can honor Proxy. If the
// user configured no proxy, then we return nil.
func uhttpContextWithProxyURL(ctx context.Context) *url.URL {
	URL, _ := ctx.Value(uhttpProxyURLKey{}).(*url.URL)
	return URL
}

// RoundTrip implements http.RoundTripper.RoundTrip.
func (txp *UHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	txp.maybeInitTxps()
	// Step 1: immediately dispatch HTTP requests
	switch req.URL.Scheme {
	case "http":
		uhttpLog.Printf("uhttp: using transport %s", txp.cleartext)
		return txp.cleartext.RoundTrip(req)
	case "https":
		// we need to figure out which transport to use - fallthrough
	default:
		return nil, errors.New("uhttp: unsupported URL scheme")
	}
	// Step 2: check whether we have a proxy URL.
	proxyURL, err := txp.proxy(req)
	if err != nil {
		return nil, err
	}
	// Step 3: dispatch HTTPS requests to the proper transport
	child := txp.hostCacheGetOrDefault(req.URL)
	const maxRetries = 4
	for i := 0; i < maxRetries; i++ {
		uhttpLog.Printf("uhttp: using transport %s", child)
		resp, err := child.RoundTrip(req)
		if !errors.Is(err, errUHTTPNoCachedConn) {
			return resp, err // success or hard round trip error
		}
		uhttpLog.Printf("uhttp: dialing with transport %s", txp.onlyDial)
		resp, err = txp.onlyDial.RoundTrip(req.WithContext(
			uhttpWithProxyURL(req.Context(), proxyURL),
		))
		if err == nil {
			// if this happens then something's wrong with txpDialer
			resp.Body.Close()
			return nil, errors.New("uhttp: bug: txp.txpDialer returned nil error")
		}
		if errors.Is(err, errUHTTPUseH2) {
			child = txp.h2
			continue
		}
		if errors.Is(err, errUHTTPUseHTTPS) {
			child = txp.https
			continue
		}
		return nil, err // hard dialing error
	}
	// if this happens there's something wrong in how we're dialing
	// and/or caching connections and we should know about it
	return nil, errors.New("uhttp: bug: cannot get a suitable connection")
}

// proxy returns the proxy URL (which may be nil) or an error.
func (txp *UHTTPTransport) proxy(req *http.Request) (*url.URL, error) {
	if txp.Proxy != nil {
		return txp.Proxy(req)
	}
	return nil, nil
}

// uhttpNoCachedConnRoundTripper is a round tripper that fails
// every dial attempt with errNoCachedConn.
var uhttpNoCachedConnRoundTripper = &uhttpStringer{
	uhttpCloseableTransport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errUHTTPNoCachedConn
		},
	},
	name: "empty",
}

// hostCacheGetOrDefault returns the transport mapped to a
// specific URL.Host[:port], if any. Otherwise, it returns a default
// round tripper that will always fail to dial.
func (txp *UHTTPTransport) hostCacheGetOrDefault(URL *url.URL) http.RoundTripper {
	defer txp.mu.Unlock()
	txp.mu.Lock()
	epnt := txp.makeEndpoint(URL.Host)
	if t, found := txp.hostCache[epnt]; found {
		uhttpLog.Printf("uhttp: %s maps to transport %s", epnt, t)
		return t
	}
	return uhttpNoCachedConnRoundTripper
}

// makeEndpoint constructs an endpoint to connect to from the
// value contained inside of the URL.Host field.
func (txp *UHTTPTransport) makeEndpoint(address string) string {
	// Adapted from x/net/http2/transport.go
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, "443"
	}
	if conv, err := idna.ToASCII(host); err == nil {
		host = conv
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// uhttpCloseableTransport is a closeable http.RoundTripper.
type uhttpCloseableTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}

// uhttpStringer is a http.RoundTripper implementing the String method,
// which allows it to be pretty printed when using %s.
type uhttpStringer struct {
	uhttpCloseableTransport
	name string
}

// String returns a compact string representation of a transport.
func (uhs *uhttpStringer) String() string {
	return fmt.Sprintf("%s#%p", uhs.name, uhs)
}

// maybeInitTxps initializes the internal transports once.
func (txp *UHTTPTransport) maybeInitTxps() {
	defer txp.mu.Unlock()
	txp.mu.Lock()
	if txp.cleartext == nil {
		txp.cleartext = &uhttpStringer{
			uhttpCloseableTransport: &http.Transport{
				DialContext: txp.dialCleartext,
				Proxy:       txp.Proxy,
			},
			name: "cleartext",
		}
	}
	if txp.onlyDial == nil {
		txp.onlyDial = &uhttpStringer{
			uhttpCloseableTransport: &http.Transport{
				DialContext:    txp.disableDialContext,
				DialTLSContext: txp.dialUTLSContext,
			},
			name: "onlyDial",
		}
	}
	if txp.https == nil {
		txp.https = &uhttpStringer{
			uhttpCloseableTransport: &http.Transport{
				DialTLS: txp.connCacheDialTLSHTTPS,
			},
			name: "https",
		}
	}
	if txp.h2 == nil {
		txp.h2 = &uhttpStringer{
			uhttpCloseableTransport: &http2.Transport{
				DialTLS: txp.connCacheDialTLSH2,
			},
			name: "h2",
		}
	}
}

// dialCleartext calls DialContext or uses a default DialContext
// if no DialContext has been configured by the user.
func (txp *UHTTPTransport) dialCleartext(
	ctx context.Context, network, address string) (net.Conn, error) {
	dialFn := txp.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}
	uhttpLog.Printf("uhttp: dialCleartext %p %s %s", ctx, network, address)
	return dialFn(ctx, network, address)
}

// disableDialContext is a DialContext that always fails.
func (txp *UHTTPTransport) disableDialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("uhttp: DialContext should not have been called")
}

// connCacheDialTLSHTTPS returns a cached connection for the given
// address, if any, otherwise errUHTTPNoCachedConn.
func (txp *UHTTPTransport) connCacheDialTLSHTTPS(
	network, address string) (net.Conn, error) {
	if conn := txp.connCachePop(address); conn != nil {
		return conn, nil
	}
	uhttpLog.Printf("uhttp: https: connCache miss for %s", address)
	return nil, errUHTTPNoCachedConn
}

// connCacheDialTLSH2 returns a cached connection for the given
// address, if any, otherwise errUHTTPNoCachedConn.
func (txp *UHTTPTransport) connCacheDialTLSH2(
	network, address string, config *tls.Config) (net.Conn, error) {
	if conn := txp.connCachePop(address); conn != nil {
		return conn, nil
	}
	uhttpLog.Printf("uhttp: h2: connCache miss for %s", address)
	return nil, errUHTTPNoCachedConn
}

// dialUTLSContext dials a TLS connection using UTLS and the
// settings configured inside UHTTPTransport. This function
// updates hostCache and saves the connection into connCache,
// on success. Note that success is indicated by returning
// one of errUHTTPUse{H2,HTTPS}.
func (txp *UHTTPTransport) dialUTLSContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	uhttpLog.Printf("uhttp: dialUTLSContext %p %s %s", ctx, network, address)
	hostname, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	uconfig := txp.tlsClientConfig()
	if uconfig.NextProtos == nil {
		// TODO(bassosimone): figure out whether there is a
		// configuration where UTLS won't overwrite this field.
		uconfig.NextProtos = []string{"http/1.1", "h2"}
	}
	if uconfig.ServerName == "" {
		uconfig.ServerName = hostname
	}
	dialContext, err := txp.getDialContextFn(ctx)
	if err != nil {
		return nil, err
	}
	tcpConn, err := dialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	uConn := UClient(tcpConn, uconfig, txp.utlsClientHelloID())
	defer tcpConn.SetDeadline(time.Time{})
	tcpConn.SetDeadline(time.Now().Add(txp.tlsHandshakeTimeout()))
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close() // owned by us
		return nil, err
	}
	switch uConn.ConnectionState().NegotiatedProtocol {
	case "http/1.1", "": // assume that empty ALPN means http/1.1
		txp.hostConnCachePut(address, txp.https, uConn)
		return nil, errUHTTPUseHTTPS
	case "h2":
		txp.hostConnCachePut(address, txp.h2, uConn)
		return nil, errUHTTPUseH2
	default:
		uConn.Close()
		return nil, errors.New("utls: unexpected alpn value")
	}
}

// hostCachePut creates a new host cache entry mapping the
// given host name to the given transport. It also gives the
// ownership of conn to connCache.
func (txp *UHTTPTransport) hostConnCachePut(
	address string, t http.RoundTripper, conn net.Conn) {
	defer txp.mu.Unlock()
	txp.mu.Lock()
	if txp.hostCache == nil {
		txp.hostCache = make(map[string]http.RoundTripper)
	}
	uhttpLog.Printf("uhttp: hostCache put %s => %s", address, t)
	txp.hostCache[address] = t
	if txp.connCache == nil {
		txp.connCache = make(map[string][]net.Conn)
	}
	uhttpLog.Printf("uhttp: connCache put %s => conn#%s", address, conn.RemoteAddr())
	txp.connCache[address] = append(txp.connCache[address], conn)
}

// tlsClientConfig returns the TLS config that we should use.
func (txp *UHTTPTransport) tlsClientConfig() *Config {
	if txp.TLSClientConfig != nil {
		return txp.TLSClientConfig.Clone()
	}
	return &Config{}
}

// dialContextFn is the type of DialContext
type dialContextFn func(ctx context.Context, network, address string) (net.Conn, error)

// uhttpForwardDialer allows us to forward a dialContextFn as a dialer.
type uhttpForwardDialer struct {
	fn dialContextFn
}

// Dial is like net.Dialer.Dial.
func (d *uhttpForwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.fn(context.Background(), network, address)
}

// DialContext is like net.Dialer.DialContext.
func (d *uhttpForwardDialer) DialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	return d.fn(ctx, network, address)
}

// getDialContextFn returns the proper DialContext function to use. This
// function will honor the configured ProxyURL, if any.
func (txp *UHTTPTransport) getDialContextFn(ctx context.Context) (dialContextFn, error) {
	dialFn := txp.DialContext
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}
	proxyURL := uhttpContextWithProxyURL(ctx)
	if proxyURL == nil {
		return dialFn, nil
	}
	dialer, err := proxy.FromURL(proxyURL, &uhttpForwardDialer{dialFn})
	if err != nil {
		return nil, err
	}
	contextDialer, good := dialer.(proxy.ContextDialer)
	if !good {
		return nil, errors.New("uhttp: bug: cannot get a ContextDialer")
	}
	return contextDialer.DialContext, nil
}

// handshakeTimeout returns the TLS handshake timeout.
func (txp *UHTTPTransport) tlsHandshakeTimeout() time.Duration {
	if txp.TLSHandshakeTimeout > 0 {
		return txp.TLSHandshakeTimeout
	}
	return 10 * time.Second
}

// utlsClientHelloID returns the utls.ClientHelloID
// that we should be using for the handshake.
func (txp *UHTTPTransport) utlsClientHelloID() ClientHelloID {
	if txp.UTLSClientHelloID != nil {
		return *txp.UTLSClientHelloID
	}
	return HelloFirefox_Auto
}

// connCachePop extracts one of the connections in the cache
// that are indexed by the provided address. Returns nil if
// we don't have any entry in cache for the address.
func (txp *UHTTPTransport) connCachePop(address string) net.Conn {
	defer txp.mu.Unlock()
	txp.mu.Lock()
	if cl, found := txp.connCache[address]; found && len(cl) >= 1 {
		conn := cl[0]
		cl = cl[1:]
		if len(cl) >= 1 {
			txp.connCache[address] = cl
		} else {
			delete(txp.connCache, address) // don't keep empty cache entries
		}
		uhttpLog.Printf("uhttp: connCache pop %s => conn#%s", address, conn.RemoteAddr())
		return conn
	}
	return nil
}

// CloseIdleConnections allows an http.Client controlling this
// transport to close the idle connections.
func (txp *UHTTPTransport) CloseIdleConnections() {
	// Implementation note: cached connections are also
	// cleaned up. Consider the case of a request that is
	// interrupted via the context after it caused us to
	// create a cached conn and before the RoundTripper has
	// a chance to use the conn. Consider that after that
	// the user calls CloseIdleConnections and then the
	// transport goes out of scope. In such a case,
	// we clearly want to get rid of the cached conn,
	// otherwise we would leak the open conns.
	if txp.cleartext != nil {
		txp.cleartext.CloseIdleConnections()
	}
	if txp.https != nil {
		txp.https.CloseIdleConnections()
	}
	if txp.h2 != nil {
		txp.h2.CloseIdleConnections()
	}
	defer txp.mu.Unlock()
	txp.mu.Lock()
	for _, cl := range txp.connCache {
		for _, conn := range cl {
			conn.Close()
		}
	}
	txp.connCache = nil
}
