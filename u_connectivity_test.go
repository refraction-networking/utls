package tls

import (
	"context"
	"crypto/mldsa"
	ctls "crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// The connectivity test uses a well-known endpoint that answers with status 204 and an
// empty body. A short answer keeps the test independent of page content.
const (
	connectivityHost = "www.google.com"
	connectivityAddr = connectivityHost + ":443"
	connectivityURL  = "https://" + connectivityHost + "/generate_204"

	// Chrome sends this User-Agent with the profile that the test uses.
	connectivityUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

	connectivityTimeout = 30 * time.Second
)

// connectivityResult holds what one request of the connectivity test showed.
type connectivityResult struct {
	state      ConnectionState
	statusCode int
	bodyLen    int
}

// TestChrome150PSKConnectsToGoogle makes two real connections to www.google.com with
// the HelloChrome_150_PSK profile. The unit tests show that a server in the same
// process accepts the profile. This test shows that a production server, which applies
// its own rules to the ClientHello, also accepts it.
//
// The first connection makes a full handshake and receives a session ticket. The second
// connection sends the pre_shared_key extension of the profile, and the server must
// resume the session. Both connections must receive status 204.
//
// The test needs internet access. Use "go test -short" to skip it.
func TestChrome150PSKConnectsToGoogle(t *testing.T) {
	if testing.Short() {
		t.Skipf("skip: the test connects to %s", connectivityAddr)
	}

	cache := NewLRUClientSessionCache(0)

	first := getGenerate204(t, cache)
	if first.state.DidResume {
		t.Error("the first connection resumed a session, although the cache was empty")
	}
	if first.statusCode != http.StatusNoContent {
		t.Errorf("the first connection got status %d, but the test expects %d",
			first.statusCode, http.StatusNoContent)
	}

	second := getGenerate204(t, cache)
	if !second.state.DidResume {
		t.Error("the second connection did not resume the session, although the cache held a ticket")
	}
	if second.statusCode != http.StatusNoContent {
		t.Errorf("the second connection got status %d, but the test expects %d",
			second.statusCode, http.StatusNoContent)
	}
}

// getGenerate204 makes one request to connectivityURL through a new connection. The
// connection uses the HelloChrome_150_PSK profile and the given session cache. The
// cache is the only state that the calls share.
func getGenerate204(t *testing.T, cache ClientSessionCache) connectivityResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), connectivityTimeout)
	defer cancel()

	var result connectivityResult

	// The profile offers h2 and http/1.1. Google selects h2, thus the request goes
	// through an HTTP/2 transport that dials with utls.
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *ctls.Config) (net.Conn, error) {
			tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, connectivityAddr)
			if err != nil {
				return nil, err
			}

			uconn := UClient(tcpConn, &Config{
				ServerName:         connectivityHost,
				NextProtos:         []string{"h2", "http/1.1"},
				ClientSessionCache: cache,
				OmitEmptyPsk:       true,
			}, HelloChrome_150_PSK)

			if err := uconn.HandshakeContext(ctx); err != nil {
				tcpConn.Close()
				return nil, err
			}

			result.state = uconn.ConnectionState()
			return uconn, nil
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, connectivityURL, nil)
	if err != nil {
		t.Fatalf("cannot make the request: %v", err)
	}
	req.Header.Set("User-Agent", connectivityUserAgent)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("cannot connect to %s: %v (the test needs internet access)", connectivityAddr, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("cannot read the body: %v", err)
	}

	result.statusCode = resp.StatusCode
	result.bodyLen = len(body)

	t.Logf("%s: version 0x%04x, cipher 0x%04x, alpn %q, resumed %v, status %d, body %d bytes",
		connectivityAddr, result.state.Version, result.state.CipherSuite,
		result.state.NegotiatedProtocol, result.state.DidResume,
		result.statusCode, result.bodyLen)

	return result
}

// The Open Quantum Safe project runs an NGINX server that holds a separate port for
// each signature and key exchange combination. These 3 ports use ML-DSA server
// authentication. The port numbers come from the table at
// https://test.openquantumsafe.org/, and the server selects X25519MLKEM768 on each one.
const oqsHost = "test.openquantumsafe.org"

// oqsRootCA is the root of the test server, from https://test.openquantumsafe.org/CA.crt.
// The root uses RSA-4096. The intermediate certificate and the leaf certificate use
// ML-DSA. Thus the chain verification of this test exercises ML-DSA in crypto/x509.
//
// The certificate expires on 30 November 2026. Get the file again after that date.
const oqsRootCA = `-----BEGIN CERTIFICATE-----
MIIFTjCCAzagAwIBAgIUeg1oLTvTiGcNxrOde3kvBXtIAmkwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKb3FzdGVzdF9DQTAeFw0yNTA3MTgwOTI2NDFaFw0yNjEx
MzAwOTI2NDFaMBUxEzARBgNVBAMMCm9xc3Rlc3RfQ0EwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDiuz/TmHvGcRRdtLmDV1UWwt6Z9/IBUG54G+WVfq8d
uVYsOoCzh6N85GbQOIbM6raEoepAaqpaKEYoi7UGkVzpWnbOTscWq71lJ+T9t+TF
KXXws2xVjTJCJYrKit1taCgO777wwdfE4JzHGGTiWl/2aXJsMNqQ46kpWMu57TgS
XIpUJo95aEGO3MG56IiO5kyvqAHtfCXJiH3CmGqpqGCK30uXeKBi9fqU6xUzrJsL
Om9djmgbqeun/TG83c5mJ7jMOnCzjl0eaZDoHRZgedSyjOLpAu2JZT4DZly9b+oR
xQg9VSFKrojOvZsDkHyuxoUsTTxU2GnUec8ygUWsw8YdbCUf0OWsYStkOgnqnXnC
8ZgUxHgqlJccXpRY1+b+IfWzkmWWTpD6043d+8J+5nyfWlaTyPlq7zvEyz7kCgmq
FjF2in0/Qw7Xe8JRpr3VzKgzsb+plnj7MCkxLzo/f2A45E2N3VP99jap7EuuyQ/J
FjMOKtaggep0fubT4OjWyicDz6sh/uWDGGWW1YZoI9uX7Xdiky5wCxoUSrRetv/h
PZtExudRS9OGsC57kb9vwQSkwyKcXGnQiIrMjBUe8GUP4yu8umXj6ei10s1TysUB
iSRQW2kNN3StGE6sTDuT5X+Knng6ciOVuW/XrsPP3TklQqBLo+ArGXV2+Q/IW7HJ
twIDAQABo4GVMIGSMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIGnIxlFxqHD
68PdPBIbGne/LZ+GMFAGA1UdIwRJMEeAFIGnIxlFxqHD68PdPBIbGne/LZ+GoRmk
FzAVMRMwEQYDVQQDDApvcXN0ZXN0X0NBghR6DWgtO9OIZw3Gs517eS8Fe0gCaTAO
BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBACQfDyP6jpizi0foDNx0
evj2vfxNaOxBttOB1mImtUncfTIHFAXG0BldFJJs8NPeyDRn2/7xZ9KpHWTRyIqM
WZfd0fi2bj2+22BGNtmcIAdEuquhP25Mi5N8eT5eBD35Fp5M2ryECpl44R50mDkW
/8Gt+jtIany0ZFKqVZ/0ZsYgC94bx1rp6ZMm67IoxUrG0v7xDTunDOVX+SYVD02E
+ggx3bgUEdFKT9G4NxcZoDAOWiNVj5P5KTv4qoAB6J3pTUFqM9bbjpLLSKh6F752
fHN/SZBB2aZ0ittVwtgs7NEKqoNpTgfYXX+eAIWnmLU9P6S++xHt1Jvyb/z4hQCn
EeOIm8IzmIqZ07ov1viPtN92Ra1EehikdJTvMMBVA0GttXB4054v6Ro7bfgu04Xr
iICIquMwx4/qxiMFvujP2KMbI2VPhGQi2dhI1ho+Yv9nY9sgc36nWDlQF2OUwrRy
FY4GOve0Dxcwv23oD7GbKgE7fCQ1z78ccLFagzuwTHNPoFL8SrczPJF5/0K8N4GH
5r8GsajDh5AH+plRkq5UObOBh8RLqinUucraF9FCZV6xZ00gqRY43ZqR5VxmH2la
7pxJQCce++0kxgeuFDA9jr5ng8pnYqVSy+vfDy0VseqVq83UwLxtEoGfO7S4Jh/u
gP3YMSSdsj+fvqmrI6j3C6md
-----END CERTIFICATE-----`

// oqsMLDSAPorts maps each ML-DSA parameter set to its port on the test server.
var oqsMLDSAPorts = []struct {
	name       string
	port       int
	signature  x509.SignatureAlgorithm
	parameters mldsa.Parameters
}{
	{"ML-DSA-44", 6184, x509.MLDSA44, mldsa.MLDSA44()},
	{"ML-DSA-65", 6197, x509.MLDSA65, mldsa.MLDSA65()},
	{"ML-DSA-87", 6212, x509.MLDSA87, mldsa.MLDSA87()},
}

// TestChrome150PSKConnectsToMLDSAServer makes a real connection to each ML-DSA port of
// the Open Quantum Safe test server with the HelloChrome_150_PSK profile.
//
// The unit tests show that the client verifies ML-DSA against a server in the same
// process. This test shows that the client verifies ML-DSA against an NGINX server that
// uses OpenSSL 3.5 or later.
//
// Each connection proves 3 things. The client offers the ML-DSA codepoints, thus the
// server selects one. The client verifies the CertificateVerify signature of the
// server, which uses the ML-DSA key of the leaf certificate. And crypto/x509 verifies a
// chain in which the intermediate certificate signs the leaf with ML-DSA.
//
// The test needs internet access. Use "go test -short" to skip it.
func TestChrome150PSKConnectsToMLDSAServer(t *testing.T) {
	if testing.Short() {
		t.Skipf("skip: the test connects to %s", oqsHost)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(oqsRootCA)) {
		t.Fatal("cannot read the root certificate of the test server")
	}

	for _, target := range oqsMLDSAPorts {
		t.Run(target.name, func(t *testing.T) {
			address := net.JoinHostPort(oqsHost, strconv.Itoa(target.port))

			tcpConn, err := net.DialTimeout("tcp", address, connectivityTimeout)
			if err != nil {
				t.Fatalf("cannot connect to %s: %v (the test needs internet access)", address, err)
			}
			defer tcpConn.Close()

			uconn := UClient(tcpConn, &Config{
				ServerName:   oqsHost,
				RootCAs:      roots,
				OmitEmptyPsk: true,
			}, HelloChrome_150_PSK)

			ctx, cancel := context.WithTimeout(context.Background(), connectivityTimeout)
			defer cancel()

			if err := uconn.HandshakeContext(ctx); err != nil {
				t.Fatalf("the handshake with %s failed: %v", address, err)
			}
			defer uconn.Close()

			state := uconn.ConnectionState()
			if state.Version != VersionTLS13 {
				t.Errorf("the connection uses the version 0x%04x, but ML-DSA needs TLS 1.3", state.Version)
			}
			if state.testingOnlyCurveID != X25519MLKEM768 {
				t.Errorf("the connection uses the group %v, but the test expects X25519MLKEM768",
					state.testingOnlyCurveID)
			}

			if len(state.PeerCertificates) == 0 {
				t.Fatal("the connection holds no peer certificate")
			}
			leaf := state.PeerCertificates[0]

			// The leaf certificate holds an ML-DSA key. RFC 8446 makes the server sign
			// the CertificateVerify message with the key of the leaf certificate. Thus
			// this check shows that the client verified an ML-DSA signature.
			if leaf.PublicKeyAlgorithm != x509.MLDSA {
				t.Errorf("the leaf certificate holds a %v key, but the test expects an ML-DSA key",
					leaf.PublicKeyAlgorithm)
			}
			publicKey, ok := leaf.PublicKey.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("the leaf certificate holds the key type %T, but the test expects *mldsa.PublicKey",
					leaf.PublicKey)
			}
			if got := publicKey.Parameters().String(); got != target.parameters.String() {
				t.Errorf("the leaf key uses the parameter set %s, but the test expects %s",
					got, target.parameters.String())
			}

			// The intermediate certificate signs the leaf certificate with ML-DSA.
			if leaf.SignatureAlgorithm != target.signature {
				t.Errorf("the intermediate certificate signs the leaf with %v, but the test expects %v",
					leaf.SignatureAlgorithm, target.signature)
			}

			t.Logf("%s: version 0x%04x, cipher 0x%04x, group %v, leaf key %v, leaf signature %v",
				address, state.Version, state.CipherSuite, state.testingOnlyCurveID,
				publicKey.Parameters(), leaf.SignatureAlgorithm)
		})
	}
}
