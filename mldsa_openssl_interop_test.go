// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build opensslinterop && !nomldsa

package tls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const opensslInteropImage = "alpine:edge"

func TestOpenSSLMLDSAInterop(t *testing.T) {
	requireDocker(t)

	workDir := t.TempDir()
	generateOpenSSLMLDSACerts(t, workDir)

	t.Run("OpenSSL client verifies uTLS ML-DSA server", func(t *testing.T) {
		certPEM, err := os.ReadFile(filepath.Join(workDir, "server.crt"))
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := os.ReadFile(filepath.Join(workDir, "server.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			defer conn.Close()
			serverErr <- Server(conn, &Config{
				Certificates: []Certificate{cert},
				MinVersion:   VersionTLS13,
				MaxVersion:   VersionTLS13,
			}).Handshake()
		}()

		hostPort := ln.Addr().(*net.TCPAddr).Port
		runDocker(t, workDir, "sh", "-lc", fmt.Sprintf(
			"apk add --no-cache openssl >/dev/null && printf 'Q\\n' | openssl s_client -connect host.docker.internal:%d -servername localhost -verify_hostname localhost -tls1_3 -groups X25519 -sigalgs mldsa44 -CAfile /w/ca.crt -verify_return_error -brief",
			hostPort,
		))
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("uTLS client and OpenSSL ML-DSA server", func(t *testing.T) {
		hostAddr := startOpenSSLMLDSAServer(t, workDir, "server.crt", "server.key")
		roots := loadInteropCertPool(t, workDir, "ca.crt")

		clientConfig := &Config{
			ServerName: "localhost",
			RootCAs:    roots,
			MinVersion: VersionTLS13,
			MaxVersion: VersionTLS13,
		}
		// The container installs OpenSSL before s_server starts listening, and
		// Docker Desktop's proxy accepts connections before the backend is up,
		// so retry the full handshake instead of probing the TCP port.
		client := dialUTLSWithRetry(t, hostAddr, clientConfig, HelloChrome_150)
		if got := client.ConnectionState().Version; got != VersionTLS13 {
			client.Close()
			t.Fatalf("version = %#x, want TLS 1.3", got)
		}
		if len(client.ConnectionState().PeerCertificates) == 0 {
			client.Close()
			t.Fatal("OpenSSL server did not send a certificate")
		}
		expectMLDSAPublicKey(t, client.ConnectionState().PeerCertificates[0].PublicKey, MLDSA44)
		// s_server handles one connection at a time: close before the
		// single-shot handshakes below or they never see a ServerHello.
		client.Close()

		// The server is known to be up from here on, so failures below are
		// meaningful single-shot handshakes, not readiness races.
		t.Run("rejects untrusted CA", func(t *testing.T) {
			err := utlsHandshakeErr(t, hostAddr, &Config{
				ServerName: "localhost",
				RootCAs:    loadInteropCertPool(t, workDir, "wrongca.crt"),
				MinVersion: VersionTLS13,
				MaxVersion: VersionTLS13,
			}, HelloChrome_150)
			var unknownAuthority x509.UnknownAuthorityError
			if !errors.As(err, &unknownAuthority) {
				t.Fatalf("handshake error = %v, want x509.UnknownAuthorityError", err)
			}
		})

		t.Run("classical-only ClientHello cannot negotiate", func(t *testing.T) {
			err := utlsHandshakeErr(t, hostAddr, &Config{
				ServerName: "localhost",
				RootCAs:    roots,
				MinVersion: VersionTLS13,
				MaxVersion: VersionTLS13,
			}, HelloChrome_133)
			if err == nil {
				t.Fatal("handshake succeeded without advertising ML-DSA to an ML-DSA-only server")
			}
			t.Logf("handshake failed as expected: %v", err)
		})
	})

	t.Run("uTLS client and pure ML-DSA chain", func(t *testing.T) {
		hostAddr := startOpenSSLMLDSAServer(t, workDir, "pqserver.crt", "pqserver.key")

		// TLS-level ML-DSA (CertificateVerify, leaf public key) works even for
		// an ML-DSA-issued chain, so skipping x509 verification must succeed.
		client := dialUTLSWithRetry(t, hostAddr, &Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         VersionTLS13,
			MaxVersion:         VersionTLS13,
		}, HelloChrome_150)
		expectMLDSAPublicKey(t, client.ConnectionState().PeerCertificates[0].PublicKey, MLDSA44)
		client.Close()

		// crypto/x509 cannot verify ML-DSA chain signatures: trusting the
		// ML-DSA root must still fail verification. If this starts passing,
		// the classical-issuer-only restriction can be lifted.
		err := utlsHandshakeErr(t, hostAddr, &Config{
			ServerName: "localhost",
			RootCAs:    loadInteropCertPool(t, workDir, "mldsa-ca.crt"),
			MinVersion: VersionTLS13,
			MaxVersion: VersionTLS13,
		}, HelloChrome_150)
		var unknownAuthority x509.UnknownAuthorityError
		if !errors.As(err, &unknownAuthority) {
			t.Fatalf("handshake error = %v, want x509.UnknownAuthorityError", err)
		}
		t.Logf("pure ML-DSA chain rejected as expected: %v", err)
	})
}

func startOpenSSLMLDSAServer(t *testing.T, workDir, certFile, keyFile string) string {
	t.Helper()

	containerID := runDockerOutput(t, workDir, "docker", "run", "-d", "--rm",
		"-v", dockerVolume(workDir)+":/w",
		"-p", "127.0.0.1::4433",
		opensslInteropImage,
		"sh", "-lc",
		fmt.Sprintf("apk add --no-cache openssl >/dev/null && openssl s_server -accept 4433 -cert /w/%s -key /w/%s -tls1_3 -groups X25519 -sigalgs mldsa44 -www -quiet", certFile, keyFile),
	)
	containerID = strings.TrimSpace(containerID)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})
	return dockerPublishedAddress(t, containerID)
}

func loadInteropCertPool(t *testing.T, workDir, certFile string) *x509.CertPool {
	t.Helper()

	pem, err := os.ReadFile(filepath.Join(workDir, certFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("failed to parse %s", certFile)
	}
	return pool
}

func utlsHandshakeErr(t *testing.T, addr string, config *Config, helloID ClientHelloID) error {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	return UClient(conn, config, helloID).Handshake()
}

func requireDocker(t *testing.T) {
	t.Helper()

	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Docker is required for OpenSSL interop tests: %v\n%s", err, out)
	}
}

func generateOpenSSLMLDSACerts(t *testing.T, workDir string) {
	t.Helper()

	runDocker(t, workDir, "sh", "-lc", strings.Join([]string{
		"apk add --no-cache openssl >/dev/null",
		"cd /w",
		"openssl version",
		"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key",
		"openssl req -x509 -new -key ca.key -sha256 -days 30 -subj '/CN=utls interop test root' -out ca.crt",
		"openssl genpkey -algorithm ML-DSA-44 -out server.key",
		"openssl req -new -key server.key -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -out server.csr",
		"openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -copy_extensions copy -out server.crt",
		"openssl x509 -in server.crt -noout -text | grep -E 'Public Key Algorithm|Signature Algorithm'",
		"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out wrongca.key",
		"openssl req -x509 -new -key wrongca.key -sha256 -days 30 -subj '/CN=utls interop wrong root' -out wrongca.crt",
		"openssl genpkey -algorithm ML-DSA-44 -out mldsa-ca.key",
		"openssl req -x509 -new -key mldsa-ca.key -days 30 -subj '/CN=utls interop ML-DSA root' -out mldsa-ca.crt",
		"openssl genpkey -algorithm ML-DSA-44 -out pqserver.key",
		"openssl req -new -key pqserver.key -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -out pqserver.csr",
		"openssl x509 -req -in pqserver.csr -CA mldsa-ca.crt -CAkey mldsa-ca.key -CAcreateserial -days 30 -copy_extensions copy -out pqserver.crt",
		"openssl x509 -in pqserver.crt -noout -text | grep -E 'Public Key Algorithm|Signature Algorithm'",
	}, " && "))
}

func runDocker(t *testing.T, workDir string, args ...string) {
	t.Helper()

	baseArgs := []string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", dockerVolume(workDir) + ":/w", opensslInteropImage}
	out := runDockerOutput(t, workDir, "docker", append(baseArgs, args...)...)
	t.Log(out)
}

func runDockerOutput(t *testing.T, workDir, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = workDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func dockerVolume(path string) string {
	return filepath.ToSlash(path)
}

func dockerPublishedAddress(t *testing.T, containerID string) string {
	t.Helper()

	out := runDockerOutput(t, "", "docker", "port", containerID, "4433/tcp")
	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatalf("docker port returned no address for %s", containerID)
	}
	if strings.HasPrefix(line, "0.0.0.0:") {
		line = "127.0.0.1:" + strings.TrimPrefix(line, "0.0.0.0:")
	}
	if strings.HasPrefix(line, "[::]:") {
		line = "127.0.0.1:" + strings.TrimPrefix(line, "[::]:")
	}
	return line
}

func dialUTLSWithRetry(t *testing.T, addr string, config *Config, helloID ClientHelloID) *UConn {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		client := UClient(conn, config, helloID)
		if err := client.Handshake(); err != nil {
			conn.Close()
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		conn.SetDeadline(time.Time{})
		return client
	}
	t.Fatalf("timed out handshaking with %s: %v", addr, lastErr)
	return nil
}
