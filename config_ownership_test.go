// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// The owned plain-data slices of a Config are snapshotted by UClient: mutating
// them (in place, the way buffer reuse would) before the handshake must not
// change what is sent or negotiated.
func TestConfigOwnedSlicesAreSnapshotted(t *testing.T) {
	list, keys := echPair(t)
	scfg := serverConfig(t)
	scfg.MinVersion = tls.VersionTLS13
	scfg.EncryptedClientHelloKeys = keys
	scfg.ClientAuth = tls.RequireAnyClientCert
	clientCert := getPKI(t).cert
	origLeaf := bytes.Clone(clientCert.Certificate[0])

	ccfg := clientConfig(t)
	ccfg.ServerName = "secret.example"
	ccfg.NextProtos = []string{"h2", "http/1.1"}
	ccfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	ccfg.EncryptedClientHelloConfigList = bytes.Clone(list)
	ccfg.Certificates = []tls.Certificate{{Certificate: [][]byte{bytes.Clone(clientCert.Certificate[0])}, PrivateKey: clientCert.PrivateKey}}

	r := handshakeStd(t, HelloChrome_Auto, ccfg, scfg, func(uc *UConn) {
		// After UClient copied the config: scribble over every owned slice.
		ccfg.NextProtos[0] = "bogus"
		ccfg.CipherSuites[0] = 0xffff
		clear(ccfg.EncryptedClientHelloConfigList)
		clear(ccfg.Certificates[0].Certificate[0])
		ccfg.ServerName = "changed.example"
		ccfg.Certificates[0].Certificate = nil
	})
	r.ok(t)
	st := r.uc.ConnectionState()
	if st.NegotiatedProtocol != "h2" || !st.ECHAccepted {
		t.Fatalf("alpn %q ech %v: mutation leaked into the connection", st.NegotiatedProtocol, st.ECHAccepted)
	}
	if len(r.sstate.PeerCertificates) != 1 || !bytes.Equal(r.sstate.PeerCertificates[0].Raw, origLeaf) {
		t.Fatal("client certificate bytes were not snapshotted")
	}
	if r.sstate.ServerName != "secret.example" {
		t.Fatalf("server name %q", r.sstate.ServerName)
	}
}

// Referenced objects are shared, as documented (and as in crypto/tls): a
// root added to the same pool after UClient is visible to the handshake.
func TestConfigReferencedObjectsAreShared(t *testing.T) {
	ccfg := clientConfig(t)
	ccfg.RootCAs = x509.NewCertPool() // empty at UClient time
	r := handshakeStd(t, HelloChrome_Auto, ccfg, serverConfig(t), func(uc *UConn) {
		ca, _ := x509.ParseCertificate(getPKI(t).cert.Certificate[1])
		ccfg.RootCAs.AddCert(ca)
	})
	r.ok(t)
}
