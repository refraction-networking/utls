// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// This uTLS-owned file supplies the handful of symbols that the mirrored
// crypto/tls test files reference but that live in upstream test files we do
// not mirror (see upstream/exclude.txt): the BoGo shim and the FIPS 140-3
// module tests. Keeping the stubs here lets the rest of the upstream test
// suite compile and run unchanged, while the excluded files stay excluded.
//
// If a future `upstream/sync.sh update` makes the real definitions importable
// (for example because an excluded file is brought back), delete the matching
// stub here.

import "fmt"

// bogoShim stands in for the BoGo (BoringSSL) interop shim defined in the
// excluded bogo_shim_test.go. It only runs under `go test -bogo`, which we do
// not wire up, so invoking it reports that clearly instead of running.
func bogoShim() {
	panic(fmt.Sprintf("uTLS: the BoGo interop shim is not mirrored; see upstream/exclude.txt"))
}

// testConfigFIPS140 mirrors the config from the excluded fips140_test.go. The
// certificates and roots it references are defined in certificates_test.go and
// tls_test.go, which are mirrored, so the value is faithful. Non-FIPS tests use
// it only to attach a KeyLogWriter when -keylog is set.
var testConfigFIPS140 = &Config{
	Time:         testTime,
	Certificates: []Certificate{testECDSAP256Cert, testRSAPSSCert, testEd25519Cert, testMLDSA44Cert, testMLDSA65Cert, testMLDSA87Cert},
	RootCAs:      testRootCertPool,
	ServerName:   "test.golang.example",
}

// isFIPSVersion mirrors the helper from the excluded fips140_test.go.
func isFIPSVersion(v uint16) bool {
	return v == VersionTLS12 || v == VersionTLS13
}
