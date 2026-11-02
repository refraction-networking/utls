// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testenv is a uTLS shim for the standard library's internal
// internal/testenv package, which cannot be imported from outside GOROOT.
//
// It provides just the helpers the mirrored crypto/tls test files use:
// MustHaveExternalNetwork, MustHaveSource and SetGODEBUG. The implementations
// are deliberately simple; they only need to make the upstream tests run or
// skip sensibly in CI. See internal/README.md.
package testenv

import (
	"os"
	"testing"
)

// MustHaveExternalNetwork skips t unless external network access is available.
//
// CI and sandboxes usually have no outbound network, and -short mode never
// wants it, so this skips by default. Set UTLS_NETWORK_TESTS=1 to opt in on a
// machine that can reach the public internet.
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	if testing.Short() {
		t.Skipf("skipping test: external network not used in -short mode")
	}
	if os.Getenv("UTLS_NETWORK_TESTS") != "1" {
		t.Skipf("skipping test: set UTLS_NETWORK_TESTS=1 to run tests that need external network")
	}
}

// MustHaveSource skips t if Go source (a full GOROOT) is unlikely to be
// present. uTLS does not ship generators that need GOROOT sources in CI, so
// this errs toward skipping when GOROOT/src is absent.
func MustHaveSource(t testing.TB) {
	t.Helper()
	if _, err := os.Stat(gorootSrc()); err != nil {
		t.Skipf("skipping test: GOROOT source not available: %v", err)
	}
}

// SetGODEBUG sets the GODEBUG environment variable for the duration of the
// test using t.Setenv, so settings read through internal/godebug take effect.
func SetGODEBUG(t *testing.T, value string) {
	t.Setenv("GODEBUG", value)
}

func gorootSrc() string {
	if r := os.Getenv("GOROOT"); r != "" {
		return r + "/src"
	}
	return "/usr/local/go/src"
}
